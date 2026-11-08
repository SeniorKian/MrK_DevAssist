"""Gate 17 Docker management and container logs for the host_agent module.

Routes (docs/29 §3 "مدیریت Docker"):

- POST /api/v1/agent/containers/{id}/action   docker:operate + CSRF
- POST /api/v1/agent/images/pull               docker:operate + CSRF -> 202 {job_id}
- GET  /api/v1/agent/jobs/{job_id}             docker:operate
- POST /api/v1/agent/prune/preview             docker:prune
- POST /api/v1/agent/prune                     docker:prune + CSRF, confirmation "PRUNE"
- GET  /api/v1/agent/containers/{id}/logs      logs:read
- GET  /api/v1/agent/containers/{id}/logs/stream  logs:read (text/event-stream)

The agent enforces its own allowlist and protection rules; the control plane adds
RBAC, typed confirmation, audit (attempt, then result) and redaction of log text.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import secrets
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from ..logging_config import redact_text
from ..module_context import Event, ModuleContext

if TYPE_CHECKING:
    import httpx

    from .host_agent import HostAgentService

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "host_agent"


def _env_int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return min(max(value, low), high)


# Container ids/names as Docker accepts them; never a path.
CONTAINER_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
# repo[:tag|@digest] with an optional registry host[:port] prefix.
IMAGE_REF = re.compile(
    # A registry host has a dot or a port, or is localhost (Docker's own rule).
    r"^(?:(?:(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|localhost)(?::[0-9]{1,5})?"
    r"|[A-Za-z0-9-]+:[0-9]{1,5})/)?"
    r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$"
)
PRUNE_TOKEN = re.compile(r"^[a-f0-9]{64}$")
# Nested quantifiers such as (a+)+ are the classic catastrophic-backtracking shape.
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*}][^)]*\)\s*[+*{]")

LOG_TAIL_MAX = 5000
LOG_SEARCH_MAX_CHARS = 200
LOG_LINE_MAX_CHARS = 16384
LOG_RESPONSE_MAX_BYTES = 8 * 1024 * 1024
LOG_REQUEST_TIMEOUT_SECONDS = 30.0
STREAM_KEEPALIVE_SECONDS = 15.0
STREAM_MAX_SECONDS = float(_env_int("MRK_LOGS_STREAM_MAX_SECONDS", 600, 10, 600))
STREAM_QUEUE_LINES = 1000
ACTION_TIMEOUT_MARGIN_SECONDS = 30.0
PULL_TIMEOUT_SECONDS = 630.0
PRUNE_PREVIEW_TIMEOUT_SECONDS = 120.0
PRUNE_TIMEOUT_SECONDS = 630.0
JOB_MAX = _env_int("MRK_AGENT_JOB_MAX", 50, 5, 1000)
JOB_TTL_SECONDS = _env_int("MRK_AGENT_JOB_TTL_SECONDS", 3600, 60, 86400)
JOB_MAX_RUNNING = 5

PAST_TENSE = {"start": "started", "stop": "stopped", "restart": "restarted"}


# ----- request bodies --------------------------------------------------------


class ContainerActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["start", "stop", "restart"]
    allow_protected: bool = False
    confirmation: str | None = Field(default=None, max_length=128)
    timeout_seconds: int = Field(default=10, ge=0, le=300)


class ImagePullRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    image: str = Field(min_length=1, max_length=512)


PruneTarget = Literal["containers", "images", "build_cache", "networks"]


class PrunePreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[PruneTarget] = Field(min_length=1, max_length=4)
    images_mode: Literal["dangling", "unused"] = "dangling"

    def agent_body(self) -> dict[str, Any]:
        return {"targets": sorted(set(self.targets)), "images_mode": self.images_mode}


class PruneRequest(PrunePreviewRequest):
    token: str = Field(min_length=1, max_length=128)
    confirmation: str = Field(min_length=1, max_length=32)


# ----- image pull jobs --------------------------------------------------------


@dataclass(slots=True)
class Job:
    id: str
    kind: str
    target: str
    state: str
    started_at: float
    finished_at: float | None = None
    result: dict[str, Any] | None = None
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "target": self.target,
            "state": self.state,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }
        if self.result is not None:
            payload["result"] = self.result
        if self.error_code is not None:
            payload["error_code"] = self.error_code
        return payload


class JobLimitError(Exception):
    pass


class JobRegistry:
    """In-memory, bounded job registry. Finished jobs expire after ttl_seconds."""

    def __init__(
        self,
        max_jobs: int = JOB_MAX,
        ttl_seconds: float = JOB_TTL_SECONDS,
        max_running: int = JOB_MAX_RUNNING,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.max_jobs = max_jobs
        self.ttl_seconds = ttl_seconds
        self.max_running = max_running
        self.clock = clock
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._tasks: set[asyncio.Task[None]] = set()

    def _evict(self, make_room: bool = False) -> None:
        now = self.clock()
        for job_id in [
            job.id
            for job in self._jobs.values()
            if job.finished_at is not None and now - job.finished_at > self.ttl_seconds
        ]:
            del self._jobs[job_id]
        while make_room and len(self._jobs) >= self.max_jobs:
            finished = next(
                (job.id for job in self._jobs.values() if job.state != "running"), None
            )
            if finished is None:
                break
            del self._jobs[finished]

    def running(self) -> int:
        return sum(1 for job in self._jobs.values() if job.state == "running")

    def create(self, kind: str, target: str) -> Job:
        self._evict(make_room=True)
        if len(self._jobs) >= self.max_jobs or self.running() >= self.max_running:
            raise JobLimitError
        job = Job(
            id=secrets.token_hex(12),
            kind=kind,
            target=target,
            state="running",
            started_at=self.clock(),
        )
        self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        self._evict()
        return self._jobs.get(job_id)

    def finish(
        self,
        job: Job,
        *,
        result: dict[str, Any] | None = None,
        error_code: str | None = None,
    ) -> None:
        job.state = "failed" if error_code else "succeeded"
        job.result = result
        job.error_code = error_code
        job.finished_at = self.clock()

    def spawn(self, coroutine: Awaitable[None]) -> asyncio.Task[None]:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def stop(self) -> None:
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        for job in self._jobs.values():
            if job.state == "running":
                self.finish(job, error_code="cancelled")


# ----- logs ------------------------------------------------------------------


class LogFilterError(ValueError):
    pass


def build_line_filter(search: str | None, regex: bool = False) -> Callable[[str], bool] | None:
    """Case-insensitive substring filter, or a validated length-limited regex."""
    if not search:
        return None
    if len(search) > LOG_SEARCH_MAX_CHARS:
        raise LogFilterError(f"search must be at most {LOG_SEARCH_MAX_CHARS} characters")
    if not regex:
        needle = search.casefold()
        return lambda text: needle in text.casefold()
    if _NESTED_QUANTIFIER.search(search):
        raise LogFilterError("regex uses nested quantifiers")
    try:
        pattern = re.compile(search, re.IGNORECASE)
    except re.error as exc:
        raise LogFilterError("regex is invalid") from exc
    return lambda text: pattern.search(text) is not None


def clean_line(raw: Any) -> dict[str, str] | None:
    """Normalize one agent log line and redact secrets from its text."""
    if not isinstance(raw, dict):
        return None
    text = raw.get("text")
    if not isinstance(text, str):
        return None
    ts = raw.get("ts")
    stream = raw.get("stream")
    return {
        "ts": ts[:64] if isinstance(ts, str) else "",
        "stream": stream if stream in ("stdout", "stderr") else "stdout",
        "text": redact_text(text[:LOG_LINE_MAX_CHARS]),
    }


def sse_event(event: str, data: Any) -> str:
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return f"event: {event}\ndata: {payload}\n\n"


def logs_path(container: str, params: dict[str, Any]) -> str:
    query = urlencode({key: value for key, value in params.items() if value is not None})
    return f"/v1/docker/containers/{quote(container, safe='')}/logs?{query}"


async def stream_log_events(
    client: httpx.AsyncClient,
    response: httpx.Response,
    request: Request,
    line_filter: Callable[[str], bool] | None,
    *,
    keepalive_seconds: float | None = None,
    max_seconds: float | None = None,
) -> AsyncIterator[str]:
    """Turn the agent's NDJSON follow stream into SSE frames.

    Ends when the agent closes the stream, max_seconds pass or the browser goes
    away; the agent connection is always closed.
    """
    keepalive = STREAM_KEEPALIVE_SECONDS if keepalive_seconds is None else keepalive_seconds
    limit = STREAM_MAX_SECONDS if max_seconds is None else max_seconds
    loop = asyncio.get_running_loop()
    deadline = loop.time() + limit
    queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue(maxsize=STREAM_QUEUE_LINES)

    async def pump() -> None:
        try:
            async for raw in response.aiter_lines():
                if not raw.strip():
                    continue
                try:
                    line = clean_line(json.loads(raw))
                except ValueError:
                    continue
                if line is None or (line_filter is not None and not line_filter(line["text"])):
                    continue
                await queue.put(("line", line))
            await queue.put(("end", "agent_closed"))
        except asyncio.CancelledError:
            raise
        except Exception:  # any transport failure ends the stream
            await queue.put(("end", "agent_error"))

    task = asyncio.create_task(pump())
    reason = "timeout"
    try:
        yield ": connected\n\n"
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                kind, value = await asyncio.wait_for(
                    queue.get(), timeout=min(keepalive, remaining)
                )
            except TimeoutError:
                if await request.is_disconnected():
                    reason = "client_closed"
                    return
                if deadline - loop.time() > 0:
                    yield ": keepalive\n\n"
                continue
            if kind == "end":
                reason = value
                break
            yield sse_event("line", value)
        yield sse_event("end", {"reason": reason})
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
        with contextlib.suppress(Exception):
            await response.aclose()
        with contextlib.suppress(Exception):
            await client.aclose()


# ----- routes ----------------------------------------------------------------


def add_docker_routes(
    ctx: ModuleContext, router: APIRouter, service: HostAgentService
) -> JobRegistry:
    from .host_agent import AgentError

    jobs = JobRegistry()

    def failure(exc: AgentError) -> JSONResponse:
        if exc.code == "agent_not_found":
            return ctx.error_payload("container_not_found", "Container not found", 404)
        return ctx.error_payload(exc.code, exc.message, exc.status_code)

    async def audit(
        user_id: int, action: str, object_type: str, object_id: str | None, result: str
    ) -> None:
        try:
            await asyncio.to_thread(ctx.audit, user_id, action, object_type, object_id, result)
        except Exception:  # pragma: no cover - audit failure must not hide the outcome
            LOGGER.exception("audit write failed", extra={"action": action})

    def invalid_ref() -> JSONResponse:
        return ctx.error_payload("invalid_container", "Container id or name is invalid", 422)

    async def find_container(ref: str) -> dict[str, Any] | None:
        payload = await service.call("/v1/docker/containers")
        items = payload.get("items") if isinstance(payload, dict) else None
        name = ref.lstrip("/")
        for item in items or []:
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id") or "")
            if item_id == ref or item.get("name") == name or (
                len(ref) >= 12 and item_id.startswith(ref)
            ):
                return item
        return None

    # ---- container actions ----

    @router.post("/containers/{container}/action", response_model=None)
    async def container_action(
        container: str, request: Request, body: ContainerActionRequest
    ) -> dict[str, Any] | JSONResponse:
        principal = ctx.require_principal(request, "docker:operate")
        ctx.require_csrf(request, principal)
        if not CONTAINER_REF.fullmatch(container):
            return invalid_ref()
        audit_action = f"docker.container.{body.action}"
        try:
            item = await find_container(container)
        except AgentError as exc:
            return failure(exc)
        if item is None:
            return ctx.error_payload("container_not_found", "Container not found", 404)
        name = str(item.get("name") or container)
        protected = bool(item.get("protected"))
        if protected:
            if not body.allow_protected:
                await audit(principal.user_id, audit_action, "container", name, "denied")
                return ctx.error_payload(
                    "container_protected",
                    "This container is protected; confirm with allow_protected and its name",
                    403,
                )
            if body.confirmation != name:
                await audit(principal.user_id, audit_action, "container", name, "denied")
                return ctx.error_payload(
                    "confirmation_required", f'Type the container name "{name}" to confirm', 422
                )
        await audit(principal.user_id, audit_action, "container", name, "attempted")
        container_id = str(item.get("id") or container)
        try:
            await service.request(
                "POST",
                f"/v1/docker/containers/{quote(container_id, safe='')}/{body.action}",
                {"timeout_seconds": body.timeout_seconds, "allow_protected": protected},
                timeout=body.timeout_seconds + ACTION_TIMEOUT_MARGIN_SECONDS,
            )
        except AgentError as exc:
            await audit(principal.user_id, audit_action, "container", name, "failure")
            return failure(exc)
        await audit(principal.user_id, audit_action, "container", name, "success")
        ctx.events.publish(
            Event(
                type=f"container.{PAST_TENSE[body.action]}",
                severity="info",
                title=f"Container {name} {PAST_TENSE[body.action]}",
                message=f"Requested by {principal.username}",
                module=MODULE_NAME,
                dedupe_key=f"container.{body.action}:{name}:{secrets.token_hex(4)}",
                details={"container": name, "protected": protected},
            )
        )
        return {"ok": True, "id": container_id, "name": name, "action": body.action}

    # ---- image pull jobs ----

    @router.post("/images/pull", status_code=202, response_model=None)
    async def image_pull(request: Request, body: ImagePullRequest) -> JSONResponse:
        principal = ctx.require_principal(request, "docker:operate")
        ctx.require_csrf(request, principal)
        image = body.image.strip()
        if not IMAGE_REF.fullmatch(image) or len(image) > 255:
            return ctx.error_payload("invalid_image", "Image reference is invalid", 422)
        try:
            service._target()
        except AgentError as exc:
            return failure(exc)
        try:
            job = jobs.create("image_pull", image)
        except JobLimitError:
            return ctx.error_payload(
                "too_many_jobs", "Too many image pulls are running; try again later", 429
            )
        await audit(principal.user_id, "docker.image.pull", "image", image, "attempted")

        async def run() -> None:
            try:
                result = await service.request(
                    "POST",
                    "/v1/docker/images/pull",
                    {"image": image},
                    timeout=PULL_TIMEOUT_SECONDS,
                )
            except AgentError as exc:
                jobs.finish(job, error_code=exc.code)
            except asyncio.CancelledError:
                jobs.finish(job, error_code="cancelled")
                raise
            except Exception:
                LOGGER.exception("image pull job failed")
                jobs.finish(job, error_code="internal_error")
            else:
                digest = result.get("digest") if isinstance(result, dict) else None
                jobs.finish(job, result={"image": image, "digest": digest})
            await audit(
                principal.user_id,
                "docker.image.pull",
                "image",
                image,
                "success" if job.state == "succeeded" else "failure",
            )

        jobs.spawn(run())
        return JSONResponse({"job_id": job.id}, status_code=202)

    @router.get("/jobs/{job_id}", response_model=None)
    async def get_job(job_id: str, request: Request) -> dict[str, Any] | JSONResponse:
        ctx.require_principal(request, "docker:operate")
        job = jobs.get(job_id) if re.fullmatch(r"[a-f0-9]{24}", job_id) else None
        if job is None:
            return ctx.error_payload("job_not_found", "Job not found or expired", 404)
        return job.to_dict()

    # ---- prune ----

    @router.post("/prune/preview", response_model=None)
    async def prune_preview(request: Request, body: PrunePreviewRequest) -> Any:
        ctx.require_principal(request, "docker:prune")
        try:
            return await service.request(
                "POST",
                "/v1/docker/prune/preview",
                body.agent_body(),
                timeout=PRUNE_PREVIEW_TIMEOUT_SECONDS,
            )
        except AgentError as exc:
            return failure(exc)

    @router.post("/prune", response_model=None)
    async def prune(request: Request, body: PruneRequest) -> Any:
        principal = ctx.require_principal(request, "docker:prune")
        ctx.require_csrf(request, principal)
        if body.confirmation != "PRUNE":
            return ctx.error_payload("confirmation_required", 'Type "PRUNE" to confirm', 422)
        if not PRUNE_TOKEN.fullmatch(body.token):
            return ctx.error_payload(
                "invalid_token", "A prune token from the preview is required", 422
            )
        targets = ",".join(body.agent_body()["targets"])
        object_id = f"targets={targets};images={body.images_mode}"
        await audit(principal.user_id, "docker.prune", "docker", object_id, "attempted")
        try:
            result = await service.request(
                "POST",
                "/v1/docker/prune",
                {"token": body.token, **body.agent_body()},
                timeout=PRUNE_TIMEOUT_SECONDS,
            )
        except AgentError as exc:
            await audit(principal.user_id, "docker.prune", "docker", object_id, "failure")
            return failure(exc)
        reclaimed = result.get("reclaimed_bytes") if isinstance(result, dict) else None
        reclaimed = int(reclaimed) if isinstance(reclaimed, int | float) else 0
        removed = result.get("removed") if isinstance(result, dict) else None
        await audit(
            principal.user_id,
            "docker.prune",
            "docker",
            f"{object_id};reclaimed_bytes={reclaimed}",
            "success",
        )
        ctx.events.publish(
            Event(
                type="docker.pruned",
                severity="info",
                title="Docker prune completed",
                message=f"Reclaimed {reclaimed} bytes (requested by {principal.username})",
                module=MODULE_NAME,
                dedupe_key=f"docker.pruned:{secrets.token_hex(4)}",
                details={
                    "reclaimed_bytes": reclaimed,
                    "removed": removed if isinstance(removed, dict) else {},
                    "targets": targets.split(","),
                },
            )
        )
        return result

    # ---- logs ----

    @router.get("/containers/{container}/logs", response_model=None)
    async def container_logs(
        container: str,
        request: Request,
        tail: int = Query(default=200, ge=1, le=LOG_TAIL_MAX),
        since: int | None = Query(default=None, ge=0),
        until: int | None = Query(default=None, ge=0),
        search: str | None = Query(default=None, max_length=LOG_SEARCH_MAX_CHARS),
        regex: bool = False,
    ) -> dict[str, Any] | JSONResponse:
        principal = ctx.require_principal(request, "logs:read")
        if not CONTAINER_REF.fullmatch(container):
            return invalid_ref()
        try:
            line_filter = build_line_filter(search, regex)
        except LogFilterError as exc:
            return ctx.error_payload("invalid_search", str(exc), 422)
        path = logs_path(
            container,
            {"tail": tail, "since": since, "until": until, "timestamps": 1, "follow": 0},
        )
        try:
            payload = await service.request(
                "GET",
                path,
                timeout=LOG_REQUEST_TIMEOUT_SECONDS,
                max_bytes=LOG_RESPONSE_MAX_BYTES,
            )
        except AgentError as exc:
            await audit(principal.user_id, "logs.view", "container", container, "failure")
            return failure(exc)
        await audit(principal.user_id, "logs.view", "container", container, "success")
        raw_lines = payload.get("lines") if isinstance(payload, dict) else None
        lines: list[dict[str, str]] = []
        for raw in raw_lines if isinstance(raw_lines, list) else []:
            line = clean_line(raw)
            if line is None or (line_filter is not None and not line_filter(line["text"])):
                continue
            lines.append(line)
        return {
            "lines": lines,
            "truncated": bool(payload.get("truncated")) if isinstance(payload, dict) else False,
        }

    @router.get("/containers/{container}/logs/stream", response_model=None)
    async def container_logs_stream(
        container: str,
        request: Request,
        tail: int = Query(default=200, ge=0, le=LOG_TAIL_MAX),
        search: str | None = Query(default=None, max_length=LOG_SEARCH_MAX_CHARS),
        regex: bool = False,
    ) -> StreamingResponse | JSONResponse:
        principal = ctx.require_principal(request, "logs:read")
        if not CONTAINER_REF.fullmatch(container):
            return invalid_ref()
        try:
            line_filter = build_line_filter(search, regex)
        except LogFilterError as exc:
            return ctx.error_payload("invalid_search", str(exc), 422)
        path = logs_path(container, {"tail": tail, "timestamps": 1, "follow": 1})
        try:
            client, response = await service.open_stream(path)
        except AgentError as exc:
            await audit(principal.user_id, "logs.view", "container", container, "failure")
            return failure(exc)
        await audit(principal.user_id, "logs.view", "container", container, "success")
        return StreamingResponse(
            stream_log_events(client, response, request, line_filter),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    return jobs
