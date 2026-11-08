"""D2 panel routes of the DNS module: query log, stats, pressure, mitigations (docs/38 §4).

* ``GET logs``, ``GET logs/status``, ``GET logs/stream`` (Server-Sent Events),
  ``GET logs/export`` (streamed download): ``dns:logs``.
* ``DELETE logs`` ``{client?, before?, confirmation}``: ``dns:admin``.
* ``GET stats`` / ``GET pressure`` / ``GET events``: ``dns:read``; names and client addresses
  (``top`` lists, ``hot``, event ``data``) only with ``dns:logs``.
* ``GET/POST mitigations``, ``DELETE mitigations/{id}``: ``dns:write``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.types import Receive, Scope, Send

from ..dns_client import DnsError, EngineStream, StreamLimit
from ..module_context import ModuleContext
from . import dns_filters
from .dns_validate import DnsInputError, entity_id

LOGGER = logging.getLogger(__name__)

STREAMS_PER_USER = 3
STREAMS_TOTAL = 20
EXPORTS_PER_USER = 1
EXPORTS_TOTAL = 3
HEARTBEAT_SECONDS = 15.0
STREAM_MAX_SECONDS = 30 * 60.0
STREAM_MAX_BYTES = 512 * 1024 * 1024
STREAM_READ_TIMEOUT = 45.0  # the engine pings every 15 s
EXPORT_MAX_SECONDS = 15 * 60.0
EXPORT_MAX_BYTES = 2 * 1024 * 1024 * 1024
EXPORT_READ_TIMEOUT = 60.0
STREAM_QUEUE = 256
SSE_TYPES = ("hello", "entry", "sampled", "ping")
TOP_KEYS = ("domains", "clients", "nxdomain", "refused_clients")
HOT_KEYS = ("domains", "clients", "attacks")


class Slots:
    """Concurrent long requests per user and in total (one event loop, no lock)."""

    def __init__(self, per_user: int, total: int) -> None:
        self.per_user = per_user
        self.total = total
        self.by_user: Counter[int] = Counter()

    def acquire(self, user_id: int) -> str | None:
        """None when taken, else the scope that is full ("user" | "global")."""
        if sum(self.by_user.values()) >= self.total:
            return "global"
        if self.by_user[user_id] >= self.per_user:
            return "user"
        self.by_user[user_id] += 1
        return None

    def release(self, user_id: int) -> None:
        if self.by_user[user_id] > 0:
            self.by_user[user_id] -= 1
        if self.by_user[user_id] <= 0:
            del self.by_user[user_id]

    def active(self) -> int:
        return sum(self.by_user.values())


STREAM_SLOTS = Slots(STREAMS_PER_USER, STREAMS_TOTAL)
EXPORT_SLOTS = Slots(EXPORTS_PER_USER, EXPORTS_TOTAL)


class Cleanup:
    """Runs once: close the engine stream, stop the pump, free the slot."""

    def __init__(self, stream: EngineStream, release: Callable[[], None]) -> None:
        self.stream = stream
        self.release = release
        self.task: asyncio.Task[None] | None = None
        self.done = False

    async def __call__(self) -> None:
        if self.done:
            return
        self.done = True
        if self.task is not None and not self.task.done():
            self.task.cancel()
            with contextlib.suppress(BaseException):
                await self.task
        try:
            await self.stream.aclose()
        finally:
            self.release()


class ManagedStreamingResponse(StreamingResponse):
    """A StreamingResponse that always runs its cleanup, also on client disconnect."""

    def __init__(self, content: AsyncIterator[bytes], cleanup: Cleanup, **kwargs: Any) -> None:
        super().__init__(content, **kwargs)
        self._cleanup = cleanup

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            await self._cleanup()


def sse_frame(kind: str, data: dict[str, Any]) -> bytes:
    """One unnamed SSE message (EventSource ``onmessage``): ``data: {"type":..., ...}``."""
    payload = json.dumps({"type": kind, **data}, separators=(",", ":"), ensure_ascii=False)
    return f"data: {payload}\n\n".encode()


async def sse_events(
    stream: EngineStream,
    is_disconnected: Callable[[], Awaitable[bool]],
    cleanup: Cleanup,
    *,
    heartbeat: float | None = None,
) -> AsyncIterator[bytes]:
    """Engine NDJSON -> SSE frames (``hello``/``entry``/``sampled``/``ping``, then
    ``end`` or ``error``) with a comment heartbeat while the engine is quiet."""
    queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue(maxsize=STREAM_QUEUE)

    async def pump() -> None:
        try:
            async for item in stream.lines():
                await queue.put(("item", item))
            await queue.put(("end", "engine_closed"))
        except StreamLimit as exc:
            await queue.put(("end", exc.reason))
        except DnsError as exc:
            await queue.put(("error", {"code": exc.code, "reason": exc.extra.get("reason")}))
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - reported to the browser as a broken stream
            LOGGER.exception("dns log stream pump failed")
            await queue.put(("error", {"code": "dns_unreachable", "reason": "engine_error"}))

    cleanup.task = asyncio.create_task(pump(), name="mrk-dns-log-stream")
    wait = heartbeat if heartbeat is not None else HEARTBEAT_SECONDS
    try:
        yield b"retry: 5000\n\n"
        while True:
            try:
                kind, value = await asyncio.wait_for(queue.get(), wait)
            except TimeoutError:
                if await is_disconnected():
                    return
                yield b": keep-alive\n\n"
                continue
            if kind == "item":
                event = value.get("type")
                if event not in SSE_TYPES:
                    continue
                data = {key: item for key, item in value.items() if key != "type"}
                yield sse_frame(event, data)
            elif kind == "end":
                yield sse_frame("end", {"reason": value})
                return
            else:
                yield sse_frame("error", value)
                return
    finally:
        await cleanup()


def shape_stats(payload: Any, can_see_names: bool) -> Any:
    if not isinstance(payload, dict):
        return payload
    result = dict(payload)
    top = result.get("top") if isinstance(result.get("top"), dict) else {}
    if can_see_names:
        result["top"] = {key: top.get(key) if isinstance(top.get(key), list) else []
                         for key in TOP_KEYS}
        result["top_hidden"] = False
    else:
        result["top"] = {key: [] for key in TOP_KEYS}
        result["top_hidden"] = True
    return result


def shape_pressure(payload: Any, can_see_names: bool) -> Any:
    if not isinstance(payload, dict):
        return payload
    result = dict(payload)
    hot = result.get("hot") if isinstance(result.get("hot"), dict) else {}
    lists = {key: hot.get(key) if isinstance(hot.get(key), list) else [] for key in HOT_KEYS}
    if can_see_names:
        result["hot"] = {**lists, "hidden": False}
    else:
        # Only how many; no names or addresses.
        result["hot"] = {**{key: len(value) for key, value in lists.items()}, "hidden": True}
    return result


# Keys inside engine event ``data`` that carry names or client addresses.
SENSITIVE_EVENT_KEYS = frozenset({"parent", "top_clients", "match", "client", "clients",
                                  "name", "names", "domains"})


def shape_events(payload: Any, can_see_names: bool) -> Any:
    if not isinstance(payload, dict):
        return payload
    raw = payload.get("items")
    items = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        item = dict(item)
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        if can_see_names:
            item["data"] = data
            item["hidden"] = False
        else:
            item["data"] = {key: value for key, value in data.items()
                            if key not in SENSITIVE_EVENT_KEYS}
            item["hidden"] = any(key in SENSITIVE_EVENT_KEYS for key in data)
        items.append(item)
    return {"items": items, "next": payload.get("next")}


def _export_name(fmt: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return f"mrk-dns-logs-{stamp}.{'csv' if fmt == 'csv' else 'ndjson'}"


def _summary(params: dict[str, str]) -> str:
    keys = ("format", "from", "to", "client", "name", "qtype", "rcode", "source", "blocked")
    return ",".join(f"{key}={params[key]}" for key in keys if key in params)[:255] or "all"


def register_routes(
    ctx: ModuleContext,
    router: APIRouter,
    service: Any,
    *,
    fail: Callable[[Any], JSONResponse],
    audit: Callable[..., Awaitable[None]],
    change: Callable[..., Awaitable[Any]],
    read: Callable[..., Awaitable[Any]],
) -> None:
    client = service.client

    def limit_error(scope: str, limit: int) -> JSONResponse:
        return ctx.error_payload(  # type: ignore[call-arg]
            "dns_stream_limit", "Too many open log streams; close one and try again", 429,
            scope=scope, limit=limit,
        )

    # ---------------------------------------------------------------- query log
    @router.get("/logs", response_model=None)
    async def search_logs(request: Request) -> Any:
        async def work() -> Any:
            params = dns_filters.query_filters(request.query_params, mode="search")
            return await client.get("/v1/querylog" + dns_filters.encode(params), timeout=8.0)

        return await read(request, "dns:logs", work)

    @router.get("/logs/status", response_model=None)
    async def logs_status(request: Request) -> Any:
        return await read(request, "dns:logs", lambda: client.get("/v1/querylog/status"))

    @router.get("/logs/stream", response_model=None)
    async def stream_logs(request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:logs")
        try:
            params = dns_filters.query_filters(request.query_params, mode="stream")
        except DnsInputError as exc:
            return fail(exc)
        full = STREAM_SLOTS.acquire(principal.user_id)
        if full is not None:
            return limit_error(full, STREAMS_PER_USER if full == "user" else STREAMS_TOTAL)
        try:
            stream = await client.open_stream(
                "/v1/querylog/stream" + dns_filters.encode(params),
                max_bytes=STREAM_MAX_BYTES, max_seconds=STREAM_MAX_SECONDS,
                read_timeout=STREAM_READ_TIMEOUT,
            )
        except DnsError as exc:
            STREAM_SLOTS.release(principal.user_id)
            return fail(exc)
        except BaseException:
            STREAM_SLOTS.release(principal.user_id)
            raise
        cleanup = Cleanup(stream, lambda: STREAM_SLOTS.release(principal.user_id))
        return ManagedStreamingResponse(
            sse_events(stream, request.is_disconnected, cleanup), cleanup,
            media_type="text/event-stream",
            headers={"X-Accel-Buffering": "no"},  # no-store comes from the middleware
        )

    @router.get("/logs/export", response_model=None)
    async def export_logs(request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:logs")
        try:
            params = dns_filters.query_filters(request.query_params, mode="export")
        except DnsInputError as exc:
            return fail(exc)
        full = EXPORT_SLOTS.acquire(principal.user_id)
        if full is not None:
            return limit_error(full, EXPORTS_PER_USER if full == "user" else EXPORTS_TOTAL)
        try:
            stream = await client.open_stream(
                "/v1/querylog/export" + dns_filters.encode(params),
                max_bytes=EXPORT_MAX_BYTES, max_seconds=EXPORT_MAX_SECONDS,
                read_timeout=EXPORT_READ_TIMEOUT,
            )
        except DnsError as exc:
            EXPORT_SLOTS.release(principal.user_id)
            if exc.status_code not in {404, 422}:
                await audit(principal, "dns.logs.export", "dns_querylog", _summary(params),
                            "failure")
            return fail(exc)
        except BaseException:
            EXPORT_SLOTS.release(principal.user_id)
            raise
        cleanup = Cleanup(stream, lambda: EXPORT_SLOTS.release(principal.user_id))
        await audit(principal, "dns.logs.export", "dns_querylog", _summary(params))

        async def body() -> AsyncIterator[bytes]:
            try:
                async for chunk in stream.chunks():
                    yield chunk
            except StreamLimit as exc:
                LOGGER.warning("dns log export stopped at the panel limit (%s)", exc.reason)
            except DnsError as exc:
                LOGGER.warning("dns log export broke off (%s)", exc.extra.get("reason"))
            finally:
                await cleanup()

        fmt = params["format"]
        media = "text/csv; charset=utf-8" if fmt == "csv" else "application/x-ndjson"
        return ManagedStreamingResponse(
            body(), cleanup, media_type=media,
            headers={"Content-Disposition": f'attachment; filename="{_export_name(fmt)}"'},
        )

    @router.delete("/logs", response_model=None)
    async def delete_logs(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            engine_body, expected = dns_filters.delete_body(body)
            confirmation = body.get("confirmation") if isinstance(body, dict) else None
            if not dns_filters.confirmation_ok(confirmation, expected,
                                               engine_body.get("client")):
                raise DnsError(
                    "confirmation_mismatch", 422,
                    f"Type {expected} to confirm",
                    fields=[{"field": "confirmation", "reason_code": "incorrect"}],
                    expected_confirmation=expected,
                )
            result = await client.request("DELETE", "/v1/querylog", engine_body, timeout=30.0)
            target = ",".join(f"{key}={value}" for key, value in engine_body.items()) or "all"
            return result, target

        return await change(request, "dns:admin", "dns.logs.delete", "dns_querylog", None, work)

    # ---------------------------------------------------------------- stats / pressure
    @router.get("/stats", response_model=None)
    async def stats(request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:read")
        try:
            unknown = sorted(set(request.query_params) - {"range", "_"})
            if unknown:
                raise DnsInputError("dns_query_invalid", "Unknown parameters", [
                    {"field": key[:40], "reason_code": "unknown_field"} for key in unknown[:10]])
            rng = dns_filters.stats_range(request.query_params.get("range"))
            payload = await client.get(f"/v1/stats?range={rng}", timeout=8.0)
        except (DnsInputError, DnsError) as exc:
            return fail(exc)
        return shape_stats(payload, principal.allows("dns:logs"))

    @router.get("/pressure", response_model=None)
    async def pressure(request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:read")
        try:
            payload = await client.get("/v1/pressure", timeout=3.0)
        except DnsError as exc:
            return fail(exc)
        service.monitor.remember_pressure(payload)
        return shape_pressure(payload, principal.allows("dns:logs"))

    @router.get("/events", response_model=None)
    async def events(request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:read")
        try:
            unknown = sorted(set(request.query_params) - {"after", "_"})
            raw = request.query_params.get("after") or "0"
            fields = [{"field": key[:40], "reason_code": "unknown_field"} for key in unknown[:10]]
            if not raw.isdigit() or len(raw) > 18:
                fields.append({"field": "after", "reason_code": "invalid_type"})
            if fields:
                raise DnsInputError("dns_query_invalid", "Invalid parameters", fields)
            payload = await client.get(f"/v1/events?after={int(raw)}", timeout=5.0)
        except (DnsInputError, DnsError) as exc:
            return fail(exc)
        return shape_events(payload, principal.allows("dns:logs"))

    # ---------------------------------------------------------------- mitigations
    @router.get("/mitigations", response_model=None)
    async def list_mitigations(request: Request) -> Any:
        return await read(request, "dns:write", lambda: client.get("/v1/mitigations"))

    @router.post("/mitigations", status_code=201, response_model=None)
    async def create_mitigation(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            payload = dns_filters.mitigation_body(body)
            result = await client.request("POST", "/v1/mitigations", payload)
            return result, f"{payload['kind']}:{payload['match']}:{payload['action']}"

        return await change(request, "dns:write", "dns.mitigation.create", "dns_mitigation",
                            None, work)

    @router.delete("/mitigations/{mitigation_id}", response_model=None)
    async def delete_mitigation(mitigation_id: str, request: Request) -> Any:
        async def work(_body: Any) -> tuple[Any, str | None]:
            mid = entity_id(mitigation_id)
            await client.request("DELETE", f"/v1/mitigations/{mid}")
            return {"deleted": mid}, mid

        return await change(request, "dns:write", "dns.mitigation.delete", "dns_mitigation",
                            mitigation_id[:255], work)
