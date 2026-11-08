"""The ``mrk-firewall`` HTTP API. Every route except ``GET /v1/health`` is HMAC-signed.

Routes (signed, JSON):

* ``GET  /v1/info``    version, nft availability, applied state, table counters,
  host-local addresses (never blockable).
* ``POST /v1/apply``   ``{mode, allow: [cidr], blocks: [{cidr, expires_at}]}``. enforce ->
  atomic replace of table ``inet mrk``; off/dry_run -> table removed. Persisted and
  re-applied on startup.
* ``POST /v1/signals`` ``{sources: [{name, kind, path}], sensitive_paths: [..]}`` -> new
  signals parsed from the appended part of each log file since the previous call.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..agent.signing import RequestVerifier, SignatureError
from . import FIREWALL_VERSION, netinfo
from .nft import (
    DEFAULT_NFT,
    DesiredState,
    DesiredStateError,
    NftError,
    NftManager,
    NftRunner,
    Runner,
    render_ruleset,
)
from .parsers import SOURCE_KINDS, PathMatcher, parse_lines, validate_patterns
from .tail import DEFAULT_MAX_BYTES, FileTailer

LOGGER = logging.getLogger("mrk_control_plane.firewall")
STATE_FILE = "desired.json"
DEFAULT_STATE_DIR = "/var/lib/mrk-firewall"
DEFAULT_LOG_ROOT = "/host/log"
_MAX_BODY_BYTES = 4 * 1024 * 1024
_MAX_SOURCES = 8
_MAX_SIGNALS = 5000
_SIGNED_ROUTES = {("GET", "/v1/info"), ("POST", "/v1/apply"), ("POST", "/v1/signals")}
_SOURCE_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class FirewallConfig:
    key: bytes
    state_dir: Path = field(default_factory=lambda: Path(DEFAULT_STATE_DIR))
    log_root: Path = field(default_factory=lambda: Path(DEFAULT_LOG_ROOT))
    nft_binary: str = DEFAULT_NFT
    force_dry_run: bool = False
    proc_net: Path = field(default_factory=lambda: Path("/proc/net"))

    @classmethod
    def from_env(cls, key: bytes, state_dir: Path) -> FirewallConfig:
        return cls(
            key=key,
            state_dir=state_dir,
            log_root=Path(os.getenv("MRK_FIREWALL_LOG_ROOT", "").strip() or DEFAULT_LOG_ROOT),
            nft_binary=os.getenv("MRK_FIREWALL_NFT", "").strip() or DEFAULT_NFT,
            force_dry_run=_truthy(os.getenv("MRK_FIREWALL_FORCE_DRY_RUN", "")),
        )


def _error(code: str, status_code: int, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": code, **extra})


class SignatureMiddleware:
    def __init__(self, app: Any, verifier: RequestVerifier) -> None:
        self.app = app
        self.verifier = verifier

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method, path = scope["method"], scope["path"]
        if path == "/v1/health" and method == "GET":
            await self.app(scope, receive, send)
            return
        if (method, path) not in _SIGNED_ROUTES:
            await _error("not_found", 404)(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > _MAX_BODY_BYTES:
                await _error("body_too_large", 413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        raw_path = scope.get("raw_path") or path.encode()
        query = scope.get("query_string") or b""
        path_with_query = raw_path.decode("latin-1") + (
            "?" + query.decode("latin-1") if query else ""
        )
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers") or []}
        try:
            self.verifier.verify(method, path_with_query, headers, bytes(body))
        except SignatureError as exc:
            LOGGER.warning("rejected unauthenticated request", extra={"reason": exc.reason})
            await _error("auth_failed", 401, reason=exc.reason)(scope, receive, send)
            return
        sent = False

        async def replay() -> dict[str, Any]:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


_LOG_PATH = re.compile(r"^/host/log/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){0,7}$")


def resolve_source(log_root: Path, value: object) -> Path:
    """Map a logical ``/host/log/...`` path onto the log root (MRK_FIREWALL_LOG_ROOT).

    The API namespace is always ``/host/log/``; ``..`` segments are refused and the
    resolved path (symlinks followed) must stay inside the root, so only the files the
    operator mounted read-only there can ever be read.
    """
    if not isinstance(value, str) or not _LOG_PATH.fullmatch(value) \
            or any(part in {".", ".."} for part in value.split("/")):
        raise ValueError(f"source path must be a file under {DEFAULT_LOG_ROOT}/")
    root = log_root.resolve()
    resolved = (root / value[len(DEFAULT_LOG_ROOT) + 1:]).resolve()
    if root not in resolved.parents:
        raise ValueError(f"source path must be a file under {DEFAULT_LOG_ROOT}/")
    return resolved


class HelperState:
    def __init__(self, config: FirewallConfig, runner: Runner) -> None:
        self.config = config
        self.manager = NftManager(runner, config.state_dir)
        self.runner = runner
        self.lock = asyncio.Lock()
        self.desired = DesiredState(mode="dry_run")
        self.applied_at: float | None = None
        self.last_error: str | None = None
        self.tailers: dict[tuple[str, str], FileTailer] = {}

    @property
    def state_path(self) -> Path:
        return self.config.state_dir / STATE_FILE

    def effective(self, state: DesiredState) -> DesiredState:
        if self.config.force_dry_run and state.mode == "enforce":
            return DesiredState(mode="dry_run", allow=state.allow, blocks=state.blocks)
        return state

    def persist(self, state: DesiredState) -> None:
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(f".{STATE_FILE}.{secrets.token_hex(4)}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state.to_payload(), handle, separators=(",", ":"))
        os.replace(temporary, self.state_path)

    def load(self) -> DesiredState | None:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            return DesiredState.from_payload(payload)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            LOGGER.error("ignoring unreadable firewall state file",
                         extra={"error": type(exc).__name__})
            return None

    def apply(self, state: DesiredState) -> dict[str, Any]:
        effective = self.effective(state)
        result = self.manager.apply(effective)
        self.desired = state
        self.applied_at = time.time()
        self.last_error = None
        self.persist(state)
        return result


def create_firewall_app(config: FirewallConfig, *, runner: Runner | None = None) -> FastAPI:
    verifier = RequestVerifier(config.key)
    helper = HelperState(config, runner or NftRunner(config.nft_binary, config.state_dir))

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        stored = await asyncio.to_thread(helper.load)
        target = stored or DesiredState(mode="dry_run")
        try:
            # Startup reconcile: enforce -> rebuild our table with remaining timeouts;
            # anything else -> make sure no table of ours is left behind.
            async with helper.lock:
                await asyncio.to_thread(helper.apply, target)
            LOGGER.info("mrk-firewall started", extra={"mode": target.mode,
                                                       "blocks": len(target.blocks)})
        except (NftError, OSError) as exc:
            helper.last_error = getattr(exc, "message", type(exc).__name__)
            helper.desired = target
            LOGGER.error("startup reconcile failed", extra={"error": helper.last_error})
        yield
        LOGGER.info("mrk-firewall stopped")

    app = FastAPI(title="mrk-firewall", docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.helper = helper
    app.add_middleware(SignatureMiddleware, verifier=verifier)

    async def body_json(request: Request) -> Any:
        raw = await request.body()
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            return None

    @app.get("/v1/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/info")
    async def info() -> dict[str, Any]:
        table = await asyncio.to_thread(helper.manager.table_status)
        addresses = await asyncio.to_thread(netinfo.local_addresses, config.proc_net)
        return {
            "version": FIREWALL_VERSION,
            "nft_available": helper.runner.available(),
            "force_dry_run": config.force_dry_run,
            "mode": helper.desired.mode,
            "effective_mode": helper.effective(helper.desired).mode,
            "state_hash": helper.desired.state_hash(),
            "applied_at": helper.applied_at,
            "last_error": helper.last_error,
            "table": table,
            "local_addresses": addresses,
        }

    @app.post("/v1/apply")
    async def apply(request: Request):
        payload = await body_json(request)
        try:
            state = DesiredState.from_payload(payload)
        except DesiredStateError as exc:
            return _error(exc.code, 422, message=str(exc))
        async with helper.lock:
            try:
                result = await asyncio.to_thread(helper.apply, state)
            except NftError as exc:
                helper.last_error = exc.message
                LOGGER.error("nft apply failed", extra={"code": exc.code})
                return _error(exc.code, 503 if exc.code == "nft_unavailable" else 502,
                              message=exc.message)
        effective = helper.effective(state)
        return {
            "ok": True,
            "mode": state.mode,
            "effective_mode": effective.mode,
            "state_hash": state.state_hash(),
            "action": result["action"],
            "nft_available": result["nft_available"],
            "allow_count": len(state.allow),
            "block_count": len(state.blocks),
            "ruleset": render_ruleset(DesiredState("enforce", state.allow, state.blocks))[:200_000],
        }

    @app.post("/v1/signals")
    async def signals(request: Request):
        payload = await body_json(request)
        if not isinstance(payload, dict) or set(payload) - {"sources", "sensitive_paths",
                                                            "max_bytes"}:
            return _error("invalid_request", 422)
        sources = payload.get("sources", [])
        if not isinstance(sources, list) or len(sources) > _MAX_SOURCES:
            return _error("invalid_request", 422, message="at most 8 sources")
        try:
            matcher = PathMatcher(validate_patterns(payload.get("sensitive_paths", [])))
        except (ValueError, TypeError) as exc:
            return _error("invalid_request", 422, message=str(exc))
        max_bytes = payload.get("max_bytes", DEFAULT_MAX_BYTES)
        if not isinstance(max_bytes, int) or not 4096 <= max_bytes <= 16 * 1024 * 1024:
            return _error("invalid_request", 422, message="max_bytes out of range")
        wanted: list[tuple[str, str, Path]] = []
        for item in sources:
            if not isinstance(item, dict) or set(item) != {"name", "kind", "path"}:
                return _error("invalid_request", 422, message="source is {name, kind, path}")
            name, kind = item["name"], item["kind"]
            if not isinstance(name, str) or not _SOURCE_NAME.fullmatch(name) \
                    or kind not in SOURCE_KINDS:
                return _error("invalid_request", 422, message="invalid source name or kind")
            try:
                path = resolve_source(config.log_root, item["path"])
            except ValueError as exc:
                return _error("invalid_source_path", 422, message=str(exc), source=name)
            wanted.append((name, kind, path))

        def collect() -> dict[str, Any]:
            keys = {(name, str(path)) for name, _kind, path in wanted}
            for stale in set(helper.tailers) - keys:
                helper.tailers.pop(stale, None)
            out: list[dict[str, Any]] = []
            report: dict[str, Any] = {}
            dropped = 0
            for name, kind, path in wanted:
                tailer = helper.tailers.setdefault((name, str(path)), FileTailer(path))
                result = tailer.read(max_bytes)
                now = time.time()
                parsed = parse_lines(kind, result.lines, matcher)
                for signal in parsed:
                    if len(out) >= _MAX_SIGNALS:
                        dropped += 1
                        continue
                    out.append(signal.to_dict(name, now))
                report[name] = {
                    "ok": result.error is None,
                    "error": result.error,
                    "rotated": result.rotated,
                    "truncated": result.truncated,
                    "more": result.more,
                    "lines": len(result.lines),
                    "signals": len(parsed),
                }
            return {"signals": out, "sources": report, "dropped": dropped}

        result = await asyncio.to_thread(collect)
        result["state_hash"] = helper.desired.state_hash()
        result["mode"] = helper.desired.mode
        return result

    return app
