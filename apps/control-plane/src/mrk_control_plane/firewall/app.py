"""The ``mrk-firewall`` HTTP API. Every route except ``GET /v1/health`` is HMAC-signed.

Routes (signed, JSON):

* ``GET  /v1/info``    version, nft availability, applied state, table counters,
  host-local addresses (never blockable).
* ``POST /v1/apply``   ``{mode, allow: [cidr], blocks: [{cidr, expires_at}]}``. enforce ->
  atomic replace of table ``inet mrk``; off/dry_run -> table removed. Persisted and
  re-applied on startup.
* ``POST /v1/signals`` ``{sources: [{name, kind, path}], sensitive_paths: [..]}`` -> new
  signals parsed from the appended part of each log file since the previous call.

Port policy (docs/45), carried as ``ports`` in ``/v1/apply``:

* The helper keeps the last-known-good (LKG = last confirmed) policy. An apply whose
  policy differs from the LKG (temporary allows aside) must carry ``rollback_seconds``;
  it becomes *pending* and is rolled back to the LKG when not confirmed in time, also
  when the helper restarts meanwhile. Turning the policy off is always allowed.
* ``POST /v1/confirm``  ``{token}`` -> the pending policy becomes the LKG.
* ``POST /v1/recover``  ``{open: bool}`` -> LKG now (or policy off); used by the panel's
  "undo now" and by the console command ``mrk-firewall recover``.
* ``GET  /v1/import``   read-only UFW / PAASIFY-DOCKER-FW / sshd facts as proposals.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..agent.signing import RequestVerifier, SignatureError
from . import FIREWALL_VERSION, importers, netinfo
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
from .ports import PortError, PortPolicy, risk_key
from .tail import DEFAULT_MAX_BYTES, FileTailer

LOGGER = logging.getLogger("mrk_control_plane.firewall")
STATE_FILE = "desired.json"
PORTS_FILE = "ports.json"
DEFAULT_STATE_DIR = "/var/lib/mrk-firewall"
DEFAULT_LOG_ROOT = "/host/log"
DEFAULT_HOST_ETC = "/host/etc"
MIN_ROLLBACK_SECONDS, MAX_ROLLBACK_SECONDS = 30, 900
_MAX_BODY_BYTES = 4 * 1024 * 1024
_MAX_SOURCES = 8
_MAX_SIGNALS = 5000
_SIGNED_ROUTES = {("GET", "/v1/info"), ("POST", "/v1/apply"), ("POST", "/v1/signals"),
                  ("POST", "/v1/confirm"), ("POST", "/v1/recover"), ("GET", "/v1/import")}
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
    # Read-only host config mounts (ufw/, ssh/) used by /v1/import and the SSH check.
    host_etc: Path = field(default_factory=lambda: Path(DEFAULT_HOST_ETC))
    clock: Callable[[], float] = time.time

    @classmethod
    def from_env(cls, key: bytes, state_dir: Path) -> FirewallConfig:
        return cls(
            key=key,
            state_dir=state_dir,
            log_root=Path(os.getenv("MRK_FIREWALL_LOG_ROOT", "").strip() or DEFAULT_LOG_ROOT),
            host_etc=Path(os.getenv("MRK_FIREWALL_HOST_ETC", "").strip() or DEFAULT_HOST_ETC),
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
        # Port policy safety (docs/45): last confirmed policy, the unconfirmed change.
        self.lkg: PortPolicy | None = None
        self.pending: dict[str, Any] | None = None  # {token, key, deadline, started_at}
        self.last_rollback: dict[str, Any] | None = None

    @property
    def state_path(self) -> Path:
        return self.config.state_dir / STATE_FILE

    @property
    def ports_path(self) -> Path:
        return self.config.state_dir / PORTS_FILE

    def effective(self, state: DesiredState) -> DesiredState:
        if self.config.force_dry_run and (state.mode == "enforce" or state.ports is not None):
            return DesiredState(mode="dry_run", allow=state.allow, blocks=state.blocks)
        return state

    def _write(self, path: Path, payload: Any) -> None:
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))
        os.replace(temporary, path)

    def persist(self, state: DesiredState) -> None:
        self._write(self.state_path, state.to_payload())

    def persist_ports(self) -> None:
        self._write(self.ports_path, {
            "lkg": None if self.lkg is None else self.lkg.to_payload(),
            "pending": self.pending,
            "last_rollback": self.last_rollback,
        })

    def load_ports(self, now: float) -> None:
        try:
            payload = json.loads(self.ports_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            LOGGER.error("ignoring unreadable port policy state file")
            return
        if not isinstance(payload, dict):
            return
        try:
            lkg = payload.get("lkg")
            self.lkg = None if lkg is None else PortPolicy.from_payload(lkg, now=now)
        except PortError:
            LOGGER.error("ignoring an invalid last-known-good port policy")
            self.lkg = None
        pending = payload.get("pending")
        self.pending = pending if isinstance(pending, dict) else None
        last = payload.get("last_rollback")
        self.last_rollback = last if isinstance(last, dict) else None

    def ports_info(self, now: float | None = None) -> dict[str, Any]:
        current = self.config.clock() if now is None else now
        pending = None
        if self.pending is not None:
            deadline = float(self.pending.get("deadline", 0))
            pending = {**self.pending, "remaining": max(0, int(deadline - current))}
        return {
            "active": self.desired.ports_active(),
            "key": risk_key(self.desired.ports),
            "lkg_key": risk_key(self.lkg),
            "lkg": None if self.lkg is None else self.lkg.to_payload(),
            "pending": pending,
            "last_rollback": self.last_rollback,
        }

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

    def apply(self, state: DesiredState, *, rollback_seconds: int | None = None,
              now: float | None = None) -> dict[str, Any]:
        """Apply a state; a port policy that differs from the LKG needs a rollback timer."""
        current = self.config.clock() if now is None else now
        new_key = risk_key(state.ports)
        if self.pending is not None and new_key == self.pending.get("key"):
            plan = "keep"  # the pending change itself (e.g. a block was added meanwhile)
        elif new_key == risk_key(self.lkg):
            plan = "lkg"
        elif new_key == "off" or self.config.force_dry_run:
            plan = "safe"  # opening everything (or never enforcing) cannot lock anyone out
        elif rollback_seconds is None:
            raise DesiredStateError(
                "this port policy is not the last confirmed one; apply it with a rollback "
                "timer and confirm it", "rollback_required")
        else:
            plan = "risky"
        result = self.manager.apply(self.effective(state), now=current)
        self.desired = state
        self.applied_at = time.time()
        self.last_error = None
        if plan == "lkg":
            self.pending = None
        elif plan == "safe":
            self.lkg = state.ports if state.ports_active() else None
            self.pending = None
        elif plan == "risky":
            assert rollback_seconds is not None
            self.pending = {"token": secrets.token_hex(8), "key": new_key,
                            "deadline": int(current) + rollback_seconds,
                            "started_at": int(current)}
            LOGGER.warning("port policy applied; automatic rollback armed",
                           extra={"seconds": rollback_seconds})
        self.persist(state)
        self.persist_ports()
        return {**result, "plan": plan}

    def confirm(self, token: object) -> None:
        if self.pending is None:
            raise DesiredStateError("there is no unconfirmed port policy", "no_pending_change")
        if not isinstance(token, str) or not secrets.compare_digest(
            token, str(self.pending.get("token", ""))
        ):
            raise DesiredStateError("the confirmation token does not match", "token_mismatch")
        self.lkg = self.desired.ports if self.desired.ports_active() else None
        self.pending = None
        self.persist_ports()
        LOGGER.info("port policy confirmed")

    def restore(self, reason: str, *, open_ports: bool = False,
                now: float | None = None) -> dict[str, Any]:
        """Load the LKG port policy (or none at all); fail open if that cannot be loaded."""
        current = self.config.clock() if now is None else now
        if open_ports:
            self.lkg = None
        previous_key = risk_key(self.desired.ports)
        if self.lkg is not None:
            ports: PortPolicy | None = PortPolicy.from_payload(self.lkg.to_payload(), now=current)
        else:
            ports = None
        target = DesiredState(mode=self.desired.mode, allow=self.desired.allow,
                              blocks=self.desired.blocks, ports=ports)
        try:
            self.manager.apply(self.effective(target), now=current)
            outcome = "restored"
        except NftError as exc:
            LOGGER.error("restoring the last-known-good ruleset failed; removing our table",
                         extra={"code": exc.code})
            self.last_error = exc.message
            try:
                self.manager.delete_table()
                outcome = "table_deleted"
            except NftError as again:
                self.last_error = again.message
                outcome = "failed"
        self.desired = target
        self.pending = None
        self.last_rollback = {"at": int(current), "reason": reason, "outcome": outcome,
                              "from_key": previous_key, "to_key": risk_key(ports)}
        self.persist(target)
        self.persist_ports()
        LOGGER.warning("port policy rolled back", extra={"reason": reason, "outcome": outcome})
        return self.last_rollback

    def check_rollback(self, now: float | None = None) -> dict[str, Any] | None:
        current = self.config.clock() if now is None else now
        if self.pending is None or current < float(self.pending.get("deadline", 0)):
            return None
        return self.restore("timeout", now=current)


def create_firewall_app(config: FirewallConfig, *, runner: Runner | None = None,
                        iptables: importers.IptablesRunner | None = None) -> FastAPI:
    verifier = RequestVerifier(config.key)
    iptables = iptables or importers.IptablesRunner()
    helper = HelperState(config, runner or NftRunner(config.nft_binary, config.state_dir))

    async def rollback_loop() -> None:
        while True:
            await asyncio.sleep(1.0)
            pending = helper.pending
            if pending is None or config.clock() < float(pending.get("deadline", 0)):
                continue
            try:
                async with helper.lock:
                    await asyncio.to_thread(helper.check_rollback)
            except Exception:  # pragma: no cover - keep the safety net alive
                LOGGER.exception("automatic rollback failed")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        stored = await asyncio.to_thread(helper.load)
        target = stored or DesiredState(mode="dry_run")
        now = config.clock()
        await asyncio.to_thread(helper.load_ports, now)
        if helper.pending is not None:
            # Restarted while a port change was unconfirmed: start from the LKG.
            target = DesiredState(mode=target.mode, allow=target.allow, blocks=target.blocks,
                                  ports=helper.lkg)
            helper.pending = None
            helper.last_rollback = {"at": int(now), "reason": "restart", "outcome": "restored",
                                    "from_key": risk_key(stored.ports if stored else None),
                                    "to_key": risk_key(helper.lkg)}
        elif helper.lkg is None and target.ports_active() and not helper.ports_path.exists():
            helper.lkg = target.ports
        elif risk_key(target.ports) != risk_key(helper.lkg):
            # Interrupted between the two state files: never start from an unconfirmed policy.
            target = DesiredState(mode=target.mode, allow=target.allow, blocks=target.blocks,
                                  ports=helper.lkg)
        try:
            # Startup reconcile: rebuild our table with remaining timeouts, or make sure
            # no table of ours is left behind.
            async with helper.lock:
                await asyncio.to_thread(helper.apply, target, rollback_seconds=None)
            LOGGER.info("mrk-firewall started", extra={"mode": target.mode,
                                                       "blocks": len(target.blocks)})
        except (NftError, OSError, DesiredStateError) as exc:
            helper.last_error = getattr(exc, "message", None) or str(exc) or type(exc).__name__
            helper.desired = target
            LOGGER.error("startup reconcile failed", extra={"error": helper.last_error})
        task = asyncio.create_task(rollback_loop(), name="mrk-firewall-rollback")
        yield
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
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
            "ports": helper.ports_info(),
            "ssh": await asyncio.to_thread(importers.read_sshd_ports, config.host_etc),
            "listening": await asyncio.to_thread(netinfo.listening_ports, config.proc_net),
        }

    @app.post("/v1/apply")
    async def apply(request: Request):
        payload = await body_json(request)
        rollback_seconds = None
        if isinstance(payload, dict) and "rollback_seconds" in payload:
            payload = dict(payload)
            rollback_seconds = payload.pop("rollback_seconds")
            if rollback_seconds is not None and (
                not isinstance(rollback_seconds, int) or isinstance(rollback_seconds, bool)
                or not MIN_ROLLBACK_SECONDS <= rollback_seconds <= MAX_ROLLBACK_SECONDS
            ):
                return _error("invalid_state", 422, message="rollback_seconds must be "
                              f"{MIN_ROLLBACK_SECONDS}..{MAX_ROLLBACK_SECONDS}")
        try:
            state = DesiredState.from_payload(payload, now=config.clock())
        except DesiredStateError as exc:
            return _error(exc.code, 422, message=str(exc))
        async with helper.lock:
            try:
                result = await asyncio.to_thread(helper.apply, state,
                                                 rollback_seconds=rollback_seconds)
            except DesiredStateError as exc:
                return _error(exc.code, 409, message=str(exc), ports=helper.ports_info())
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
            "ruleset": render_ruleset(DesiredState("enforce", state.allow, state.blocks,
                                                   state.ports))[:200_000],
            "ports": helper.ports_info(),
        }

    @app.post("/v1/confirm")
    async def confirm(request: Request):
        payload = await body_json(request)
        if not isinstance(payload, dict) or set(payload) != {"token"}:
            return _error("invalid_request", 422, message="body is {token}")
        async with helper.lock:
            try:
                await asyncio.to_thread(helper.confirm, payload["token"])
            except DesiredStateError as exc:
                return _error(exc.code, 409, message=str(exc), ports=helper.ports_info())
        return {"ok": True, "ports": helper.ports_info()}

    @app.post("/v1/recover")
    async def recover(request: Request):
        payload = await body_json(request)
        if not isinstance(payload, dict) or set(payload) - {"open", "reason"} or not isinstance(
            payload.get("open", False), bool
        ):
            return _error("invalid_request", 422, message="body is {open: bool}")
        reason = payload.get("reason", "recover")
        if reason not in {"recover", "undo"}:
            return _error("invalid_request", 422, message="reason is recover or undo")
        async with helper.lock:
            outcome = await asyncio.to_thread(
                helper.restore, f"{reason}_open" if payload.get("open") else reason,
                open_ports=bool(payload.get("open")))
        return {"ok": outcome["outcome"] != "failed", "rollback": outcome,
                "ports": helper.ports_info()}

    @app.get("/v1/import")
    async def import_rules() -> dict[str, Any]:
        def collect() -> dict[str, Any]:
            return {
                "ufw": importers.read_ufw(config.host_etc),
                "legacy": importers.read_legacy_chain(iptables),
                "ssh": importers.read_sshd_ports(config.host_etc),
                "listening": netinfo.listening_ports(config.proc_net),
            }

        return await asyncio.to_thread(collect)

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
