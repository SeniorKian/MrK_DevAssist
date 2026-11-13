"""Builds from the internal mirrors (docs/48, phase 1).

Layer A/B (Docker's registry mirror, BuildKit's mirrors) are applied on each server
by ``build_mirror_script.sh``; the panel builds the command and checks the result
through the Host Agent (read-only). Layer C (npm/PyPI variables in each Dokploy
application's env) is written by the panel through Dokploy's API.

Routes (``/api/v1/build-mirrors``): ``status``, ``settings``, ``command``,
``projects``, ``projects/apply``, ``projects/remove``, ``report``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shlex
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from ..module_context import ModuleContext
from . import build_mirror_coverage as coverage
from . import build_mirror_env as envblock

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "build_mirror"
STATE_FILE = "build-mirror.json"
SCRIPT_FILE = Path(__file__).with_name("build_mirror_script.sh")
SCRIPT_NAME = "devassist-build-mirror.sh"
HEREDOC_TAG = "DEVASSIST_SCRIPT"
DEFAULT_SETTINGS: dict[str, Any] = {
    "enabled": False,
    "npm": True,
    "pypi": True,
    "auto_apply_new": True,
    "npm_url": "",
    "pypi_url": "",
    "registry_host": "",
    "check_interval_seconds": 300,
}
SOURCE_TTL_SECONDS = 120.0
INSPECT_BUDGET = 30
AUTO_APPLY_BUDGET = 10
LOG_BUDGET = 3
LOG_TAIL = 3000
MAX_SEEN_DEPLOYMENTS = 500
MAX_COVERAGE = 500
_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::\d{1,5})?$")
_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DEPLOYABLE = ("application", "compose")


class BuildMirrorError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


def _clean_url(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parts = urlsplit(text)
    if (parts.scheme not in {"http", "https"} or not parts.hostname or parts.username
            or parts.password or parts.query or parts.fragment or len(text) > 300
            or any(char.isspace() for char in text)):
        raise BuildMirrorError("validation_error", 422, f"{field} must be an http(s) address")
    return text if text.endswith("/") else text + "/"


def validate_settings(payload: Any, current: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise BuildMirrorError("validation_error", 422, "settings must be an object")
    unknown = set(payload) - set(DEFAULT_SETTINGS)
    if unknown:
        raise BuildMirrorError("validation_error", 422, f"unknown setting: {sorted(unknown)[0]}")
    merged = {**current, **payload}
    for key in ("enabled", "npm", "pypi", "auto_apply_new"):
        if not isinstance(merged[key], bool):
            raise BuildMirrorError("validation_error", 422, f"{key} must be true or false")
    merged["npm_url"] = _clean_url(merged["npm_url"], "npm_url")
    merged["pypi_url"] = _clean_url(merged["pypi_url"], "pypi_url")
    host = str(merged["registry_host"] or "").strip().lower()
    host = host.removeprefix("https://").split("/", 1)[0]
    if host and not _HOST.fullmatch(host):
        raise BuildMirrorError("validation_error", 422, "registry_host must be a host name")
    merged["registry_host"] = host
    interval = merged["check_interval_seconds"]
    if isinstance(interval, bool) or not isinstance(interval, int) or not 0 <= interval <= 86400:
        raise BuildMirrorError("validation_error", 422, "check_interval_seconds: 0-86400")
    return merged


def build_command(action: str, args: list[str], script: str) -> str:
    """One paste: the script travels inside a quoted heredoc, no download needed."""
    argv = " ".join(shlex.quote(item) for item in [action, *args])
    return f"sudo bash -s -- {argv} <<'{HEREDOC_TAG}'\n{script.rstrip()}\n{HEREDOC_TAG}\n"


def _check(check_id: str, state: str, code: str, **params: Any) -> dict[str, Any]:
    return {"id": check_id, "state": state, "code": code, "params": params}


class BuildMirrorService:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.path = ctx.data_dir / "control-plane" / STATE_FILE
        self.lock = threading.Lock()
        self.sources: dict[str, tuple[float, dict[str, Any]]] = {}
        self._task: asyncio.Task[None] | None = None
        self.last_cycle: dict[str, Any] | None = None

    # ------------------------------------------------------------------ state
    def _read(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        settings = payload.get("settings") if isinstance(payload.get("settings"), dict) else {}
        payload["settings"] = {**DEFAULT_SETTINGS,
                               **{k: v for k, v in settings.items() if k in DEFAULT_SETTINGS}}
        for key in ("known", "seen_deployments"):
            if not isinstance(payload.get(key), list):
                payload[key] = []
        if not isinstance(payload.get("coverage"), dict):
            payload["coverage"] = {}
        return payload

    def _write(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(self.path)

    def get_settings(self) -> dict[str, Any]:
        return dict(self._read()["settings"])

    def put_settings(self, payload: Any, _user_id: int | None = None) -> dict[str, Any]:
        with self.lock:
            state = self._read()
            state["settings"] = validate_settings(payload, state["settings"])
            self._write(state)
            return dict(state["settings"])

    def _update_state(self, change: Any) -> None:
        with self.lock:
            state = self._read()
            change(state)
            self._write(state)

    # ------------------------------------------------------------------ neighbours
    def dokploy(self) -> Any | None:
        from . import dokploy

        service = dokploy.ACTIVE_SERVICE
        if service is None:
            return None
        try:
            source, url, _key = service.resolve()
        except Exception:  # noqa: BLE001 - a broken config counts as not connected
            return None
        return service if source is not None and url is not None else None

    def agent(self) -> Any | None:
        from .home import find_service

        return find_service(self.ctx, "HostAgentService")

    @staticmethod
    def _service_url(service_id: str) -> str | None:
        from . import services as services_module

        service = services_module.ACTIVE_SERVICE
        if service is None:
            return None
        try:
            return services_module.public_url(service.primary(service_id))
        except Exception:  # noqa: BLE001 - no database row / module not ready
            return None

    def endpoints(self) -> dict[str, Any]:
        """Mirror addresses: the saved ones, else each service's main domain."""
        settings = self.get_settings()
        npm, pypi, host = settings["npm_url"], settings["pypi_url"], settings["registry_host"]
        source = {"npm": "settings" if npm else None, "pypi": "settings" if pypi else None,
                  "registry": "settings" if host else None}
        if not npm and (base := self._service_url("npm")):
            npm, source["npm"] = base.rstrip("/") + "/", "domain"
        if not pypi and (base := self._service_url("pypi")):
            pypi, source["pypi"] = base.rstrip("/") + "/root/pypi/+simple/", "domain"
        if not host and (base := self._service_url("registry")):
            parts = urlsplit(base)
            if parts.scheme == "https" and parts.hostname:
                host, source["registry"] = parts.netloc, "domain"
        return {"npm": npm or None, "pypi": pypi or None, "registry": host or None,
                "source": source}

    def wanted(self) -> dict[str, str]:
        settings = self.get_settings()
        urls = self.endpoints()
        ecosystems = [name for name in envblock.ECOSYSTEMS if settings[name]]
        return envblock.wanted_values(urls["npm"], urls["pypi"], ecosystems)

    @staticmethod
    async def token_check() -> dict[str, Any]:
        """docs/48: can Docker pull from the registry without a password (token service)?"""
        from . import registry_service

        service = registry_service.ACTIVE_SERVICE
        if service is None or service.connected() is None:
            return _check("registry_token", "fail", "token_registry_missing")
        try:
            token = await asyncio.to_thread(service.get_token_settings)
            view = await service.docker_view()
        except Exception:  # noqa: BLE001
            return _check("registry_token", "fail", "token_registry_unreachable")
        if not token["enabled"]:
            return _check("registry_token", "fail", "token_off")
        if view["state"] == "unreachable":
            return _check("registry_token", "fail", "token_registry_unreachable")
        if view["state"] != "token" or view["realm"] != token["effective_realm"]:
            # Zot reloads config.json by itself; an old stack may still answer the old way.
            return _check("registry_token", "warn", "token_not_in_zot_yet")
        return _check("registry_token", "ok", "token_ok", realm=token["effective_realm"],
                      ranges=", ".join(token["trusted_ranges"]), scope=token["scope"])

    # ------------------------------------------------------------------ Dokploy services
    async def targets(self) -> list[dict[str, Any]]:
        dokploy = self.dokploy()
        if dokploy is None:
            raise BuildMirrorError("build_mirror_dokploy_missing", 409, "Connect Dokploy first")
        tree = await dokploy.projects()
        items: list[dict[str, Any]] = []
        for project in tree.get("items") or []:
            for service in project.get("services") or []:
                if service.get("type") in DEPLOYABLE and _ID.fullmatch(str(service.get("id"))):
                    items.append({"type": service["type"], "id": service["id"],
                                  "name": service.get("name") or service["id"],
                                  "project": project.get("name")})
        return items

    async def source(self, service_type: str, service_id: str, fresh: bool = False
                     ) -> dict[str, Any]:
        key = f"{service_type}:{service_id}"
        hit = self.sources.get(key)
        if hit and not fresh and time.monotonic() - hit[0] < SOURCE_TTL_SECONDS:
            return hit[1]
        dokploy = self.dokploy()
        if dokploy is None:
            raise BuildMirrorError("build_mirror_dokploy_missing", 409, "Connect Dokploy first")
        value = await dokploy.build_env_source(service_type, service_id)
        self.sources[key] = (time.monotonic(), value)
        return value

    def describe(self, target: dict[str, Any], source: dict[str, Any] | None,
                 wanted: dict[str, str], cover: dict[str, Any] | None) -> dict[str, Any]:
        item = {**target, "coverage": cover}
        if source is None:
            return {**item, "eligible": None, "state": "unknown", "reason": None,
                    "build_type": None, "overridden": []}
        eligible, reason = envblock.eligibility(source, target["type"])
        state = envblock.env_state(source.get("env"), wanted)
        status = state["state"]
        if not eligible:
            # A block left from before (e.g. the build type changed) still shows up.
            status = "leftover" if status != "missing" else "skipped"
        elif not wanted:
            status = "skipped"
            reason = "no_mirror_address"
        return {**item, "eligible": eligible, "state": status, "reason": reason,
                "build_type": source.get("buildType") or source.get("composeType"),
                "overridden": state["overridden"] if eligible else []}

    async def projects_view(self) -> dict[str, Any]:
        targets = await self.targets()
        wanted = self.wanted()
        cover = self._read()["coverage"]
        items, budget, partial = [], INSPECT_BUDGET, False
        for target in targets:
            key = f"{target['type']}:{target['id']}"
            hit = self.sources.get(key)
            source = hit[1] if hit and time.monotonic() - hit[0] < SOURCE_TTL_SECONDS else None
            if source is None and budget > 0:
                budget -= 1
                try:
                    source = await self.source(target["type"], target["id"])
                except Exception as exc:  # noqa: BLE001 - one bad service never hides the rest
                    LOGGER.info("build mirror: service unreadable",
                                extra={"error_code": getattr(exc, "code", type(exc).__name__)})
            elif source is None:
                partial = True
            items.append(self.describe(target, source, wanted, cover.get(key)))
        return {"items": items, "partial": partial, "wanted": sorted(wanted)}

    async def _change(self, target: dict[str, Any], mode: str,
                      wanted: dict[str, str]) -> dict[str, Any]:
        dokploy = self.dokploy()
        if dokploy is None:
            raise BuildMirrorError("build_mirror_dokploy_missing", 409, "Connect Dokploy first")
        base = {"type": target["type"], "id": target["id"]}
        try:
            source = await self.source(target["type"], target["id"], fresh=True)
            current = source.get("env") or ""
            if mode == "apply":
                eligible, reason = envblock.eligibility(source, target["type"])
                if not eligible:
                    return {**base, "result": "skipped", "reason": reason}
                updated = envblock.apply_block(current, wanted)
            else:
                updated = envblock.strip_block(current)
            no_block = mode == "remove" and envblock.split_block(current)[1] is None
            if updated == current or no_block:
                return {**base, "result": "unchanged", "reason": None}
            if len(updated.encode("utf-8")) > envblock.MAX_ENV_BYTES:
                return {**base, "result": "error", "reason": "env_too_large"}
            await dokploy.save_build_env(target["type"], target["id"], updated, source)
            self.sources.pop(f"{target['type']}:{target['id']}", None)
            return {**base, "result": "applied" if mode == "apply" else "removed", "reason": None}
        except BuildMirrorError:
            raise
        except Exception as exc:  # noqa: BLE001 - reported per service
            return {**base, "result": "error",
                    "reason": getattr(exc, "code", None) or type(exc).__name__}

    async def change(self, mode: str, targets: list[dict[str, Any]] | None) -> dict[str, Any]:
        wanted = self.wanted()
        if mode == "apply" and not wanted:
            raise BuildMirrorError("build_mirror_mirrors_missing", 409,
                                   "Give the npm or PyPI service a domain first")
        known = {(item["type"], item["id"]): item for item in await self.targets()}
        if targets is None:
            chosen = list(known.values())
        else:
            chosen = []
            for target in targets:
                key = (str(target.get("type")), str(target.get("id")))
                if key not in known:
                    raise BuildMirrorError("build_mirror_target_invalid", 422,
                                           f"unknown service {key[0]}:{key[1]}")
                chosen.append(known[key])
        results = []
        for target in chosen:
            results.append(await self._change(target, mode, wanted))

        def remember(state: dict[str, Any]) -> None:
            names = set(state["known"]) | {f"{t['type']}:{t['id']}" for t in known.values()}
            state["known"] = sorted(names)[-5000:]
            if mode == "apply":
                state["settings"]["enabled"] = True
            elif targets is None:
                state["settings"]["enabled"] = False

        await asyncio.to_thread(self._update_state, remember)
        counts: dict[str, int] = {}
        for item in results:
            counts[item["result"]] = counts.get(item["result"], 0) + 1
        return {"results": results, "counts": counts}

    # ------------------------------------------------------------------ server (agent)
    async def agent_facts(self) -> tuple[str, dict[str, Any] | None]:
        agent = self.agent()
        if agent is None:
            return "not_configured", None
        try:
            source, url, _key = agent.resolve()
        except Exception:  # noqa: BLE001
            return "not_configured", None
        if source is None or url is None:
            return "not_configured", None
        try:
            payload = await agent.request("GET", "/v1/build-mirror/facts", timeout=8.0)
        except Exception as exc:  # noqa: BLE001 - mapped to a state
            code = getattr(exc, "code", None)
            return ("outdated" if code == "agent_not_found" else "unreachable"), None
        return ("ok", payload) if isinstance(payload, dict) else ("unreachable", None)

    def command(self, action: str, *, allow_restart: bool = False) -> dict[str, Any]:
        if action not in {"install", "status", "undo"}:
            raise BuildMirrorError("validation_error", 422, "action: install, status or undo")
        urls = self.endpoints()
        if urls["registry"] is None and action == "install":
            raise BuildMirrorError("build_mirror_registry_missing", 409,
                                   "Give the image registry a domain with HTTPS first")
        args: list[str] = []
        if urls["registry"]:
            args += ["--registry", urls["registry"]]
        if action == "install":
            if urls["npm"]:
                args += ["--npm", urls["npm"]]
            if urls["pypi"]:
                args += ["--pypi", urls["pypi"]]
        if allow_restart and action in {"install", "undo"}:
            args.append("--allow-restart")
        # LF only: a CRLF copy (Windows checkout) would break bash on the server.
        script = SCRIPT_FILE.read_bytes().decode("utf-8").replace("\r\n", "\n")
        return {"action": action, "args": args, "command": build_command(action, args, script),
                "script_name": SCRIPT_NAME, "script": script}

    # ------------------------------------------------------------------ status
    async def status(self) -> dict[str, Any]:
        settings = self.get_settings()
        urls = self.endpoints()
        checks: list[dict[str, Any]] = []
        checks.append(_check("dokploy", "ok", "connected") if self.dokploy() else
                      _check("dokploy", "fail", "dokploy_not_connected"))
        for name in envblock.ECOSYSTEMS:
            url = urls[name]
            if not settings[name]:
                checks.append(_check(f"{name}_mirror", "skipped", "turned_off"))
            elif url is None:
                checks.append(_check(f"{name}_mirror", "fail", "mirror_address_missing"))
            elif url.startswith("http:"):
                checks.append(_check(f"{name}_mirror", "warn", "mirror_not_https", url=url))
            else:
                checks.append(_check(f"{name}_mirror", "ok", "mirror_ready", url=url))
        registry = urls["registry"]
        checks.append(_check("registry", "ok", "registry_ready", host=registry) if registry else
                      _check("registry", "fail", "registry_address_missing"))
        checks.append(await self.token_check())

        agent_state, facts = await self.agent_facts()
        checks.append(_check("agent", "ok", "agent_ok") if agent_state == "ok" else
                      _check("agent", "warn" if agent_state != "unreachable" else "fail",
                             f"agent_{agent_state}"))
        checks.extend(self._server_checks(facts, registry, settings))

        counts: dict[str, int] = {}
        project_error = None
        try:
            view = await self.projects_view() if self.dokploy() else {"items": []}
            for item in view["items"]:
                counts[item["state"]] = counts.get(item["state"], 0) + 1
        except Exception as exc:  # noqa: BLE001
            project_error = getattr(exc, "code", None) or type(exc).__name__
        pending = counts.get("missing", 0) + counts.get("outdated", 0)
        if project_error:
            checks.append(_check("projects", "fail", "projects_unreadable", error=project_error))
        elif pending:
            checks.append(_check("projects", "warn", "projects_pending", pending=pending, **counts))
        else:
            checks.append(_check("projects", "ok" if counts.get("applied") else "unknown",
                                 "projects_ready" if counts.get("applied") else "projects_none",
                                 **counts))
        results: dict[str, int] = {}
        for item in self._read()["coverage"].values():
            results[item.get("result", "unknown")] = results.get(item.get("result", "unknown"),
                                                                 0) + 1
        bad = results.get("none", 0) + results.get("partial", 0)
        checks.append(_check("coverage", "warn" if bad else ("ok" if results else "unknown"),
                             "coverage_gaps" if bad else
                             ("coverage_full" if results else "coverage_no_builds"), **results))
        states = [item["state"] for item in checks]
        overall = "fail" if "fail" in states else ("warn" if "warn" in states else "ok")
        return {"overall": overall, "checks": checks, "settings": settings, "endpoints": urls,
                "agent": {"state": agent_state, "facts": facts}, "last_cycle": self.last_cycle}

    @staticmethod
    def _server_checks(facts: dict[str, Any] | None, registry: str | None,
                       settings: dict[str, Any]) -> list[dict[str, Any]]:
        if not facts:
            return [_check("server", "unknown", "server_unknown")]
        checks: list[dict[str, Any]] = []
        marker = facts.get("marker")
        mirror = f"https://{registry}" if registry else None
        if not facts.get("host_root"):
            checks.append(_check("server", "unknown", "agent_no_host_root"))
        elif not marker:
            checks.append(_check("server", "fail", "script_not_run"))
        elif marker.get("valid") is False:
            checks.append(_check("server", "fail", "script_marker_invalid"))
        elif mirror and marker.get("registry") and marker["registry"].rstrip("/") != mirror:
            checks.append(_check("server", "warn", "script_old_registry",
                                 applied=marker["registry"]))
        else:
            checks.append(_check("server", "ok", "script_applied",
                                 at=marker.get("applied_at")))
        daemon = facts.get("daemon") or {}
        mirrors = [item.rstrip("/") for item in daemon.get("mirrors") or []]
        live = [item.rstrip("/") for item in facts.get("live_mirrors") or []]
        if mirror:
            checks.append(_check("daemon_file", "ok", "daemon_has_mirror") if mirror in mirrors
                          else _check("daemon_file", "fail", "daemon_no_mirror"))
            if facts.get("docker"):
                checks.append(_check("daemon_live", "ok", "docker_uses_mirror") if mirror in live
                              else _check("daemon_live", "warn", "docker_reload_needed"))
            else:
                checks.append(_check("daemon_live", "unknown", "docker_unreachable"))
        if marker and marker.get("valid") is not False:
            checks.append(_check("builder_file", "ok", "builder_file_written")
                          if marker.get("buildkit_file") else
                          _check("builder_file", "warn", "builder_file_missing"))
            test = marker.get("test") or "skipped"
            states = {"ok": "ok", "cached": "ok", "mirror_auth": "fail",
                      "not_via_mirror": "warn", "pull_failed": "fail"}
            checks.append(_check("self_test", states.get(test, "unknown"), f"test_{test}"))
        return checks

    # ------------------------------------------------------------------ background
    async def cycle(self) -> None:
        """Auto-apply to new services, then read a few finished build logs."""
        settings = self.get_settings()
        dokploy = self.dokploy()
        if not settings["enabled"] or dokploy is None:
            return
        state = self._read()
        known = set(state["known"])
        targets = await self.targets()
        applied = 0
        wanted = self.wanted()
        if settings["auto_apply_new"] and wanted:
            for target in targets:
                key = f"{target['type']}:{target['id']}"
                if key in known or applied >= AUTO_APPLY_BUDGET:
                    continue
                result = await self._change(target, "apply", wanted)
                known.add(key)
                if result["result"] == "applied":
                    applied += 1
                    await asyncio.to_thread(
                        self.ctx.audit, None, "build_mirror.auto_apply", MODULE_NAME, key,
                        "success")
        else:
            known |= {f"{t['type']}:{t['id']}" for t in targets}
        analyzed = await self._analyze(dokploy, state)

        def save(current: dict[str, Any]) -> None:
            current["known"] = sorted(set(current["known"]) | known)[-5000:]
            current["seen_deployments"] = state["seen_deployments"][-MAX_SEEN_DEPLOYMENTS:]
            current["coverage"] = OrderedDict(list(state["coverage"].items())[-MAX_COVERAGE:])

        await asyncio.to_thread(self._update_state, save)
        self.last_cycle = {"at": int(time.time()), "auto_applied": applied, "analyzed": analyzed}

    async def _analyze(self, dokploy: Any, state: dict[str, Any]) -> int:
        recent = await dokploy.recent_deployments()
        if not recent:
            return 0
        seen = set(state["seen_deployments"])
        urls = self.endpoints()
        done = 0
        for item in recent:
            if done >= LOG_BUDGET or not isinstance(item, dict):
                break
            deployment_id = str(item.get("deploymentId") or "")
            if (not _ID.fullmatch(deployment_id) or deployment_id in seen
                    or item.get("status") not in {"done", "error"}):
                continue
            service_type = "application" if item.get("applicationId") else "compose"
            service_id = str(item.get("applicationId") or item.get("composeId") or "")
            if not _ID.fullmatch(service_id):
                continue
            seen.add(deployment_id)
            state["seen_deployments"].append(deployment_id)
            try:
                log = await dokploy.deployment_log(deployment_id, LOG_TAIL)
            except Exception as exc:  # noqa: BLE001 - the next cycle reads newer ones
                LOGGER.info("build mirror: log unreadable",
                            extra={"error_code": getattr(exc, "code", type(exc).__name__)})
                continue
            done += 1
            if not log.get("available"):
                continue
            result = coverage.analyze(log.get("lines") or [], urls["npm"], urls["pypi"])
            key = f"{service_type}:{service_id}"
            state["coverage"].pop(key, None)
            state["coverage"][key] = {**result, "deployment_id": deployment_id,
                                      "at": int(time.time())}
        return done

    async def _loop(self) -> None:
        from .dokploy import _BACKGROUND

        _BACKGROUND.set(True)
        while True:
            interval = self.get_settings()["check_interval_seconds"]
            if interval > 0:
                try:
                    await self.cycle()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    LOGGER.info("build mirror cycle failed",
                                extra={"error_code": getattr(exc, "code", type(exc).__name__)})
            await asyncio.sleep(max(interval, 60) if interval > 0 else 300)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="mrk-build-mirror")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    # ------------------------------------------------------------------ report
    async def report(self) -> str:
        status = await self.status()
        lines = [f"DevAssist build mirrors report ({time.strftime('%Y-%m-%d %H:%M:%S')})",
                 f"overall: {status['overall']}"]
        urls = status["endpoints"]
        lines.append(f"npm: {urls['npm']}  pypi: {urls['pypi']}  registry: {urls['registry']}")
        for check in status["checks"]:
            params = ", ".join(f"{k}={v}" for k, v in check["params"].items())
            lines.append(f"[{check['state']}] {check['id']}: {check['code']}"
                         + (f" ({params})" if params else ""))
        facts = status["agent"]["facts"] or {}
        lines.append(f"docker: {facts.get('docker_version')}  builder: {facts.get('builder')}")
        try:
            view = await self.projects_view()
            for item in view["items"]:
                cover = item.get("coverage") or {}
                lines.append(
                    f"- {item['type']} {item['name']}: {item['state']}"
                    f" ({item.get('reason') or item.get('build_type') or '-'})"
                    f" coverage={cover.get('result', '-')} gaps={','.join(cover.get('gaps', []))}")
        except Exception as exc:  # noqa: BLE001
            lines.append(f"projects: {getattr(exc, 'code', type(exc).__name__)}")
        return "\n".join(lines) + "\n"


class SettingsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    npm: bool | None = None
    pypi: bool | None = None
    auto_apply_new: bool | None = None
    npm_url: str | None = Field(default=None, max_length=300)
    pypi_url: str | None = Field(default=None, max_length=300)
    registry_host: str | None = Field(default=None, max_length=260)
    check_interval_seconds: int | None = None


class TargetBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(pattern=r"^(application|compose)$")
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")


class ChangeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    all: bool = False
    targets: list[TargetBody] = Field(default_factory=list, max_length=500)


ACTIVE_SERVICE: BuildMirrorService | None = None


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = BuildMirrorService(ctx)
    ACTIVE_SERVICE = service
    router = APIRouter(prefix="/api/v1/build-mirrors", tags=["build-mirrors"])

    def failure(exc: Exception):
        code = getattr(exc, "code", None) or "build_mirror_failed"
        message = getattr(exc, "message", None) or "Build mirror request failed"
        status = getattr(exc, "status_code", None)
        return ctx.error_payload(code, message, status if isinstance(status, int) else 502)

    async def audit(principal: Any, action: str, object_id: str, result: str = "success"):
        await asyncio.to_thread(ctx.audit, principal.user_id, action, MODULE_NAME,
                                object_id[:255], result)

    @router.get("/status")
    async def get_status(request: Request):
        ctx.require_principal(request, "dokploy:read")
        return await service.status()

    @router.get("/settings")
    async def get_settings(request: Request):
        ctx.require_principal(request, "dokploy:read")
        return {**service.get_settings(), "endpoints": service.endpoints()}

    @router.put("/settings")
    async def put_settings(request: Request, body: SettingsBody):
        principal = ctx.require_principal(request, "dokploy:write")
        ctx.require_csrf(request, principal)
        payload = body.model_dump(exclude_none=True)
        try:
            result = await asyncio.to_thread(service.put_settings, payload, principal.user_id)
        except Exception as exc:  # noqa: BLE001 - mapped to a stable error code
            return failure(exc)
        await audit(principal, "build_mirror.settings", ",".join(sorted(payload)) or "-")
        return {**result, "endpoints": service.endpoints()}

    @router.get("/command")
    async def get_command(request: Request, action: str = "install", restart: bool = False):
        ctx.require_principal(request, "dokploy:read")
        try:
            return service.command(action, allow_restart=restart)
        except BuildMirrorError as exc:
            return failure(exc)

    @router.get("/projects")
    async def get_projects(request: Request):
        ctx.require_principal(request, "dokploy:read")
        try:
            return await service.projects_view()
        except Exception as exc:
            return failure(exc)

    async def change(request: Request, body: ChangeBody, mode: str):
        principal = ctx.require_principal(request, "dokploy:write")
        ctx.require_csrf(request, principal)
        if not body.all and not body.targets:
            return ctx.error_payload("validation_error", "choose services or all", 422)
        targets = None if body.all else [item.model_dump() for item in body.targets]
        try:
            result = await service.change(mode, targets)
        except Exception as exc:
            await audit(principal, f"build_mirror.{mode}", "all" if body.all else "some",
                        "failure")
            return failure(exc)
        outcome = "failure" if result["counts"].get("error") else "success"
        await audit(principal, f"build_mirror.{mode}",
                    "all" if body.all else ",".join(f"{t['type']}:{t['id']}"
                                                    for t in targets or []), outcome)
        return result

    @router.post("/projects/apply")
    async def apply_projects(request: Request, body: ChangeBody):
        return await change(request, body, "apply")

    @router.post("/projects/remove")
    async def remove_projects(request: Request, body: ChangeBody):
        return await change(request, body, "remove")

    @router.get("/report")
    async def get_report(request: Request):
        ctx.require_principal(request, "dokploy:read")
        return {"text": await service.report()}

    ctx.routers.append(router)
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)
