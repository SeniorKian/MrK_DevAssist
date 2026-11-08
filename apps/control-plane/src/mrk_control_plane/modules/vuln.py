"""Native image vulnerability scanning (Gate 19, S8; contract docs/32 §4).

Flow of one scan (daily by default, or ``POST /api/v1/vuln/scan``):

1. List containers through the host agent; keep running ones (``include_stopped``
   adds the rest) and pick one container per image id (dedupe per image).
2. Inventory: ``GET /v1/vuln/containers/{id}/package-files`` on the agent returns
   fixed package-database paths (dpkg, apk, rpm sqlite, os-release, npm/PyPI
   lockfiles); ``vuln_inventory`` parses them. Image ids are immutable, so the
   parsed inventory is cached per image id (7 days, or until a manual scan asks
   for ``refresh_inventory``).
3. Feeds: the OSV ecosystems the inventories need (+ ``ecosystems_extra``) are
   refreshed with conditional requests through ``outbound.py`` (provider kind
   ``vuln_feed``) into ``data_dir/modules/vuln/osv.sqlite``.
4. Matching with per-ecosystem version ordering (``vuln_versions``), results to
   ``data_dir/modules/vuln/results.sqlite``; ignore rules (database table
   ``vuln_ignores``) apply at read time and before notifications.
5. Events ``vuln.new_critical`` / ``vuln.new_high`` (and medium/low if selected),
   one per image and severity, deduplicated per image+advisory.

Settings and run state: ``data_dir/control-plane/vuln.json``.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from .. import outbound
from ..models import VulnIgnore
from ..module_context import Event, ModuleContext
from ..netresolve import resolve_host
from .host_agent import AgentError, HostAgentService
from .vuln_inventory import Inventory, build_inventory
from .vuln_osv import (
    SEVERITIES,
    SUPPORTED_FEEDS,
    FeedImportError,
    OsvStore,
    feed_for,
    feed_url,
    temp_download_path,
)
from .vuln_settings import (
    DEFAULT_SETTINGS,
    MAX_IGNORES,
    SettingsError,
    validate_ignore,
    validate_settings,
)
from .vuln_store import IgnoreRule, ResultStore, empty_counts, first_match, sort_findings
from .vuln_versions import evaluate

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "vuln"
STATE_FILE = "vuln.json"
PROVIDER_KIND = "vuln_feed"
PROVIDER_ENTRY = "osv"
LIVE_STATES = frozenset({"running", "restarting", "paused"})
STARTUP_DELAY_SECONDS = 120.0
RETRY_SECONDS = 1800.0
MAX_IDLE_SECONDS = 300.0
MAX_IMAGES = 300
INVENTORY_MAX_AGE = 7 * 86400.0
FEED_RECHECK_SECONDS = 3600.0
FEED_TIMEOUT_SECONDS = 60.0
AGENT_FILES_TIMEOUT = 180.0
AGENT_FILES_MAX_BYTES = 64 * 1024 * 1024
MAX_EVENT_IDS = 20
EVENT_SEVERITY = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}

# Tests replace these (httpx.MockTransport / a fixed resolver).
TRANSPORT_FACTORY: Callable[[], httpx.AsyncBaseTransport] | None = None
RESOLVER: outbound.Resolver | None = None

ACTIVE_SERVICE: VulnService | None = None


def _resolve(host: str, port: int, config: Any) -> list[str]:
    if RESOLVER is not None:
        return RESOLVER(host, port, config)
    return resolve_host(host, port, config)


def normalize_image_id(value: str) -> str:
    text = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return f"sha256:{text}"
    return text


def match_inventory(osv: OsvStore, inventory: Inventory) -> list[dict[str, Any]]:
    """Findings for one inventory: one per (advisory, matched package, version)."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for package in inventory.packages:
        group = groups.setdefault(
            (package.ecosystem, package.name, package.version),
            {"binaries": [], "location": package.location},
        )
        if package.binary and package.binary not in group["binaries"]:
            group["binaries"].append(package.binary)
    by_ecosystem: dict[str, list[str]] = {}
    for ecosystem, name, _version in groups:
        names = by_ecosystem.setdefault(ecosystem, [])
        if name not in names:
            names.append(name)
    findings: dict[tuple[str, str, str], dict[str, Any]] = {}
    for ecosystem, names in by_ecosystem.items():
        matches = osv.lookup(ecosystem, names)
        for (eco, name, version), group in groups.items():
            if eco != ecosystem:
                continue
            for match in matches.get(name, []):
                try:
                    hit, fixed = evaluate(match.entry, version, ecosystem)
                except Exception:  # noqa: BLE001 - one malformed record must not stop a scan
                    LOGGER.debug("osv evaluation failed", extra={"advisory": match.id})
                    continue
                if not hit:
                    continue
                key = (match.id, name, version)
                previous = findings.get(key)
                if previous is not None:
                    if fixed and not previous["fixed"]:
                        previous["fixed"] = fixed
                    continue
                findings[key] = {
                    "id": match.id,
                    "aliases": [a for a in match.aliases if a != match.id],
                    "package": name,
                    "binaries": sorted(group["binaries"]),
                    "installed": version,
                    "fixed": fixed,
                    "severity": match.severity,
                    "score": match.score,
                    "summary": match.summary,
                    "ecosystem": ecosystem,
                    "location": group["location"],
                }
    return sort_findings(list(findings.values()))


class VulnService:
    def __init__(
        self,
        ctx: ModuleContext,
        agent: Any = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ctx = ctx
        self.agent = agent or HostAgentService(ctx)
        self.clock = clock
        self.path = ctx.data_dir / "control-plane" / STATE_FILE
        self.base_dir = ctx.data_dir / "modules" / "vuln"
        self.osv = OsvStore(self.base_dir / "osv.sqlite")
        self.results = ResultStore(self.base_dir / "results.sqlite")
        self._lock = threading.Lock()
        self._run_lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._run_task: asyncio.Task[None] | None = None
        self._wake: asyncio.Event | None = None
        self.running = False
        self.phase: str | None = None
        self.state = self._load()

    # ----- persistence -----------------------------------------------------------------
    def _empty(self) -> dict[str, Any]:
        return {
            "settings": copy.deepcopy(DEFAULT_SETTINGS),
            "last_run_at": None,
            "last_attempt_at": None,
            "last_error": None,
            "needed_feeds": [],
        }

    def _load(self) -> dict[str, Any]:
        state = self._empty()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return state
        except (OSError, ValueError):
            LOGGER.warning("vuln state file is invalid; using defaults")
            return state
        if not isinstance(raw, dict):
            return state
        try:
            state["settings"] = validate_settings(raw.get("settings") or {})
        except SettingsError:
            LOGGER.warning("vuln settings are invalid; using defaults")
        for key in ("last_run_at", "last_attempt_at"):
            if isinstance(raw.get(key), int | float):
                state[key] = raw[key]
        if isinstance(raw.get("last_error"), str):
            state["last_error"] = raw["last_error"][:200]
        if isinstance(raw.get("needed_feeds"), list):
            state["needed_feeds"] = [f for f in raw["needed_feeds"] if f in SUPPORTED_FEEDS]
        return state

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{STATE_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps(self.state, indent=2) + "\n", encoding="utf-8")
        with contextlib.suppress(OSError):
            temporary.chmod(0o600)
        os.replace(temporary, self.path)

    @property
    def settings(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self.state["settings"])

    def save_settings(self, payload: Any) -> dict[str, Any]:
        with self._lock:
            value = validate_settings(
                payload, base=self.state["settings"], network=self.ctx.network_settings
            )
            self.state["settings"] = value
            self._save_locked()
        if self._wake is not None:
            self._wake.set()
        return copy.deepcopy(value)

    # ----- outbound provider ------------------------------------------------------------
    def outbound_entries(self) -> list[dict[str, Any]]:
        settings = self.settings
        return [
            {
                "id": PROVIDER_ENTRY,
                "name": "OSV vulnerability feeds",
                "group": "default",
                "proxy_id": settings["proxy_id"],
            }
        ]

    def set_proxy(self, entry_id: str, proxy_id: str | None) -> None:
        if entry_id != PROVIDER_ENTRY:
            raise KeyError(entry_id)
        with self._lock:
            settings = copy.deepcopy(self.state["settings"])
            settings["proxy_id"] = proxy_id
            self.state["settings"] = validate_settings(settings, base=DEFAULT_SETTINGS)
            self._save_locked()

    # ----- ignores (control-plane database) ------------------------------------------------
    def ignore_rules(self) -> list[dict[str, Any]]:
        now = self.clock()
        with self.ctx.database.session() as db:
            rows = db.scalars(select(VulnIgnore).order_by(VulnIgnore.created_at)).all()
            return [
                {
                    "id": row.id,
                    "advisory": row.advisory,
                    "package": row.package,
                    "image": row.image,
                    "reason": row.reason,
                    "expires_at": row.expires_at,
                    "created_at": row.created_at,
                    "created_by": row.created_by,
                    "expired": row.expires_at is not None and row.expires_at <= now,
                }
                for row in rows
            ]

    def active_rules(self) -> list[IgnoreRule]:
        return [
            IgnoreRule(r["id"], r["advisory"], r["package"], r["image"], r["reason"],
                       r["expires_at"])
            for r in self.ignore_rules()
            if not r["expired"]
        ]

    def add_ignore(self, payload: Any, user_id: int | None) -> dict[str, Any]:
        fields = validate_ignore(payload, self.clock())
        with self.ctx.database.session() as db, db.begin():
            count = len(db.scalars(select(VulnIgnore.id)).all())
            if count >= MAX_IGNORES:
                raise SettingsError(f"at most {MAX_IGNORES} ignore rules", "too_many_ignores")
            row = VulnIgnore(
                id=secrets.token_hex(8),
                created_at=int(self.clock()),
                created_by=user_id,
                **fields,
            )
            db.add(row)
            rule_id = row.id
        return next(rule for rule in self.ignore_rules() if rule["id"] == rule_id)

    def delete_ignore(self, rule_id: str) -> bool:
        with self.ctx.database.session() as db, db.begin():
            row = db.get(VulnIgnore, rule_id)
            if row is None:
                return False
            db.delete(row)
        return True

    # ----- agent ------------------------------------------------------------------------
    def agent_configured(self) -> bool:
        source, url, _key = self.agent.resolve()
        return source is not None and url is not None

    async def _containers(self, include_stopped: bool) -> dict[str, list[dict[str, Any]]]:
        payload = await self.agent.call("/v1/docker/containers")
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            raise AgentError("agent_unreachable", 502, "unexpected agent payload")
        by_image: dict[str, list[dict[str, Any]]] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            state = str(item.get("state") or "")
            if not include_stopped and state not in LIVE_STATES:
                continue
            image_id = item.get("image_id")
            container_id = str(item.get("id") or "")
            if not isinstance(image_id, str) or not re.fullmatch(r"[0-9a-f]{64}", container_id):
                continue
            by_image.setdefault(normalize_image_id(image_id), []).append(item)
        return by_image

    async def _digests(self) -> dict[str, str]:
        try:
            payload = await self.agent.call("/v1/docker/images")
        except AgentError:
            return {}
        items = payload.get("items") if isinstance(payload, dict) else None
        result: dict[str, str] = {}
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            digests = [d for d in item.get("repo_digests") or [] if isinstance(d, str)]
            if digests:
                result[normalize_image_id(item["id"])] = digests[0].rpartition("@")[2]
        return result

    async def _inventory(
        self, image_id: str, container: dict[str, Any], refresh: bool
    ) -> tuple[Inventory | None, float | None, list[str], bool]:
        """(inventory, fetched_at, errors, fresh) — cached inventory when allowed."""
        now = self.clock()
        cached = await asyncio.to_thread(self.results.cached_inventory, image_id)
        if cached is not None and not refresh and now - cached[1] < INVENTORY_MAX_AGE:
            return Inventory.from_public(cached[0]), cached[1], [], False
        try:
            payload = await self.agent.request(
                "GET",
                f"/v1/vuln/containers/{container['id']}/package-files",
                timeout=AGENT_FILES_TIMEOUT,
                max_bytes=AGENT_FILES_MAX_BYTES,
            )
        except AgentError as exc:
            if cached is not None:
                return Inventory.from_public(cached[0]), cached[1], [exc.code], False
            return None, None, [exc.code], False
        if not isinstance(payload, dict):
            return None, None, ["agent_unreachable"], False
        inventory = await asyncio.to_thread(build_inventory, payload)
        return inventory, now, [], True

    # ----- feeds ------------------------------------------------------------------------
    async def refresh_feeds(self, feeds: list[str], settings: dict[str, Any]) -> dict[str, str]:
        """Conditional download + import per feed. Returns {feed: error_code} for failures."""
        errors: dict[str, str] = {}
        known = await asyncio.to_thread(self.osv.feeds)
        due = [
            feed
            for feed in feeds
            if not (
                (info := known.get(feed))
                and info.get("updated_at")
                and info.get("url") == feed_url(settings["feed_base_url"], feed)
                and self.clock() - float(info.get("checked_at") or 0) < FEED_RECHECK_SECONDS
            )
        ]
        if not due:
            return errors
        try:
            async with outbound.outbound_client(
                self.ctx.network_settings,
                self.ctx.secret_store,
                settings["proxy_id"],
                timeout=FEED_TIMEOUT_SECONDS,
                transport=TRANSPORT_FACTORY() if TRANSPORT_FACTORY else None,
                resolver=_resolve,
            ) as client:
                for feed in due:
                    try:
                        await self._download(client, feed, known.get(feed) or {}, settings)
                    except (FeedImportError, outbound.OutboundError, httpx.HTTPError,
                            OSError) as exc:
                        code = (
                            exc.code if isinstance(exc, FeedImportError)
                            else outbound.error_code(exc)
                        )
                        errors[feed] = code
                        await asyncio.to_thread(
                            self.osv.mark, feed, status="error", error=code,
                            checked_at=self.clock(),
                        )
                        LOGGER.warning("vuln feed refresh failed",
                                       extra={"feed": feed, "error_code": code})
        except outbound.OutboundError as exc:
            for feed in due:
                errors[feed] = exc.code
                await asyncio.to_thread(
                    self.osv.mark, feed, status="error", error=exc.code, checked_at=self.clock()
                )
        return errors

    async def _download(
        self, client: Any, feed: str, info: dict[str, Any], settings: dict[str, Any]
    ) -> None:
        url = feed_url(settings["feed_base_url"], feed)
        headers = {"Accept": "application/zip", "User-Agent": "mrk-vuln-scanner/1"}
        if info.get("updated_at") and info.get("url") == url:
            if info.get("etag"):
                headers["If-None-Match"] = str(info["etag"])
            if info.get("last_modified"):
                headers["If-Modified-Since"] = str(info["last_modified"])
        cap = settings["feed_max_mb"] * 1024 * 1024
        response = await client.send("GET", url, headers=headers, stream=True)
        target: Path | None = None
        try:
            if response.status_code == 304:
                await asyncio.to_thread(
                    self.osv.mark, feed, checked_at=self.clock(), status="ok", error=None
                )
                return
            if response.status_code != 200:
                raise FeedImportError(f"http_{response.status_code}")
            length = response.headers.get("content-length")
            if length and length.isdigit() and int(length) > cap:
                raise FeedImportError("feed_too_large")
            target = temp_download_path(self.base_dir / "downloads")
            total = 0
            with target.open("wb") as handle:
                async for chunk in response.aiter_bytes(256 * 1024):
                    total += len(chunk)
                    if total > cap:
                        raise FeedImportError("feed_too_large")
                    handle.write(chunk)
            etag = response.headers.get("etag")
            modified = response.headers.get("last-modified")
        except BaseException:
            if target is not None:
                target.unlink(missing_ok=True)
            raise
        finally:
            await response.aclose()
        try:
            records = await asyncio.to_thread(
                self.osv.import_zip,
                feed,
                target,
                max_total_bytes=cap * 8,
                meta={"url": url, "etag": etag, "last_modified": modified,
                      "updated_at": self.clock(), "checked_at": self.clock()},
            )
        finally:
            target.unlink(missing_ok=True)
        LOGGER.info("vuln feed imported", extra={"feed": feed, "records": records})

    # ----- scan -------------------------------------------------------------------------
    async def run_scan(self, trigger: str = "manual", refresh_inventory: bool = False) -> dict:
        async with self._run_lock:
            self.running = True
            try:
                return await self._run(trigger, refresh_inventory)
            finally:
                self.running = False
                self.phase = None

    def _fail(self, code: str) -> dict[str, Any]:
        with self._lock:
            self.state["last_error"] = code
            self._save_locked()
        LOGGER.warning("vulnerability scan skipped", extra={"error_code": code})
        return {"ok": False, "error_code": code}

    async def _run(self, trigger: str, refresh_inventory: bool) -> dict[str, Any]:
        settings = self.settings
        started = self.clock()
        with self._lock:
            self.state["last_attempt_at"] = started
        self.phase = "inventory"
        try:
            by_image = await self._containers(settings["include_stopped"])
            digests = await self._digests()
        except AgentError as exc:
            return self._fail(exc.code)
        scanned: list[tuple[dict[str, Any], Inventory | None, list[str], float | None, bool]] = []
        for image_id in sorted(by_image)[:MAX_IMAGES]:
            containers = by_image[image_id]
            containers.sort(key=lambda c: (str(c.get("state")) not in LIVE_STATES, c.get("name")))
            inventory, fetched_at, errors, fresh = await self._inventory(
                image_id, containers[0], refresh_inventory
            )
            payload = {
                "image_id": image_id,
                "image": str(containers[0].get("image") or "")[:256],
                "digest": digests.get(image_id),
                "containers": [
                    {
                        "id": str(c.get("id"))[:64],
                        "name": str(c.get("name") or "")[:255],
                        "state": str(c.get("state") or "")[:32],
                        "protected": bool(c.get("protected")),
                    }
                    for c in containers
                ],
            }
            scanned.append((payload, inventory, errors, fetched_at, fresh))
        needed = sorted(
            {
                feed_for(ecosystem)
                for _p, inventory, _e, _f, _fresh in scanned
                if inventory is not None
                for ecosystem in inventory.ecosystems()
            }
            & set(SUPPORTED_FEEDS)
            | set(settings["ecosystems_extra"])
        )
        with self._lock:
            self.state["needed_feeds"] = needed
        self.phase = "feeds"
        feed_errors = await self.refresh_feeds(needed, settings)
        self.phase = "matching"
        ready = {feed for feed, info in (await asyncio.to_thread(self.osv.feeds)).items()
                 if info.get("updated_at")}
        images: list[tuple[dict[str, Any], dict[str, Any] | None, float | None]] = []
        findings: dict[str, list[dict[str, Any]]] = {}
        for payload, inventory, errors, fetched_at, fresh in scanned:
            image_errors = [{"code": code} for code in errors]
            if inventory is not None:
                image_feeds = {feed_for(e) for e in inventory.ecosystems()}
                for feed in sorted(image_feeds):
                    if feed not in SUPPORTED_FEEDS:
                        image_errors.append({"code": "ecosystem_unsupported", "feed": feed})
                    elif feed not in ready:
                        image_errors.append(
                            {"code": feed_errors.get(feed, "feed_unavailable"), "feed": feed}
                        )
                findings[payload["image_id"]] = await asyncio.to_thread(
                    match_inventory, self.osv, inventory
                )
            payload.update(
                os=inventory.os if inventory else None,
                packages_scanned=len(inventory.packages) if inventory else 0,
                ecosystems=sorted(inventory.ecosystems()) if inventory else [],
                notes=inventory.notes if inventory else [],
                inventory_at=fetched_at,
                scanned_at=self.clock() if inventory is not None else None,
                errors=image_errors,
            )
            images.append(
                (payload, inventory.public() if inventory is not None and fresh else None,
                 fetched_at if fresh else None)
            )
        await asyncio.to_thread(self.results.save_scan, images, findings, self.clock())
        events = await asyncio.to_thread(self._new_events, images, findings, settings)
        for event in events:
            self.ctx.events.publish(event)
        with self._lock:
            self.state.update(last_run_at=started, last_error=None)
            self._save_locked()
        LOGGER.info(
            "vulnerability scan finished",
            extra={"trigger": trigger, "images": len(images), "events": len(events)},
        )
        return {"ok": True, "images": len(images), "feed_errors": feed_errors}

    def _new_events(
        self,
        images: list[tuple[dict[str, Any], Any, Any]],
        findings: dict[str, list[dict[str, Any]]],
        settings: dict[str, Any],
    ) -> list[Event]:
        levels = settings["severities_to_notify"]
        if not levels:
            return []
        rules = self.active_rules()
        seen = self.results.notified()
        events: list[Event] = []
        marked: list[tuple[str, str]] = []
        for payload, _inventory, _at in images:
            image_id = payload["image_id"]
            fresh: dict[str, list[dict[str, Any]]] = {}
            for finding in findings.get(image_id, []):
                if finding["severity"] not in levels:
                    continue
                if (image_id, finding["id"]) in seen or first_match(
                    rules, finding, payload["image"]
                ):
                    continue
                if any(item["id"] == finding["id"] for item in fresh.get(finding["severity"], [])):
                    continue
                fresh.setdefault(finding["severity"], []).append(finding)
            for severity in levels:
                items = fresh.get(severity)
                if not items:
                    continue
                ids = sorted({item["id"] for item in items})
                marked.extend((image_id, advisory) for advisory in ids)
                events.append(self._event(payload, severity, items, ids))
        self.results.mark_notified(marked, self.clock())
        return events

    @staticmethod
    def _event(
        payload: dict[str, Any], severity: str, items: list[dict[str, Any]], ids: list[str]
    ) -> Event:
        image = payload["image"] or payload["image_id"]
        containers = [c["name"] for c in payload["containers"]]
        shown = ", ".join(
            f"{item['id']} ({item['package']} {item['installed']}"
            + (f" -> {item['fixed']}" if item.get("fixed") else "")
            + ")"
            for item in items[:MAX_EVENT_IDS]
        )
        more = len(items) - MAX_EVENT_IDS
        digest = hashlib.sha256("|".join(ids).encode()).hexdigest()[:16]
        return Event(
            type=f"vuln.new_{severity}",
            severity=EVENT_SEVERITY[severity],
            title=f"{len(ids)} new {severity} vulnerabilit{'y' if len(ids) == 1 else 'ies'} "
            f"in {image}",
            message=shown + (f" and {more} more" if more > 0 else "")
            + f". Containers: {', '.join(containers) or '-'}.",
            module=MODULE_NAME,
            dedupe_key=f"vuln.new_{severity}:{payload['image_id']}:{digest}",
            details={
                "image": payload["image"],
                "image_id": payload["image_id"],
                "severity": severity,
                "advisories": ids[:100],
                "containers": containers,
            },
        )

    # ----- views ------------------------------------------------------------------------
    def next_run_at(self) -> float | None:
        with self._lock:
            settings = self.state["settings"]
            last_run, last_attempt = self.state["last_run_at"], self.state["last_attempt_at"]
            failed = self.state["last_error"] is not None
        if not settings["enabled"]:
            return None
        if failed and last_attempt is not None:
            return last_attempt + RETRY_SECONDS
        if last_run is None:
            return 0.0
        return last_run + settings["interval_hours"] * 3600

    @staticmethod
    def _status(counts: dict[str, int], payload: dict[str, Any]) -> str:
        if counts["critical"]:
            return "critical"
        if counts["high"] or counts["medium"]:
            return "warning"
        if payload.get("scanned_at") is None or any(
            error.get("code") != "ecosystem_unsupported" for error in payload.get("errors") or []
        ):
            return "error"
        if not payload.get("packages_scanned"):
            return "unsupported"
        return "secure"

    def _annotated(
        self, rules: list[IgnoreRule], payload: dict[str, Any], items: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, int], int]:
        counts = empty_counts()
        ignored = 0
        for item in items:
            rule = first_match(rules, item, payload.get("image"))
            item["ignored"] = rule is not None
            item["ignore_id"] = rule.id if rule else None
            if rule is None:
                counts[item["severity"] if item["severity"] in counts else "unknown"] += 1
            else:
                ignored += 1
        return items, counts, ignored

    def _image_view(
        self, payload: dict[str, Any], counts: dict[str, int], ignored: int, fixable: int
    ) -> dict[str, Any]:
        view = dict(payload)
        view.update(counts=counts, ignored=ignored, fixable=fixable,
                    status=self._status(counts, payload))
        return view

    def images_view(self) -> dict[str, Any]:
        rules = self.active_rules()
        all_findings = self.results.findings()
        items = []
        for payload in self.results.images():
            annotated, counts, ignored = self._annotated(
                rules, payload, all_findings.get(payload["image_id"], [])
            )
            fixable = sum(1 for f in annotated if not f["ignored"] and f["fixed"])
            items.append(self._image_view(payload, counts, ignored, fixable))
        order = {"critical": 0, "warning": 1, "error": 2, "secure": 3, "unsupported": 4}
        items.sort(key=lambda i: (order.get(i["status"], 9), -i["counts"]["critical"],
                                  -i["counts"]["high"], i["image"]))
        return {"items": items, **self._run_info()}

    def _run_info(self) -> dict[str, Any]:
        with self._lock:
            state = copy.deepcopy(self.state)
        return {
            "running": self.running,
            "phase": self.phase,
            "last_run_at": state["last_run_at"],
            "last_attempt_at": state["last_attempt_at"],
            "last_error": state["last_error"],
            "next_run_at": self.next_run_at(),
        }

    def summary_view(self) -> dict[str, Any]:
        images = self.images_view()["items"]
        counts = empty_counts()
        statuses = dict.fromkeys(("critical", "warning", "secure", "error", "unsupported"), 0)
        for item in images:
            for severity in SEVERITIES:
                counts[severity] += item["counts"][severity]
            statuses[item["status"]] = statuses.get(item["status"], 0) + 1
        feeds = self.feeds_view()["items"]
        return {
            "enabled": self.settings["enabled"],
            "agent_configured": self.agent_configured(),
            "images": len(images),
            "counts": counts,
            "fixable": sum(item["fixable"] for item in images),
            "ignored": sum(item["ignored"] for item in images),
            "images_by_status": statuses,
            "feeds_ready": bool(feeds) and all(f["updated_at"] for f in feeds if f["needed"]),
            **self._run_info(),
        }

    def findings_view(
        self,
        image_id: str,
        severities: list[str] | None,
        query: str | None,
        include_ignored: bool,
        limit: int,
        offset: int,
    ) -> dict[str, Any] | None:
        image_id = normalize_image_id(image_id)
        payload = self.results.image(image_id)
        if payload is None:
            return None
        rules = self.active_rules()
        annotated, counts, ignored = self._annotated(
            rules, payload, self.results.findings(image_id).get(image_id, [])
        )
        fixable = sum(1 for f in annotated if not f["ignored"] and f["fixed"])
        items = sort_findings(annotated)
        if severities:
            items = [f for f in items if f["severity"] in severities]
        if not include_ignored:
            items = [f for f in items if not f["ignored"]]
        if query:
            needle = query.lower()
            items = [
                f for f in items
                if needle in f["id"].lower()
                or needle in f["package"].lower()
                or any(needle in alias.lower() for alias in f["aliases"])
                or any(needle in name.lower() for name in f["binaries"])
                or needle in (f["summary"] or "").lower()
            ]
        return {
            "image": self._image_view(payload, counts, ignored, fixable),
            "total": len(items),
            "items": items[offset : offset + limit],
        }

    def feeds_view(self) -> dict[str, Any]:
        settings = self.settings
        with self._lock:
            needed = set(self.state["needed_feeds"]) | set(settings["ecosystems_extra"])
        known = self.osv.feeds()
        items = []
        for feed in sorted(set(known) | needed):
            info = known.get(feed) or {}
            items.append(
                {
                    "ecosystem": feed,
                    "needed": feed in needed,
                    "url": info.get("url") or feed_url(settings["feed_base_url"], feed),
                    "updated_at": info.get("updated_at"),
                    "checked_at": info.get("checked_at"),
                    "records": info.get("records") or 0,
                    "size": info.get("size") or 0,
                    "status": info.get("status") or "pending",
                    "error": info.get("error"),
                }
            )
        return {
            "items": items,
            "feed_base_url": settings["feed_base_url"],
            "supported": list(SUPPORTED_FEEDS),
        }

    # ----- background --------------------------------------------------------------------
    def trigger(self, refresh_inventory: bool = False) -> bool:
        if self.running or (self._run_task is not None and not self._run_task.done()):
            return False
        self.running = True
        self._run_task = asyncio.create_task(
            self._guarded("manual", refresh_inventory), name="mrk-vuln-scan"
        )
        return True

    async def _guarded(self, trigger: str, refresh_inventory: bool = False) -> None:
        try:
            await self.run_scan(trigger, refresh_inventory)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.running = False
            LOGGER.exception("vulnerability scan failed")
            with contextlib.suppress(Exception):
                self._fail("scan_failed")

    async def _loop(self) -> None:
        assert self._wake is not None
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._wake.wait(), STARTUP_DELAY_SECONDS)
        while True:
            self._wake.clear()
            due = self.next_run_at()
            delay = MAX_IDLE_SECONDS if due is None else due - self.clock()
            if due is not None and delay <= 0 and not self.running:
                if self.agent_configured():
                    await self._guarded("schedule")
                else:
                    with self._lock:
                        self.state["last_attempt_at"] = self.clock()
                        self.state["last_error"] = (
                            self.state["last_error"] or "agent_not_configured"
                        )
                await asyncio.sleep(1.0)
                continue
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), min(max(delay, 1.0), MAX_IDLE_SECONDS))

    async def start(self) -> None:
        self._wake = asyncio.Event()
        self._task = asyncio.create_task(self._loop(), name="mrk-vuln-scheduler")

    async def stop(self) -> None:
        for task in (self._task, self._run_task):
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        self._task = self._run_task = None


async def _json(request: Request) -> Any:
    raw = await request.body()
    if not raw.strip():
        return {}
    return json.loads(raw)


def build_router(ctx: ModuleContext, service: VulnService) -> APIRouter:
    router = APIRouter(prefix="/api/v1/vuln", tags=["vuln"])

    async def audit(principal: Any, action: str, object_id: str, result: str = "success"):
        await asyncio.to_thread(
            ctx.audit, principal.user_id, action, "vuln", object_id, result
        )

    def invalid_json() -> JSONResponse:
        return ctx.error_payload("invalid_json", "request body must be JSON", 422)

    @router.get("/summary")
    async def summary(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "vuln:read")
        return await asyncio.to_thread(service.summary_view)

    @router.get("/images")
    async def images(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "vuln:read")
        return await asyncio.to_thread(service.images_view)

    @router.get("/images/{image_id}/findings", response_model=None)
    async def findings(request: Request, image_id: str) -> dict[str, Any] | JSONResponse:
        ctx.require_principal(request, "vuln:read")
        params = request.query_params
        severity = params.get("severity")
        severities = [s for s in (severity or "").split(",") if s] or None
        if severities and any(s not in SEVERITIES for s in severities):
            return ctx.error_payload(
                "invalid_query", f"severity must be among {', '.join(SEVERITIES)}", 422
            )
        try:
            limit = min(max(int(params.get("limit", "500")), 1), 5000)
            offset = max(int(params.get("offset", "0")), 0)
        except ValueError:
            return ctx.error_payload("invalid_query", "limit/offset must be integers", 422)
        query = (params.get("q") or "").strip()[:200] or None
        include_ignored = params.get("include_ignored", "1") not in {"0", "false"}
        view = await asyncio.to_thread(
            service.findings_view, image_id, severities, query, include_ignored, limit, offset
        )
        if view is None:
            return ctx.error_payload("image_not_found", "No scan result for that image", 404)
        return view

    @router.post("/scan", status_code=202, response_model=None)
    async def scan(request: Request) -> dict[str, Any] | JSONResponse:
        principal = ctx.require_principal(request, "vuln:write")
        ctx.require_csrf(request, principal)
        try:
            body = await _json(request)
        except (ValueError, UnicodeDecodeError):
            return invalid_json()
        if not isinstance(body, dict) or set(body) - {"refresh_inventory"} or not isinstance(
            body.get("refresh_inventory", False), bool
        ):
            return ctx.error_payload("invalid_body", "body: {refresh_inventory?: bool}", 422)
        if not await asyncio.to_thread(service.agent_configured):
            return ctx.error_payload(
                "agent_not_configured", "The host agent is not configured", 409
            )
        started = service.trigger(bool(body.get("refresh_inventory", False)))
        await audit(principal, "vuln.scan", "images")
        return {"started": started, "running": True}

    @router.get("/settings")
    async def get_settings(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "vuln:read")
        return service.settings

    @router.put("/settings", response_model=None)
    async def put_settings(request: Request) -> dict[str, Any] | JSONResponse:
        principal = ctx.require_principal(request, "vuln:write")
        ctx.require_csrf(request, principal)
        try:
            payload = await _json(request)
        except (ValueError, UnicodeDecodeError):
            return invalid_json()
        try:
            value = await asyncio.to_thread(service.save_settings, payload)
        except SettingsError as exc:
            await audit(principal, "vuln.settings.update", "settings", "failure")
            return ctx.error_payload(exc.code, exc.message, 422)
        await audit(principal, "vuln.settings.update", "settings")
        return value

    @router.get("/ignores")
    async def list_ignores(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "vuln:read")
        return {"items": await asyncio.to_thread(service.ignore_rules)}

    @router.post("/ignores", status_code=201, response_model=None)
    async def add_ignore(request: Request) -> dict[str, Any] | JSONResponse:
        principal = ctx.require_principal(request, "vuln:write")
        ctx.require_csrf(request, principal)
        try:
            payload = await _json(request)
        except (ValueError, UnicodeDecodeError):
            return invalid_json()
        try:
            rule = await asyncio.to_thread(service.add_ignore, payload, principal.user_id)
        except SettingsError as exc:
            await audit(principal, "vuln.ignore.create", "ignore", "failure")
            return ctx.error_payload(exc.code, exc.message, 422)
        await audit(principal, "vuln.ignore.create", rule["id"])
        return rule

    @router.delete("/ignores/{rule_id}", response_model=None)
    async def delete_ignore(request: Request, rule_id: str) -> dict[str, Any] | JSONResponse:
        principal = ctx.require_principal(request, "vuln:write")
        ctx.require_csrf(request, principal)
        if not re.fullmatch(r"[0-9a-f]{1,32}", rule_id):
            return ctx.error_payload("ignore_not_found", "Unknown ignore rule", 404)
        if not await asyncio.to_thread(service.delete_ignore, rule_id):
            return ctx.error_payload("ignore_not_found", "Unknown ignore rule", 404)
        await audit(principal, "vuln.ignore.delete", rule_id)
        return {"deleted": True}

    @router.get("/feeds")
    async def feeds(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "vuln:read")
        return await asyncio.to_thread(service.feeds_view)

    return router


def register_outbound(ctx: ModuleContext, service: VulnService) -> None:
    """Feed downloads appear in the central "service -> proxy" table."""
    outbound.outbound_registry(ctx.data_dir).register(
        outbound.OutboundProvider(
            kind=PROVIDER_KIND,
            list_entries=service.outbound_entries,
            supported_types=lambda _entry: outbound.ALL_PROXY_TYPES,
            set_proxy=service.set_proxy,
            read_permission="vuln:read",
            write_permission="vuln:write",
        )
    )


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = VulnService(ctx)
    ACTIVE_SERVICE = service
    ctx.routers.append(build_router(ctx, service))
    register_outbound(ctx, service)
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)
