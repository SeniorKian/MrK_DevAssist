"""Background work of the DNS module for D2 (docs/38 §4).

While the engine is installed (its admin socket exists) one loop:

* every ``EVENTS_SECONDS`` reads ``GET /v1/events?after=<seq>`` and turns
  engine events into notification-centre events (``dns.pressure``,
  ``dns.attack_detected``, ``dns.mitigation_auto``, ``dns.logs_degraded`` /
  ``dns.logs_recovered``; D4, docs/40 §5: ``dns.dnssec_trust_anchor_failed``,
  ``dns.dnssec_bogus_spike``, ``dns.tls_certificate_expiring|expired``,
  ``dns.priming_failed``; final phase, docs/41 §6: ``dns.secondary_expired``,
  ``dns.transfer_failed``, ``dns.filter_list_failed``, ``dns.dnssec_signing_failed``,
  which also feed the home page's per-zone problems). The cursor lives in memory only; after a panel
  restart the first read just takes the current tail so old events are not
  replayed. An engine restart (its ``next`` going backwards) restarts at 0.
* every ``PRESSURE_SECONDS`` caches ``GET /v1/pressure`` for the home rules,
  so a home request never calls the engine.
* every ``HOST_METRICS_SECONDS`` pushes the newest Host Agent sample (CPU,
  memory, load) to ``POST /v1/host-metrics`` so the engine can include whole
  host load in its pressure level.

When the engine does not answer the loop backs off up to ``BACKOFF_MAX``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

from .. import dns_client
from ..dns_client import DnsClient, DnsError
from ..module_context import Event, ModuleContext

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "dns"
MONITOR_ENABLED = True  # tests switch the loop off and drive the steps directly
EVENTS_SECONDS = 5.0
PRESSURE_SECONDS = 10.0
HOST_METRICS_SECONDS = 10.0
BACKOFF_MAX = 60.0
PRESSURE_FRESH_SECONDS = 60.0
HOST_SAMPLE_MAX_AGE = 60.0
MAX_PUBLISH_PER_POLL = 20
DEDUPE_SECONDS = 300.0
LEVELS = ("normal", "warning", "critical", "emergency")
# Pressure level -> notification severity (docs/38 §4); "warning" is home-only.
LEVEL_SEVERITY = {"critical": "warning", "emergency": "error", "normal": "info"}
LEVEL_TITLES = {
    "critical": "Pishkar DNS is under heavy load",
    "emergency": "Pishkar DNS is overloaded and protecting itself",
    "normal": "Pishkar DNS load is back to normal",
}


# D4 engine event -> (notification type, severity, title, panel route), docs/40 §5.
D4_EVENTS: dict[str, tuple[str, str, str, str]] = {
    "dnssec.trust_anchor_failed": ("dns.dnssec_trust_anchor_failed", "error",
                                   "Pishkar DNS could not update the DNSSEC root key",
                                   "#/dns/settings"),
    "dnssec.bogus_spike": ("dns.dnssec_bogus_spike", "warning",
                           "Many DNS answers failed the DNSSEC check", "#/dns/monitor"),
    "tls.certificate_expiring": ("dns.tls_certificate_expiring", "warning",
                                 "The encrypted DNS certificate expires soon",
                                 "#/dns/encrypted"),
    "tls.certificate_expired": ("dns.tls_certificate_expired", "error",
                                "The encrypted DNS certificate has expired", "#/dns/encrypted"),
    "resolution.priming_failed": ("dns.priming_failed", "error",
                                  "Pishkar DNS cannot reach the root servers", "#/dns/settings"),
}


# Final-phase engine events (docs/41 §6). The engine names are not fixed by the contract,
# so a few spellings are accepted: event -> (notification, severity, title, kind).
D5_EVENTS: dict[str, tuple[str, str, str, str]] = {
    "zone.secondary_expired": ("dns.secondary_expired", "error",
                               "A secondary DNS zone has expired", "secondary"),
    "secondary.expired": ("dns.secondary_expired", "error",
                          "A secondary DNS zone has expired", "secondary"),
    "zone.transfer_failed": ("dns.transfer_failed", "warning",
                             "A DNS zone transfer failed", "transfer"),
    "secondary.refresh_failed": ("dns.transfer_failed", "warning",
                                 "A DNS zone transfer failed", "transfer"),
    "transfer.failed": ("dns.transfer_failed", "warning", "A DNS zone transfer failed",
                        "transfer"),
    "filtering.list_failed": ("dns.filter_list_failed", "warning",
                              "A DNS block list could not be updated", "filter"),
    "filter.list_failed": ("dns.filter_list_failed", "warning",
                           "A DNS block list could not be updated", "filter"),
    "zone.dnssec_signing_failed": ("dns.dnssec_signing_failed", "error",
                                   "Pishkar DNS could not sign a zone", "signing"),
    "dnssec.signing_failed": ("dns.dnssec_signing_failed", "error",
                              "Pishkar DNS could not sign a zone", "signing"),
    "zone.signing_failed": ("dns.dnssec_signing_failed", "error",
                            "Pishkar DNS could not sign a zone", "signing"),
}
# Events that end a per-zone problem on the home page (no notification).
D5_RECOVERY: dict[str, str] = {
    "zone.secondary_refreshed": "secondary", "secondary.refreshed": "secondary",
    "secondary.recovered": "secondary", "zone.transfer_succeeded": "secondary",
    "zone.transfer_recovered": "secondary",
    "dnssec.signing_recovered": "signing", "zone.signed": "signing",
    "dnssec.signed": "signing",
}


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: Any, limit: int = 255) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


def clean_reasons(raw: Any, limit: int = 5) -> list[dict[str, Any]]:
    reasons: list[dict[str, Any]] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get("metric"), str):
            continue
        reasons.append({
            "metric": item["metric"][:40],
            "value": item.get("value") if isinstance(item.get("value"), int | float) else None,
            "threshold": item.get("threshold")
            if isinstance(item.get("threshold"), int | float) else None,
        })
        if len(reasons) >= limit:
            break
    return reasons


def _reason_text(reasons: list[dict[str, Any]]) -> str:
    parts = []
    for item in reasons:
        if item["value"] is not None and item["threshold"] is not None:
            parts.append(f"{item['metric']} {item['value']:g} >= {item['threshold']:g}")
        else:
            parts.append(item["metric"])
    return ", ".join(parts)


class DnsMonitor:
    def __init__(
        self, ctx: ModuleContext, client: DnsClient,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ctx = ctx
        self.client = client
        self.clock = clock
        self.cursor: int | None = None
        self.pressure: dict[str, Any] | None = None
        self.pressure_at: float | None = None
        self.notified_level = "normal"
        self.failures = 0
        self.last_metrics_push: float | None = None
        self._recent: dict[str, float] = {}
        self._next: dict[str, float] = {"events": 0.0, "pressure": 0.0, "metrics": 0.0}
        self._task: asyncio.Task[None] | None = None
        # Set by DnsService: (kind, zone, problem | None) for the home page.
        self.zone_problem: Callable[[str, str, dict[str, Any] | None], None] | None = None

    # ------------------------------------------------------------------ pressure cache
    def cached_pressure(self) -> dict[str, Any] | None:
        if self.pressure is None or self.pressure_at is None:
            return None
        if self.clock() - self.pressure_at > PRESSURE_FRESH_SECONDS:
            return None
        return self.pressure

    def remember_pressure(self, payload: Any) -> None:
        if isinstance(payload, dict) and payload.get("level") in LEVELS:
            if self.pressure is None and payload["level"] in LEVEL_TITLES:
                # First look after a panel start: a later recovery still gets announced.
                self.notified_level = payload["level"]
            self.pressure = payload
            self.pressure_at = self.clock()

    async def refresh_pressure(self) -> dict[str, Any] | None:
        payload = await self.client.get("/v1/pressure", timeout=3.0)
        self.remember_pressure(payload)
        return self.cached_pressure()

    # ------------------------------------------------------------------ host metrics
    def host_sample(self) -> dict[str, Any] | None:
        from .home import find_service

        monitoring = find_service(self.ctx, "MonitoringService")
        if monitoring is None:
            return None
        try:
            latest = monitoring.latest_host()
        except Exception:  # noqa: BLE001 - monitoring trouble never breaks DNS
            LOGGER.debug("no host sample for the DNS engine", exc_info=True)
            return None
        if not isinstance(latest, dict) or not isinstance(latest.get("ts"), int | float):
            return None
        if self.clock() - float(latest["ts"]) > HOST_SAMPLE_MAX_AGE:
            return None
        cpu, memory = latest.get("cpu_percent"), latest.get("mem_percent")
        if cpu is None and memory is None:
            return None
        return {
            "cpu_percent": cpu,
            "memory_percent": memory,
            "load1": latest.get("load1"),
            "ts": int(float(latest["ts"]) * 1000),
        }

    async def push_host_metrics(self) -> bool:
        sample = self.host_sample()
        if sample is None:
            return False
        await self.client.request("POST", "/v1/host-metrics", sample, timeout=3.0)
        self.last_metrics_push = self.clock()
        return True

    # ------------------------------------------------------------------ events
    async def poll_events(self) -> int:
        """Read new engine events; returns how many notifications were published."""
        after = self.cursor if self.cursor is not None else 0
        payload = await self.client.get(f"/v1/events?after={after}", timeout=3.0)
        if not isinstance(payload, dict):
            return 0
        raw_items = payload.get("items")
        items = sorted(
            (item for item in (raw_items if isinstance(raw_items, list) else [])
             if isinstance(item, dict) and _int(item.get("seq")) is not None),
            key=lambda item: item["seq"],
        )
        next_seq = _int(payload.get("next"))
        newest = max([item["seq"] for item in items], default=None)
        if self.cursor is None:
            # Panel (re)start: begin at the current tail, never replay history.
            self.cursor = max(x for x in (next_seq, newest, 0) if x is not None)
            return 0
        if next_seq is not None and next_seq < self.cursor and not items:
            self.cursor = 0  # the engine restarted and its sequence began again
            return 0
        published = 0
        for item in items:
            if item["seq"] <= self.cursor:
                continue
            self.cursor = item["seq"]
            if published < MAX_PUBLISH_PER_POLL and self.publish(item):
                published += 1
        if next_seq is not None and next_seq > self.cursor:
            self.cursor = next_seq
        return published

    def _fresh_key(self, key: str) -> bool:
        now = time.monotonic()
        self._recent = {k: at for k, at in self._recent.items() if now - at < DEDUPE_SECONDS}
        if key in self._recent:
            return False
        self._recent[key] = now
        return True

    def publish(self, item: dict[str, Any]) -> bool:
        kind = item.get("type")
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        event: Event | None = None
        if kind == "pressure.level":
            event = self._pressure_event(data)
        elif kind == "attack.detected":
            parent = _text(data.get("parent")) or "?"
            if self._fresh_key(f"attack:{parent}"):
                count = data.get("unique_nxdomain_per_min")
                clients = data.get("top_clients")
                event = Event(
                    type="dns.attack_detected", severity="warning",
                    title="Possible DNS attack detected",
                    message=f"Many random names under {parent}"
                    + (f" ({count}/min)" if isinstance(count, int | float) else ""),
                    module=MODULE_NAME, dedupe_key=f"dns.attack.{parent}",
                    details={
                        "parent": parent,
                        "unique_nxdomain_per_min": count
                        if isinstance(count, int | float) else None,
                        "clients": len(clients) if isinstance(clients, list) else 0,
                        "mitigation_id": _text(data.get("mitigation_id"), 128),
                        "route": "#/dns/monitor",
                    },
                )
        elif kind == "mitigation.auto":
            match = _text(data.get("match")) or "?"
            mkind = _text(data.get("kind"), 16) or "?"
            if self._fresh_key(f"mitigation:{mkind}:{match}"):
                action = _text(data.get("action"), 16) or "?"
                event = Event(
                    type="dns.mitigation_auto", severity="warning",
                    title="Pishkar DNS limited a source automatically",
                    message=f"{action} {mkind} {match}",
                    module=MODULE_NAME, dedupe_key=f"dns.mitigation_auto.{mkind}.{match}",
                    details={
                        "id": _text(data.get("id"), 128), "kind": mkind, "match": match,
                        "action": action, "expires_at": data.get("expires_at"),
                        "reason": _text(data.get("reason"), 200), "route": "#/dns/monitor",
                    },
                )
        elif kind in {"querylog.degraded", "querylog.recovered"}:
            degraded = kind == "querylog.degraded"
            if self._fresh_key(kind):
                event = Event(
                    type="dns.logs_degraded" if degraded else "dns.logs_recovered",
                    severity="warning" if degraded else "info",
                    title="DNS query logging was reduced" if degraded
                    else "DNS query logging is back to normal",
                    message=_text(data.get("reason") or data.get("degraded_reason"), 300) or "",
                    module=MODULE_NAME,
                    dedupe_key="dns.logs_degraded" if degraded else "dns.logs_recovered",
                    details={"mode_effective": _text(data.get("mode_effective"), 32),
                             "reason": _text(data.get("reason")
                                             or data.get("degraded_reason"), 64),
                             "route": "#/dns/logs"},
                )
        elif kind in D4_EVENTS:
            event = self._d4_event(kind, data)
        elif kind in D5_EVENTS:
            event = self._d5_event(kind, data)
        elif kind in D5_RECOVERY:
            zone = _text(data.get("zone"), 253)
            if zone and self.zone_problem is not None:
                self.zone_problem(D5_RECOVERY[kind], zone, None)
        if event is None:
            return False
        self.ctx.events.publish(event)
        return True

    def _d4_event(self, kind: str, data: dict[str, Any]) -> Event | None:
        """docs/40 §5: DNSSEC, certificate and root-priming problems."""
        name, severity, title, route = D4_EVENTS[kind]
        details: dict[str, Any] = {"route": route}
        message = ""
        dedupe = name
        if kind == "dnssec.bogus_spike":
            count = data.get("count")
            names = [item[:253] for item in data.get("names") or []
                     if isinstance(item, str)][:10]
            details.update({"count": count if isinstance(count, int | float) else None,
                            "names": names})
            message = f"{count} answers failed the DNSSEC check" if isinstance(
                count, int | float) else ""
        elif kind == "tls.certificate_expiring":
            days = _int(data.get("days_left"))
            details["days_left"] = days
            message = f"{days} days left" if days is not None else ""
            dedupe = f"{name}.{days}"
        elif kind == "tls.certificate_expired":
            details["not_after"] = _text(data.get("not_after"), 40)
        else:  # trust anchor / priming failures
            error = _text(data.get("error"), 300)
            details["error"] = error
            message = error or ""
        if not self._fresh_key(dedupe):
            return None
        return Event(type=name, severity=severity, title=title, message=message,
                     module=MODULE_NAME, dedupe_key=dedupe, details=details)

    def _d5_event(self, kind: str, data: dict[str, Any]) -> Event | None:
        """docs/41 §6: secondary expiry, transfers, block lists, zone signing."""
        name, severity, title, group = D5_EVENTS[kind]
        error = _text(data.get("error") or data.get("reason"), 300)
        if group == "filter":
            subject = _text(data.get("list_id") or data.get("id"), 128) or "?"
            details: dict[str, Any] = {"list_id": subject,
                                       "name": _text(data.get("name"), 100),
                                       "error": error, "route": "#/dns/blocking"}
            message = f"{details['name'] or subject}: {error}" if error else subject
        else:
            subject = _text(data.get("zone"), 253) or "?"
            details = {"zone": subject, "error": error,
                       "route": f"#/dns/names?zone={subject}"}
            if group == "transfer":
                details["primary"] = _text(data.get("primary") or data.get("server"), 64)
            message = f"{subject}: {error}" if error else subject
            if self.zone_problem is not None and subject != "?" and group != "transfer":
                problem = {"error": error}
                if group == "secondary":
                    problem.update({"expired": True, "last_success": None})
                self.zone_problem("secondary" if group == "secondary" else "signing",
                                  subject, problem)
        dedupe = f"{name}.{subject}"
        if not self._fresh_key(dedupe):
            return None
        return Event(type=name, severity=severity, title=title, message=message or "",
                     module=MODULE_NAME, dedupe_key=dedupe, details=details)

    def _pressure_event(self, data: dict[str, Any]) -> Event | None:
        level = data.get("level") if data.get("level") in LEVELS else data.get("to")
        if level not in LEVELS:
            return None
        if level == "warning":
            return None  # shown on the home page only
        if level == "normal" and self.notified_level == "normal":
            return None
        if level == self.notified_level:
            return None
        previous = self.notified_level
        self.notified_level = level
        reasons = clean_reasons(data.get("reasons"))
        return Event(
            type="dns.pressure", severity=LEVEL_SEVERITY[level], title=LEVEL_TITLES[level],
            message=_reason_text(reasons), module=MODULE_NAME,
            dedupe_key=f"dns.pressure.{level}",
            details={"level": level, "previous": previous, "reasons": reasons,
                     "route": "#/dns/monitor"},
        )

    # ------------------------------------------------------------------ loop
    async def tick(self) -> float:
        """One round; returns how long to sleep before the next one."""
        if not dns_client.installed():
            self.failures = 0
            self.pressure = None
            return EVENTS_SECONDS
        now = time.monotonic()
        unreachable = False
        steps = (
            ("events", EVENTS_SECONDS, self.poll_events),
            ("pressure", PRESSURE_SECONDS, self.refresh_pressure),
            ("metrics", HOST_METRICS_SECONDS, self.push_host_metrics),
        )
        for name, every, step in steps:
            if now < self._next[name]:
                continue
            self._next[name] = now + every
            try:
                await step()
            except DnsError as exc:
                if exc.code in {"dns_unreachable", "dns_not_installed"}:
                    unreachable = True
                    break
                # An engine without this route (older version) or a refusal: try later.
                LOGGER.debug("dns monitor step %s failed: %s", name, exc.code)
        if unreachable:
            self.failures += 1
            delay = min(BACKOFF_MAX, EVENTS_SECONDS * (2 ** min(self.failures, 6)))
            for name in self._next:
                self._next[name] = 0.0
            return delay
        self.failures = 0
        return EVENTS_SECONDS

    async def _loop(self) -> None:
        while True:
            try:
                delay = await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("dns monitor loop failed")
                delay = BACKOFF_MAX
            await asyncio.sleep(delay)

    async def start(self) -> None:
        if MONITOR_ENABLED and self._task is None:
            self._task = asyncio.create_task(self._loop(), name="mrk-dns-monitor")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
