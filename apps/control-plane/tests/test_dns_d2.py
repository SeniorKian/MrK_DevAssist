"""MRK DNS D2 panel side (docs/38 §4): query log, SSE, export, stats, pressure,
mitigations, background loops, notifications, home rules and settings validation."""

from __future__ import annotations

import asyncio
import copy
import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.testclient import TestClient
from mrk_control_plane import dns_client
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import (
    dns,
    dns_filters,
    dns_logs,
    dns_monitor,
    dns_validate,
    home,
    monitoring,
)

from .helpers import login_owner
from .test_dns import TOKEN, FakeEngine, role_client
from .test_dns import isolated as isolated  # noqa: F401 - fixture re-export

NOW_MS = int(time.time() * 1000)


def entry(index: int, **changes: Any) -> dict[str, Any]:
    item = {"ts": NOW_MS - index * 1000, "client": f"10.0.0.{index % 250 + 1}", "proto": "udp",
            "name": f"host{index}.example.com", "qtype": "A", "rcode": "NOERROR",
            "source": "cache", "ms": 1, "size": 60,
            "flags": {"tc": False, "stale": False, "cached": True}}
    item.update(changes)
    return item


class TailStream(httpx.AsyncByteStream):
    """An endless engine NDJSON tail (the ASGI test transport buffers whole bodies)."""

    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self.closed = False
        self.sent = 0

    async def __aiter__(self):
        yield b'{"type":"hello"}\n'
        while True:
            if self.quiet:
                await asyncio.sleep(3600)
            self.sent += 1
            yield (json.dumps({"type": "entry", **entry(self.sent)}) + "\n").encode()
            await asyncio.sleep(0.01)

    async def aclose(self) -> None:
        self.closed = True


class D2Engine(FakeEngine):
    def __init__(self) -> None:
        super().__init__()
        self.settings.update({
            "querylog": {"enabled": True, "mode": "all", "sample_percent": 100,
                         "max_age_days": 7, "max_bytes": 2147483648,
                         "min_free_disk_percent": 10, "client_ip": "full",
                         "exclude_names": [], "exclude_clients": [], "stream_max_eps": 200},
            "stats": {"minute_retention_hours": 48, "hour_retention_days": 90,
                      "day_retention_days": 400, "top_k": 100},
            "pressure": {
                "enabled": True, "capacity_qps": 50000, "dwell_seconds": 30,
                "thresholds": {
                    "warning": {"cpu": 70, "memory": 75, "qps_percent": 70, "host_cpu": 85,
                                "host_memory": 90},
                    "critical": {"cpu": 85, "memory": 85, "qps_percent": 90, "host_cpu": 92,
                                 "host_memory": 95},
                    "emergency": {"cpu": 95, "memory": 95, "qps_percent": 110, "host_cpu": 97,
                                  "host_memory": 98}},
                "exit_margin_percent": 10,
                "actions": {"log_sampling": True, "disable_prefetch": True,
                            "prefer_stale": True, "tighten_client_qps": True,
                            "refuse_heavy_clients": True, "minimal_any": True},
                "attack_detection": {"mode": "suggest", "nxdomain_unique_per_minute": 500,
                                     "mitigation_minutes": 30}},
        })
        self.events: list[dict[str, Any]] = []
        self.host_metrics: list[dict[str, Any]] = []
        self.mitigations: list[dict[str, Any]] = []
        self.deleted: list[Any] = []
        self.tail: TailStream | None = None
        self.pressure: dict[str, Any] = {
            "level": "normal", "since": NOW_MS, "reasons": [],
            "metrics": {"cpu_percent": 3, "memory_percent": 10, "qps": 5, "qps_percent": 0.01,
                        "inflight_upstream": 0, "drops_1m": 0},
            "active_actions": [],
            "hot": {"domains": [{"name": "a.example.com", "qps": 9}],
                    "clients": [{"client": "10.0.0.9", "qps": 9}], "attacks": []},
        }
        self._d2_routes()

    def add_event(self, kind: str, data: dict[str, Any], severity: str = "warning") -> None:
        seq = (self.events[-1]["seq"] if self.events else 0) + 1
        self.events.append({"seq": seq, "ts": NOW_MS, "type": kind, "severity": severity,
                            "data": data})

    def _d2_routes(self) -> None:
        app = self.app
        engine = self

        @app.get("/v1/querylog")
        async def querylog(request: Request):
            return {"items": [entry(1), entry(2, rcode="NXDOMAIN")], "next_cursor": "c-2",
                    "scanned_segments": 1, "truncated": False,
                    "query": dict(request.query_params)}

        @app.get("/v1/querylog/status")
        async def querylog_status():
            return {"enabled": True, "mode": "all", "mode_effective": "all", "bytes": 1024,
                    "segments": 2, "oldest_ts": NOW_MS - 60000, "written_total": 10,
                    "dropped_total": 0, "disk_free_percent": 80}

        @app.get("/v1/querylog/stream")
        async def querylog_stream(request: Request):
            if request.query_params.get("client") == "10.9.9.9":
                return JSONResponse(status_code=400, content={"error": {
                    "code": "invalid_filter", "message": "bad"}})

            async def body():
                yield b'{"type":"hello"}\n'
                yield (json.dumps({"type": "entry", **entry(1)}) + "\n").encode()
                yield b"not json\n"
                yield b'{"type":"unknown"}\n'
                yield b'{"type":"sampled","skipped":7}\n'
                yield b'{"type":"ping"}\n'

            return StreamingResponse(body(), media_type="application/x-ndjson")

        @app.get("/v1/querylog/export")
        async def querylog_export(request: Request):
            fmt = request.query_params.get("format")

            async def body():
                if fmt == "csv":
                    yield b"ts,client,name\n"
                    for index in range(3):
                        yield f"{NOW_MS},10.0.0.{index},h{index}.example.com\n".encode()
                else:
                    for index in range(3):
                        yield (json.dumps(entry(index)) + "\n").encode()

            return StreamingResponse(body(), media_type="text/plain")

        @app.delete("/v1/querylog")
        async def querylog_delete(request: Request):
            body = await request.body()
            engine.deleted.append(json.loads(body) if body else None)
            return {"deleted_segments": 2, "rewritten_segments": 1, "deleted_rows": 40}

        @app.get("/v1/stats")
        async def stats(request: Request):
            return {"range": request.query_params.get("range"), "resolution_seconds": 60,
                    "points": [{"ts": NOW_MS, "queries": 10, "qps": 0.2, "p50_ms": 1,
                                "p95_ms": 3, "p99_ms": 9, "cache_hit_ratio": 0.5,
                                "by_rcode": {"NOERROR": 9, "NXDOMAIN": 1}, "by_source": {}}],
                    "totals": {"queries": 10, "by_rcode": {}, "by_source": {}, "by_qtype": {}},
                    "top": {"domains": [{"name": "a.example.com", "count": 5}],
                            "clients": [{"client": "10.0.0.1", "count": 5}],
                            "nxdomain": [{"name": "x.example.com", "count": 1}],
                            "refused_clients": []}}

        @app.get("/v1/pressure")
        async def pressure():
            return engine.pressure

        @app.post("/v1/host-metrics")
        async def host_metrics(request: Request):
            engine.host_metrics.append(await request.json())
            return {"ok": True}

        @app.get("/v1/events")
        async def events(request: Request):
            after = int(request.query_params.get("after", "0"))
            items = [item for item in engine.events if item["seq"] > after]
            return {"items": items,
                    "next": engine.events[-1]["seq"] if engine.events else 0}

        @app.get("/v1/mitigations")
        async def mitigations():
            return {"items": engine.mitigations}

        @app.post("/v1/mitigations")
        async def create_mitigation(request: Request):
            body = await request.json()
            item = {"id": engine._id(), "qps": None, "reason": "", "created_at": NOW_MS,
                    "expires_at": NOW_MS + body["minutes"] * 60000, "source": "user",
                    "hits": 0, **body}
            engine.mitigations.append(item)
            return JSONResponse(status_code=201, content=item)

        @app.delete("/v1/mitigations/{mid}")
        async def delete_mitigation(mid: str):
            before = len(engine.mitigations)
            engine.mitigations = [item for item in engine.mitigations if item["id"] != mid]
            if len(engine.mitigations) == before:
                return JSONResponse(status_code=404, content={"error": {
                    "code": "mitigation_not_found", "message": "no"}})
            return {"ok": True}

    def transport(self, socket: str) -> httpx.AsyncBaseTransport:
        inner = super().transport(socket)
        engine = self

        class Router(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                if engine.tail is not None and request.url.path == "/v1/querylog/stream":
                    return httpx.Response(200, headers={"content-type": "application/x-ndjson"},
                                          stream=engine.tail, request=request)
                return await inner.handle_async_request(request)

        return Router()


@pytest.fixture
def engine(monkeypatch, isolated) -> D2Engine:  # noqa: F811
    socket, token = isolated
    socket.parent.mkdir(parents=True, exist_ok=True)
    socket.write_bytes(b"")
    token.write_text(TOKEN + "\n", encoding="utf-8")
    fake = D2Engine()
    monkeypatch.setattr(dns_client, "TRANSPORT_FACTORY", fake.transport)
    return fake


@pytest.fixture(autouse=True)
def fresh_slots(monkeypatch):
    monkeypatch.setattr(dns_monitor, "MONITOR_ENABLED", False)
    monkeypatch.setattr(dns_logs, "STREAM_SLOTS", dns_logs.Slots(3, 20))
    monkeypatch.setattr(dns_logs, "EXPORT_SLOTS", dns_logs.Slots(1, 3))


@pytest.fixture
def app_client(tmp_path: Path):
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        events: list[Any] = []

        async def collect(event) -> None:
            events.append(event)

        app.state.events.subscribe(collect)
        yield client, headers, events


def monitor() -> dns_monitor.DnsMonitor:
    assert dns.ACTIVE_SERVICE is not None
    return dns.ACTIVE_SERVICE.monitor


def audit_text(client: TestClient) -> str:
    response = client.get("/api/v1/audit-events?limit=200")
    assert response.status_code == 200, response.text
    return response.text


def settle(client: TestClient) -> None:
    """Let event handlers scheduled on the app loop run."""
    client.portal.call(asyncio.sleep, 0.05)


# ----------------------------------------------------------------------------- query log


def test_log_search_forwards_canonical_filters(app_client, engine) -> None:
    client, _headers, _events = app_client
    response = client.get("/api/v1/dns/logs", params={
        "from": "2026-11-08T10:00:00Z", "to": str(NOW_MS), "client": "10.0.0.7/24",
        "name": "*.Example.COM.", "qtype": "aaaa", "rcode": "nxdomain", "source": "UPSTREAM",
        "blocked": "1", "min_ms": "5", "cursor": "c-1"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["next_cursor"] == "c-2" and len(body["items"]) == 2
    assert body["query"] == {
        "from": "1794132000000", "to": str(NOW_MS), "client": "10.0.0.0/24",
        "name": "*.example.com", "qtype": "AAAA", "rcode": "NXDOMAIN", "source": "upstream",
        "blocked": "true", "min_ms": "5", "limit": "100", "cursor": "c-1"}


def test_log_filter_validation(app_client, engine) -> None:
    client, _headers, _events = app_client
    cases = {
        "limit=1001": "limit", "limit=0": "limit", "client=nope": "client",
        "client=10.0.0.1/99": "client", "name=a%20b": "name", "name=a*b": "name",
        "qtype=BOGUS": "qtype", "rcode=OOPS": "rcode", "source=elsewhere": "source",
        "blocked=maybe": "blocked", "min_ms=-1": "min_ms", "from=yesterday": "from",
        "from=1": "from", "cursor=%3Cx%3E": "cursor", "evil=1": "evil",
        "client=1.1.1.1&client=2.2.2.2": "client",
    }
    for query, field in cases.items():
        response = client.get(f"/api/v1/dns/logs?{query}")
        assert response.status_code == 422, query
        error = response.json()["error"]
        assert error["code"] == "dns_query_invalid", query
        assert error["fields"][0]["field"] == field, (query, error["fields"])
    late = client.get(f"/api/v1/dns/logs?from={NOW_MS}&to={NOW_MS - 1000}")
    assert late.json()["error"]["fields"] == [{"field": "from", "reason_code": "after_to"}]
    assert not [item for item in engine.requests if item[1] == "/v1/querylog"]
    # stream has no limit/cursor; export has format/limit up to 1,000,000
    assert client.get("/api/v1/dns/logs/stream?cursor=x").status_code == 422
    assert client.get("/api/v1/dns/logs/export?format=xml").status_code == 422
    assert client.get("/api/v1/dns/logs/export?limit=1000001").status_code == 422


def test_logs_permissions(app_client, engine) -> None:
    owner, headers, _events = app_client
    viewer, _vh = role_client(owner, headers, "viewer")
    operator, operator_headers = role_client(owner, headers, "operator")
    admin, admin_headers = role_client(owner, headers, "admin")
    for path in ("/api/v1/dns/logs", "/api/v1/dns/logs/status", "/api/v1/dns/logs/stream",
                 "/api/v1/dns/logs/export"):
        assert viewer.get(path).status_code == 403, path
        assert operator.get(path).status_code == 403, path
        assert admin.get(path).status_code == 200, path
    assert admin.get("/api/v1/dns/logs/status").json()["mode_effective"] == "all"
    body = {"confirmation": "DELETE LOGS"}
    assert operator.request("DELETE", "/api/v1/dns/logs", headers=operator_headers,
                            json=body).status_code == 403
    assert admin.request("DELETE", "/api/v1/dns/logs", headers=admin_headers,
                         json=body).status_code == 200
    # mitigations: dns:write
    assert viewer.get("/api/v1/dns/mitigations").status_code == 403
    assert operator.get("/api/v1/dns/mitigations").status_code == 200
    assert operator.post("/api/v1/dns/mitigations", headers=operator_headers, json={
        "kind": "client", "match": "10.0.0.9", "action": "block",
        "minutes": 15}).status_code == 201
    # stats / pressure: dns:read, names only with dns:logs
    for client in (viewer, operator):
        stats = client.get("/api/v1/dns/stats?range=7d").json()
        assert stats["top_hidden"] is True and stats["range"] == "7d"
        assert stats["top"] == {"domains": [], "clients": [], "nxdomain": [],
                                "refused_clients": []}
        assert stats["points"][0]["p95_ms"] == 3
        pressure = client.get("/api/v1/dns/pressure").json()
        assert pressure["hot"] == {"domains": 1, "clients": 1, "attacks": 0, "hidden": True}
        assert pressure["metrics"]["qps"] == 5
    stats = admin.get("/api/v1/dns/stats").json()
    assert stats["top_hidden"] is False and stats["range"] == "24h"
    assert stats["top"]["clients"] == [{"client": "10.0.0.1", "count": 5}]
    pressure = admin.get("/api/v1/dns/pressure").json()
    assert pressure["hot"]["hidden"] is False
    assert pressure["hot"]["clients"] == [{"client": "10.0.0.9", "qps": 9}]
    # events timeline: dns:read, names/addresses only with dns:logs
    engine.add_event("attack.detected", {"parent": "victim.example", "top_clients": ["10.0.0.1"],
                                         "unique_nxdomain_per_min": 900})
    engine.add_event("pressure.level", {"level": "critical", "reasons": []})
    hidden = viewer.get("/api/v1/dns/events").json()
    assert hidden["next"] == 2 and [item["type"] for item in hidden["items"]] == [
        "attack.detected", "pressure.level"]
    assert hidden["items"][0]["data"] == {"unique_nxdomain_per_min": 900}
    assert hidden["items"][0]["hidden"] is True and hidden["items"][1]["hidden"] is False
    assert hidden["items"][1]["data"]["level"] == "critical"
    full = admin.get("/api/v1/dns/events?after=1").json()
    assert [item["seq"] for item in full["items"]] == [2]
    assert admin.get("/api/v1/dns/events").json()["items"][0]["data"]["parent"] == (
        "victim.example")
    assert viewer.get("/api/v1/dns/events?after=-1").status_code == 422
    assert viewer.get("/api/v1/dns/events?limit=5").status_code == 422
    assert admin.get("/api/v1/dns/stats?range=2y").status_code == 422
    assert admin.get("/api/v1/dns/stats?rng=1h").status_code == 422


def test_logs_not_installed(app_client) -> None:
    client, headers, _events = app_client
    for path in ("/api/v1/dns/logs", "/api/v1/dns/logs/stream", "/api/v1/dns/logs/export",
                 "/api/v1/dns/stats", "/api/v1/dns/pressure"):
        response = client.get(path)
        assert response.status_code == 503, path
        assert response.json()["error"]["code"] == "dns_not_installed"
    assert dns_logs.STREAM_SLOTS.active() == 0 and dns_logs.EXPORT_SLOTS.active() == 0


# ----------------------------------------------------------------------------- SSE


def parse_sse(text: str) -> list[tuple[str, Any]]:
    frames = []
    for block in text.split("\n\n"):
        lines = [line for line in block.split("\n") if line and not line.startswith(":")]
        data = next((line[6:] for line in lines if line.startswith("data: ")), None)
        if data:
            value = json.loads(data)
            frames.append((value.pop("type"), value))
    return frames


def test_sse_stream_converts_ndjson(app_client, engine) -> None:
    client, _headers, _events = app_client
    response = client.get("/api/v1/dns/logs/stream?client=10.0.0.0/8&name=example")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-store"
    assert response.text.startswith("retry: 5000\n\n")
    frames = parse_sse(response.text)
    assert [name for name, _ in frames] == ["hello", "entry", "sampled", "ping", "end"]
    assert frames[1][1]["name"] == "host1.example.com" and "type" not in frames[1][1]
    assert frames[2][1] == {"skipped": 7}
    assert frames[-1][1] == {"reason": "engine_closed"}
    sent = [item for item in engine.requests if item[1] == "/v1/querylog/stream"]
    assert len(sent) == 1
    assert dns_logs.STREAM_SLOTS.active() == 0
    refused = client.get("/api/v1/dns/logs/stream?client=10.9.9.9")
    assert refused.status_code == 422 and refused.json()["error"]["code"] == "dns_invalid_filter"
    assert dns_logs.STREAM_SLOTS.active() == 0


def test_sse_disconnect_closes_engine_stream(app_client, engine) -> None:
    client, _headers, _events = app_client
    engine.tail = TailStream()
    seen: list[str] = []
    with client.stream("GET", "/api/v1/dns/logs/stream") as response:
        assert response.status_code == 200
        for line in response.iter_lines():
            if line.startswith("data: "):
                seen.append(json.loads(line[6:])["type"])
            if seen == ["hello"]:
                active_while_open = dns_logs.STREAM_SLOTS.active()
            if seen.count("entry") >= 2:
                break
    deadline = time.monotonic() + 5
    while (not engine.tail.closed or dns_logs.STREAM_SLOTS.active()) and (
        time.monotonic() < deadline
    ):
        settle(client)
    assert seen[:3] == ["hello", "entry", "entry"] and active_while_open == 1
    assert engine.tail.closed is True
    assert dns_logs.STREAM_SLOTS.active() == 0


def test_stream_limits_per_user_and_global(app_client, engine, monkeypatch) -> None:
    client, _headers, _events = app_client
    monkeypatch.setattr(dns_logs, "STREAM_SLOTS", dns_logs.Slots(0, 20))
    response = client.get("/api/v1/dns/logs/stream")
    assert response.status_code == 429
    assert response.json()["error"] | {} == response.json()["error"] | {
        "code": "dns_stream_limit", "scope": "user", "limit": 3}
    monkeypatch.setattr(dns_logs, "STREAM_SLOTS", dns_logs.Slots(3, 0))
    response = client.get("/api/v1/dns/logs/stream")
    assert response.json()["error"]["scope"] == "global"
    assert not [item for item in engine.requests if item[1] == "/v1/querylog/stream"]


def test_sse_heartbeat_and_disconnect_unit(engine) -> None:
    async def scenario() -> tuple[list[bytes], TailStream, list[int]]:
        engine.tail = TailStream(quiet=True)
        stream = await dns_client.DnsClient().open_stream(
            "/v1/querylog/stream", max_bytes=1 << 20, max_seconds=60)
        released: list[int] = []
        cleanup = dns_logs.Cleanup(stream, lambda: released.append(1))
        checks = iter([False, True])

        async def disconnected() -> bool:
            return next(checks)

        frames = [chunk async for chunk in dns_logs.sse_events(
            stream, disconnected, cleanup, heartbeat=0.05)]
        await cleanup()  # idempotent
        return frames, engine.tail, released

    frames, tail, released = asyncio.run(scenario())
    assert frames[0] == b"retry: 5000\n\n"
    assert frames[1] == b'data: {"type":"hello"}\n\n'
    assert frames[2] == b": keep-alive\n\n"
    assert len(frames) == 3 and tail.closed and released == [1]


def test_stream_limits_end_frames(engine) -> None:
    async def scenario(**limits: Any) -> list[tuple[str, Any]]:
        engine.tail = TailStream()
        stream = await dns_client.DnsClient().open_stream("/v1/querylog/stream", **limits)
        cleanup = dns_logs.Cleanup(stream, lambda: None)

        async def connected() -> bool:
            return False

        chunks = [chunk async for chunk in dns_logs.sse_events(stream, connected, cleanup)]
        return parse_sse(b"".join(chunks).decode())

    by_bytes = asyncio.run(scenario(max_bytes=600, max_seconds=60))
    assert by_bytes[-1] == ("end", {"reason": "max_bytes"})
    by_time = asyncio.run(scenario(max_bytes=1 << 20, max_seconds=0.05))
    assert by_time[-1] == ("end", {"reason": "max_seconds"})
    assert engine.tail.closed


# ----------------------------------------------------------------------------- export


def test_export_streams_with_disposition_and_audit(app_client, engine) -> None:
    client, _headers, _events = app_client
    response = client.get("/api/v1/dns/logs/export?format=csv&client=10.0.0.1")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    disposition = response.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="mrk-dns-logs-')
    assert disposition.endswith('.csv"')
    assert response.text.splitlines()[0] == "ts,client,name" and len(
        response.text.splitlines()) == 4
    ndjson = client.get("/api/v1/dns/logs/export")
    assert ndjson.headers["content-type"].startswith("application/x-ndjson")
    assert ndjson.headers["content-disposition"].endswith('.ndjson"')
    assert [json.loads(line)["name"] for line in ndjson.text.splitlines()] == [
        "host0.example.com", "host1.example.com", "host2.example.com"]
    sent = [item[1] for item in engine.requests if item[1] == "/v1/querylog/export"]
    assert len(sent) == 2
    text = audit_text(client)
    assert "dns.logs.export" in text and "format=csv,client=10.0.0.1" in text
    assert dns_logs.EXPORT_SLOTS.active() == 0


def test_export_limit(app_client, engine, monkeypatch) -> None:
    client, _headers, _events = app_client
    monkeypatch.setattr(dns_logs, "EXPORT_SLOTS", dns_logs.Slots(0, 3))
    response = client.get("/api/v1/dns/logs/export")
    assert response.status_code == 429 and response.json()["error"]["limit"] == 1


# ----------------------------------------------------------------------------- delete


def test_delete_logs_confirmation_and_audit(app_client, engine) -> None:
    client, headers, _events = app_client
    wrong = client.request("DELETE", "/api/v1/dns/logs", headers=headers,
                           json={"confirmation": "delete"})
    assert wrong.status_code == 422
    assert wrong.json()["error"]["code"] == "confirmation_mismatch"
    assert wrong.json()["error"]["expected_confirmation"] == "DELETE LOGS"
    missing = client.request("DELETE", "/api/v1/dns/logs", headers=headers, json={})
    assert missing.status_code == 422
    one = client.request("DELETE", "/api/v1/dns/logs", headers=headers,
                         json={"client": "10.0.0.5", "confirmation": "10.0.0.6"})
    assert one.json()["error"]["expected_confirmation"] == "10.0.0.5"
    assert engine.deleted == []
    done = client.request("DELETE", "/api/v1/dns/logs", headers=headers,
                          json={"client": "10.0.0.5", "confirmation": "10.0.0.5"})
    assert done.status_code == 200 and done.json()["deleted_rows"] == 40
    before = client.request("DELETE", "/api/v1/dns/logs", headers=headers, json={
        "before": "2026-11-01T00:00:00Z", "confirmation": "DELETE LOGS"})
    assert before.status_code == 200
    everything = client.request("DELETE", "/api/v1/dns/logs", headers=headers,
                                json={"confirmation": "DELETE LOGS"})
    assert everything.status_code == 200
    assert engine.deleted == [{"client": "10.0.0.5"}, {"before": 1793491200000}, {}]
    bad = client.request("DELETE", "/api/v1/dns/logs", headers=headers,
                         json={"client": "x", "confirmation": "DELETE LOGS"})
    assert bad.status_code == 422 and bad.json()["error"]["fields"][0]["field"] == "client"
    assert client.request("DELETE", "/api/v1/dns/logs",
                          json={"confirmation": "DELETE LOGS"}).status_code == 403  # CSRF
    text = audit_text(client)
    assert "dns.logs.delete" in text and "client=10.0.0.5" in text


# ----------------------------------------------------------------------------- mitigations


def test_mitigations_crud_validation_and_audit(app_client, engine) -> None:
    client, headers, _events = app_client
    created = client.post("/api/v1/dns/mitigations", headers=headers, json={
        "kind": "client", "match": "10.0.0.77/24", "action": "throttle", "qps": 20,
        "minutes": 60, "reason": "too loud"})
    assert created.status_code == 201, created.text
    assert created.json()["match"] == "10.0.0.0/24" and created.json()["qps"] == 20
    domain = client.post("/api/v1/dns/mitigations", headers=headers, json={
        "kind": "domain", "match": "*.Evil.Example.", "action": "block", "minutes": 10080})
    assert domain.json()["match"] == "evil.example"
    sent = json.loads([item for item in engine.requests
                       if item[:2] == ("POST", "/v1/mitigations")][-1][2])
    assert sent == {"kind": "domain", "match": "evil.example", "action": "block",
                    "minutes": 10080}
    cases = [
        ({"kind": "host", "match": "1.2.3.4", "action": "block", "minutes": 5}, "kind"),
        ({"kind": "client", "match": "nope", "action": "block", "minutes": 5}, "match"),
        ({"kind": "client", "match": "0.0.0.0/0", "action": "block", "minutes": 5}, "match"),
        ({"kind": "domain", "match": "1.2.3.4", "action": "block", "minutes": 5}, "match"),
        ({"kind": "client", "match": "1.2.3.4", "action": "drop", "minutes": 5}, "action"),
        ({"kind": "client", "match": "1.2.3.4", "action": "block", "minutes": 0}, "minutes"),
        ({"kind": "client", "match": "1.2.3.4", "action": "block", "minutes": 10081},
         "minutes"),
        ({"kind": "client", "match": "1.2.3.4", "action": "throttle", "minutes": 5}, "qps"),
        ({"kind": "client", "match": "1.2.3.4", "action": "block", "minutes": 5, "qps": 3},
         "qps"),
        ({"kind": "client", "match": "1.2.3.4", "action": "block", "minutes": 5,
          "source": "auto"}, "source"),
    ]
    for body, field in cases:
        response = client.post("/api/v1/dns/mitigations", headers=headers, json=body)
        assert response.status_code == 422, body
        assert response.json()["error"]["code"] == "dns_mitigation_invalid"
        assert response.json()["error"]["fields"][0]["field"] == field, body
    listed = client.get("/api/v1/dns/mitigations").json()["items"]
    assert len(listed) == 2
    mid = listed[0]["id"]
    assert client.request("DELETE", f"/api/v1/dns/mitigations/{mid}",
                          headers=headers).json() == {"deleted": mid}
    gone = client.request("DELETE", "/api/v1/dns/mitigations/none", headers=headers)
    assert gone.status_code == 404
    assert gone.json()["error"]["code"] == "dns_mitigation_not_found"
    text = audit_text(client)
    assert "dns.mitigation.create" in text and "dns.mitigation.delete" in text
    assert "client:10.0.0.0/24:throttle" in text


# ----------------------------------------------------------------------------- background


def test_host_metrics_push(app_client, engine) -> None:
    client, _headers, _events = app_client
    service = monitoring.ACTIVE_SERVICE
    assert service is not None
    service.last_host = None
    assert client.portal.call(monitor().push_host_metrics) is False
    now = int(time.time())
    service.last_host = {"ts": now - 5, "source": "agent", "cpu_percent": 42.5,
                         "mem_percent": 61.0, "load1": 1.25}
    assert client.portal.call(monitor().push_host_metrics) is True
    assert engine.host_metrics == [{"cpu_percent": 42.5, "memory_percent": 61.0,
                                    "load1": 1.25, "ts": (now - 5) * 1000}]
    service.last_host = {**service.last_host, "ts": now - 120}
    assert client.portal.call(monitor().push_host_metrics) is False
    assert len(engine.host_metrics) == 1


def test_events_become_notifications_with_dedupe(app_client, engine) -> None:
    client, _headers, events = app_client
    engine.add_event("pressure.level", {"level": "critical"})  # history before start
    mon = monitor()
    assert client.portal.call(mon.poll_events) == 0  # starts at the tail
    assert mon.cursor == 1
    engine.add_event("pressure.level", {"level": "warning"})
    engine.add_event("pressure.level", {"level": "critical", "reasons": [
        {"metric": "cpu", "value": 91, "threshold": 85}]})
    engine.add_event("pressure.level", {"level": "critical"})
    engine.add_event("pressure.level", {"from": "critical", "to": "emergency"})
    engine.add_event("attack.detected", {"parent": "victim.example", "top_clients": [
        "10.0.0.1"], "unique_nxdomain_per_min": 900})
    engine.add_event("attack.detected", {"parent": "victim.example"})
    engine.add_event("mitigation.auto", {"id": "m1", "kind": "client", "match": "10.0.0.1",
                                         "action": "refuse"})
    engine.add_event("mitigation.expired", {"id": "m1"})
    engine.add_event("querylog.degraded", {"mode_effective": "errors_only",
                                           "reason": "low_disk"})
    engine.add_event("querylog.recovered", {"mode_effective": "all"})
    engine.add_event("pressure.level", {"level": "normal"})
    assert client.portal.call(mon.poll_events) == 7
    settle(client)
    dns_events = [event for event in events if event.module == "dns"
                  and event.type != "dns.recovered"]
    summary = [(event.type, event.severity, event.dedupe_key) for event in dns_events]
    assert summary == [
        ("dns.pressure", "warning", "dns.pressure.critical"),
        ("dns.pressure", "error", "dns.pressure.emergency"),
        ("dns.attack_detected", "warning", "dns.attack.victim.example"),
        ("dns.mitigation_auto", "warning", "dns.mitigation_auto.client.10.0.0.1"),
        ("dns.logs_degraded", "warning", "dns.logs_degraded"),
        ("dns.logs_recovered", "info", "dns.logs_recovered"),
        ("dns.pressure", "info", "dns.pressure.normal"),
    ]
    assert dns_events[0].details["reasons"] == [{"metric": "cpu", "value": 91,
                                                 "threshold": 85}]
    assert "10.0.0.1" not in json.dumps(dns_events[2].details)
    assert mon.cursor == 12
    assert client.portal.call(mon.poll_events) == 0
    # engine restart: its sequence starts again
    engine.events = []
    assert client.portal.call(mon.poll_events) == 0 and mon.cursor == 0
    engine.add_event("attack.detected", {"parent": "other.example"})
    assert client.portal.call(mon.poll_events) == 1


def test_monitor_tick_backoff_and_loop(app_client, engine, monkeypatch) -> None:
    client, _headers, _events = app_client
    mon = monitor()
    service = monitoring.ACTIVE_SERVICE
    service.last_host = {"ts": int(time.time()), "source": "agent", "cpu_percent": 5.0,
                         "mem_percent": 6.0, "load1": 0.1}
    assert client.portal.call(mon.tick) == dns_monitor.EVENTS_SECONDS
    assert mon.cached_pressure()["level"] == "normal" and engine.host_metrics
    engine.down = True
    mon._next = dict.fromkeys(mon._next, 0.0)
    first = client.portal.call(mon.tick)
    second = client.portal.call(mon.tick)
    assert first == 10.0 and second == 20.0 and mon.failures == 2
    engine.down = False
    assert client.portal.call(mon.tick) == dns_monitor.EVENTS_SECONDS and mon.failures == 0
    # real loop: start/stop runs cleanly
    monkeypatch.setattr(dns_monitor, "MONITOR_ENABLED", True)
    monkeypatch.setattr(dns_monitor, "EVENTS_SECONDS", 0.01)
    before = len([item for item in engine.requests if item[1] == "/v1/events"])
    mon._next = dict.fromkeys(mon._next, 0.0)
    client.portal.call(mon.start)
    deadline = time.monotonic() + 5
    while len([item for item in engine.requests if item[1] == "/v1/events"]) <= before and (
        time.monotonic() < deadline
    ):
        settle(client)
    client.portal.call(mon.stop)
    assert len([item for item in engine.requests if item[1] == "/v1/events"]) > before


def test_monitor_idle_without_engine(app_client) -> None:
    client, _headers, _events = app_client
    mon = monitor()
    assert client.portal.call(mon.tick) == dns_monitor.EVENTS_SECONDS
    assert mon.cached_pressure() is None and mon.cursor is None


# ----------------------------------------------------------------------------- home


def home_rules(client: TestClient) -> dict[str, dict[str, Any]]:
    home.LAST_SERVICE.invalidate()
    return {item["id"]: item for item in client.get("/api/v1/home").json()["attention"]}


def test_home_pressure_and_attack_rules(app_client, engine) -> None:
    client, headers, _events = app_client
    dns.ACTIVE_SERVICE._status_at = 0.0
    client.get("/api/v1/dns/status")
    engine.pressure = {**engine.pressure, "level": "critical", "since": NOW_MS,
                       "reasons": [{"metric": "qps_percent", "value": 93, "threshold": 90}],
                       "hot": {"domains": [], "clients": [], "attacks": [
                           {"parent": "victim.example", "unique_nxdomain_per_min": 800,
                            "top_clients": ["10.0.0.1"], "since": NOW_MS}]}}
    # The cache is filled by the loop, not by the home request.
    assert "dns_under_pressure" not in home_rules(client)
    client.portal.call(monitor().refresh_pressure)
    calls = len([item for item in engine.requests if item[1] == "/v1/pressure"])
    rules = home_rules(client)
    assert len([item for item in engine.requests if item[1] == "/v1/pressure"]) == calls
    item = rules["dns_under_pressure"]
    assert item["severity"] == "warning"
    assert item["params"] == {"level": "critical", "since": NOW_MS, "reasons": ["qps_percent"]}
    assert item["action"] == {"kind": "navigate", "route": "#/dns/monitor"}
    attack = rules["dns_attack_detected:victim.example"]
    assert attack["severity"] == "warning"
    assert attack["params"] == {"parent": "victim.example", "since": NOW_MS}
    assert attack["action"]["route"] == "#/dns/monitor"
    engine.pressure = {**engine.pressure, "level": "emergency"}
    client.portal.call(monitor().refresh_pressure)
    assert home_rules(client)["dns_under_pressure"]["severity"] == "critical"
    viewer, _vh = role_client(client, headers, "viewer")
    seen = {item["rule"] for item in viewer.get("/api/v1/home").json()["attention"]}
    assert "dns_under_pressure" in seen
    # The attacked domain name is log data: viewers (no dns:logs) do not get it.
    assert "dns_attack_detected" not in seen
    # stale cache -> no rule
    monitor().pressure_at = time.time() - 120
    assert "dns_under_pressure" not in home_rules(client)
    assert {"dns_under_pressure", "dns_attack_detected"} <= set(
        client.get("/api/v1/home/rules").json()["attention"])


def test_home_rules_unit() -> None:
    facts = {"dns": {"installed": True, "reachable": True, "pressure": {
        "level": "warning", "since": 5, "reasons": [{"metric": "cpu"}, "junk"], "hot": {}}}}
    items = home.evaluate(facts, time.time())
    assert [(item["rule"], item["severity"], item["params"]) for item in items] == [
        ("dns_under_pressure", "warning", {"level": "warning", "since": 5,
                                           "reasons": ["cpu"]})]
    facts["dns"]["pressure"]["level"] = "normal"
    assert home.evaluate(facts, time.time()) == []
    facts["dns"]["reachable"] = False
    facts["dns"]["pressure"]["level"] = "emergency"
    assert [item["rule"] for item in home.evaluate(facts, time.time())] == ["dns_unreachable"]


# ----------------------------------------------------------------------------- settings


def test_engine_settings_d2_sections(app_client, engine) -> None:
    client, headers, _events = app_client
    current = client.get("/api/v1/dns/settings").json()
    bad = copy.deepcopy(current)
    bad["querylog"].update({"mode": "everything", "sample_percent": 0, "client_ip": "partial",
                            "max_bytes": 10, "exclude_names": ["ok.example", "bad name"],
                            "exclude_clients": ["10.0.0.0/8", "nope"], "stream_max_eps": 0,
                            "enabled": "yes"})
    bad["stats"].update({"top_k": 5, "minute_retention_hours": 1000})
    bad["pressure"]["thresholds"]["critical"]["cpu"] = 60  # below warning (70)
    bad["pressure"]["thresholds"]["warning"]["qps_percent"] = 2000
    bad["pressure"]["thresholds"]["warning"]["bogus"] = 1
    bad["pressure"]["actions"]["log_sampling"] = "on"
    bad["pressure"]["attack_detection"].update({"mode": "maybe", "mitigation_minutes": 0})
    bad["pressure"]["dwell_seconds"] = 1
    response = client.put("/api/v1/dns/settings", headers=headers, json=bad)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "dns_settings_invalid"
    fields = {item["field"]: item["reason_code"] for item in response.json()["error"]["fields"]}
    assert fields == {
        "querylog.enabled": "invalid_type",
        "querylog.mode": "invalid_choice",
        "querylog.client_ip": "invalid_choice",
        "querylog.sample_percent": "out_of_range",
        "querylog.max_bytes": "out_of_range",
        "querylog.stream_max_eps": "out_of_range",
        "querylog.exclude_names.1": "invalid_format",
        "querylog.exclude_clients.1": "invalid_cidr",
        "stats.minute_retention_hours": "out_of_range",
        "stats.top_k": "out_of_range",
        "pressure.dwell_seconds": "out_of_range",
        "pressure.thresholds.warning.bogus": "unknown_field",
        "pressure.thresholds.warning.qps_percent": "out_of_range",
        "pressure.thresholds.critical.cpu": "below_lower_level",
        "pressure.thresholds.critical.qps_percent": "below_lower_level",
        "pressure.actions.log_sampling": "invalid_type",
        "pressure.attack_detection.mode": "invalid_choice",
        "pressure.attack_detection.mitigation_minutes": "out_of_range",
    }
    assert not [item for item in engine.requests if item[0] == "PUT"]
    good = copy.deepcopy(current)
    good["querylog"].update({"mode": "sample", "sample_percent": 10, "client_ip": "mask",
                             "exclude_names": ["*.internal.example"],
                             "exclude_clients": ["192.168.0.0/16"]})
    good["pressure"]["attack_detection"]["mode"] = "auto"
    saved = client.put("/api/v1/dns/settings", headers=headers, json=good)
    assert saved.status_code == 200, saved.text
    assert saved.json()["querylog"]["mode"] == "sample"
    assert "dns.settings.update" in audit_text(client)


def test_filter_units() -> None:
    assert dns_filters.parse_time_ms("2026-11-08T10:00:00+03:30") == 1794119400000
    assert dns_filters.parse_time_ms("2026-11-08T10:00:00") is None  # no timezone
    assert dns_filters.parse_time_ms(str(NOW_MS + 2 * 86_400_000)) is None
    assert dns_filters.client_match("2001:db8::1/32") == "2001:db8::/32"
    assert dns_filters.name_filter("Bücher.example") == "xn--bcher-kva.example"
    assert dns_filters.name_filter("*.") is None
    assert dns_filters.query_filters({"limit": "5", "_": "1"}) == {"limit": "5"}
    assert dns_filters.query_filters({}, mode="export") == {"format": "ndjson"}
    assert dns_filters.query_filters({}, mode="stream") == {}
    assert dns_validate.d2_settings_errors({}) == []
    assert dns_validate.d2_settings_errors({"querylog": []}) == [
        {"field": "querylog", "reason_code": "invalid_type"}]
    slots = dns_logs.Slots(1, 2)
    assert slots.acquire(1) is None and slots.acquire(1) == "user"
    assert slots.acquire(2) is None and slots.acquire(3) == "global"
    slots.release(1)
    slots.release(1)
    assert slots.active() == 1
