"""Regression tests for the critical review fixes (2026-11-08)."""

import asyncio
import io
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane import pypi_router
from mrk_control_plane.auth import AuthStore
from mrk_control_plane.components import Probe
from mrk_control_plane.config import Settings
from mrk_control_plane.database import Database
from mrk_control_plane.healthcheck import probe_host
from mrk_control_plane.main import create_app
from mrk_control_plane.pypi_router import (
    LocalSpoolError,
    RouterSettings,
    Upstream,
    _spool_verified_artifact,
    create_router_app,
    prepare_spool_dir,
)
from mrk_control_plane.supervisor_listener import essential_programs, should_stop
from mrk_control_plane.supervisor_listener import run as run_listener
from mrk_control_plane.tasks import TaskManager
from mrk_control_plane.upstream_store import UpstreamStore
from mrk_control_plane.verdaccio_runtime import build_runtime_config

from .helpers import login_owner


def _router_settings(tmp_path: Path) -> RouterSettings:
    return RouterSettings(
        upstreams=(
            Upstream("primary", "https://pypi.example/simple/", frozenset({"pypi.example"})),
            Upstream(
                "fallback", "https://fallback.example/simple/", frozenset({"fallback.example"})
            ),
        ),
        offline_file=tmp_path / "offline",
        spool_dir=tmp_path / "spool",
    )


def test_artifact_spool_uses_data_directory_not_tmpfs(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    request = httpx.Request("GET", "https://files.example/demo.whl")
    response = httpx.Response(200, content=b"wheel", request=request)
    path, size, _digest = asyncio.run(
        _spool_verified_artifact(response, httpx.AsyncClient(), None, 1024, spool)
    )
    try:
        assert path.parent == spool
        assert size == 5
    finally:
        path.unlink(missing_ok=True)


def test_from_env_spools_under_data_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("MRK_PYPI_ROUTER_SPOOL_DIR", raising=False)
    assert RouterSettings.from_env().spool_dir == tmp_path / "tmp" / "pypi-router"


def test_insufficient_local_space_is_a_local_error(tmp_path: Path, monkeypatch) -> None:
    class Usage:
        free = 10

    monkeypatch.setattr(pypi_router.shutil, "disk_usage", lambda _path: Usage())
    request = httpx.Request("GET", "https://files.example/demo.whl")
    response = httpx.Response(
        200, content=b"x" * 64, headers={"content-length": "64"}, request=request
    )
    with pytest.raises(LocalSpoolError):
        asyncio.run(
            _spool_verified_artifact(response, httpx.AsyncClient(), None, 1024, tmp_path)
        )
    assert list(tmp_path.glob("mrk-pypi-*")) == []


def test_local_spool_failure_does_not_open_upstream_circuits(tmp_path: Path, monkeypatch) -> None:
    settings = _router_settings(tmp_path)
    page = '<a href="https://pypi.example/files/demo-1.0.whl">demo-1.0.whl</a>'

    async def fake_read(_settings, url, *_args, **_kwargs):
        return httpx.Response(200, text=page, request=httpx.Request("GET", url))

    async def fake_request(_settings, method, url, *_args, **_kwargs):
        return httpx.AsyncClient(), httpx.Response(
            200, content=b"wheel", request=httpx.Request(method, url)
        )

    async def no_space(*_args, **_kwargs):
        raise LocalSpoolError("disk full")

    monkeypatch.setattr(pypi_router, "_read_response", fake_read)
    monkeypatch.setattr(pypi_router, "_request", fake_request)
    monkeypatch.setattr(pypi_router, "_spool_verified_artifact", no_space)
    app = create_router_app(settings)

    with TestClient(app) as client:
        for _ in range(3):
            assert client.get("/files/demo/demo-1.0.whl").status_code == 507
        circuits = app.state.runtime.circuits
        assert all(state.failures == 0 for state in circuits.values())


def test_stale_spool_files_are_removed_on_start(tmp_path: Path) -> None:
    settings = _router_settings(tmp_path)
    settings.spool_dir.mkdir()
    stale = settings.spool_dir / "mrk-pypi-old.artifact"
    stale.write_bytes(b"left over")
    prepare_spool_dir(settings)
    assert not stale.exists()


def test_healthcheck_host_follows_trusted_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_TRUSTED_HOSTS", "packages.example.com,other.example.com")
    assert probe_host() == "packages.example.com"
    monkeypatch.setenv("MRK_TRUSTED_HOSTS", "*.example.com")
    assert probe_host() == "healthcheck.example.com"
    monkeypatch.delenv("MRK_TRUSTED_HOSTS")
    assert probe_host() == "localhost"


def test_readiness_reports_dead_pypi_router(tmp_path: Path, monkeypatch) -> None:
    settings = Settings.for_test(tmp_path)
    object.__setattr__(settings, "pypi_enabled", True)
    object.__setattr__(settings, "pypi_bootstrap_state_file", None)

    def fake_check(_host: str, port: int, _path: str, _timeout: float = 1.0) -> Probe:
        return Probe(port != settings.pypi_router_health_port)

    monkeypatch.setattr("mrk_control_plane.components.probe_http_component", fake_check)
    with TestClient(create_app(settings)) as client:
        ready = client.get("/health/ready")
    assert ready.status_code == 503
    assert ready.json()["component"] == "pypi_upstream_router"


def test_supervisor_listener_stops_only_on_essential_fatal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("MRK_FATAL_MARKER", str(tmp_path / "fatal"))
    monkeypatch.delenv("MRK_FATAL_ESSENTIAL", raising=False)
    fatal = {"eventname": "PROCESS_STATE_FATAL"}
    # Essential programs stop the container; npm/PyPI/S3 are left to the watchdog.
    assert should_stop(fatal, {"processname": "pglite"}, set())
    assert should_stop(fatal, {"processname": "control-plane"}, set())
    assert not should_stop(fatal, {"processname": "devpi"}, set())
    assert not should_stop(fatal, {"processname": "verdaccio"}, set())
    assert should_stop(fatal, {"processname": "devpi"}, set(), essential_programs("*"))
    assert not should_stop(
        fatal, {"processname": "devpi-configure"}, {"devpi-configure"}, essential_programs("*")
    )
    assert not should_stop({"eventname": "PROCESS_STATE_EXITED"}, {"processname": "x"}, set())

    killed: list[int] = []
    monkeypatch.setattr(
        "mrk_control_plane.supervisor_listener.os.kill", lambda _pid, sig: killed.append(sig)
    )

    def feed(name: str) -> tuple[str, str]:
        payload = f"processname:{name} groupname:{name} from_state:BACKOFF"
        header = f"ver:3.0 server:supervisor eventname:PROCESS_STATE_FATAL len:{len(payload)}\n"
        stdout, stderr = io.StringIO(), io.StringIO()
        run_listener(io.StringIO(header + payload), stdout, stderr)
        return stdout.getvalue(), stderr.getvalue()

    out, err = feed("verdaccio")
    assert not killed
    assert "RESULT 2\nOK" in out
    assert "watchdog" in err
    assert not (tmp_path / "fatal").exists()

    out, _ = feed("control-plane")
    assert killed
    assert "RESULT 2\nOK" in out
    assert (tmp_path / "fatal").read_text() == "control-plane"


def test_blocking_last_usable_upstream_is_rejected(tmp_path: Path) -> None:
    store = UpstreamStore(tmp_path)
    store.ensure_defaults("https://pypi.org/simple/", "https://package-mirror.liara.ir/repository/pypi/simple/")
    npm = [item for item in store.raw_list() if item["ecosystem"] == "npm"]
    first, second = npm
    store.update(str(first["id"]), {"blocked_until": int(time.time()) + 600})
    with pytest.raises(ValueError, match="last usable upstream"):
        store.update(str(second["id"]), {"blocked_until": int(time.time()) + 600})
    store.set_offline("npm", True)
    store.update(str(second["id"]), {"blocked_until": int(time.time()) + 600})


def test_verdaccio_without_usable_upstream_starts_cache_only(tmp_path: Path) -> None:
    store = UpstreamStore(tmp_path)
    store.ensure_defaults("https://pypi.org/simple/", "https://package-mirror.liara.ir/repository/pypi/simple/")
    for item in store.raw_list():
        if item["ecosystem"] == "npm":
            # Simulate state written before the block guard existed.
            items = store.raw_list()
            for entry in items:
                if entry["id"] == item["id"]:
                    entry["blocked_until"] = int(time.time()) + 600
            store._write(items)  # noqa: SLF001 - bypass the guard on purpose
    config_path, _env = build_runtime_config(tmp_path)
    config = config_path.read_text(encoding="utf-8")
    assert "uplinks:\n  {}" in config
    assert "proxy:" not in config


def test_setup_rate_limit_counts_rejected_attempts(tmp_path: Path) -> None:
    store = AuthStore(tmp_path)
    for _ in range(5):
        with pytest.raises(ValueError):
            store.setup_owner("Owner", "owner@example.test", "short", "10.0.0.1", None)
    with pytest.raises(ValueError, match="rate limited"):
        store.setup_owner(
            "Owner", "owner@example.test", "a-valid-long-password-123", "10.0.0.1", None
        )


def test_task_worker_survives_claim_failure(tmp_path: Path, monkeypatch) -> None:
    manager = TaskManager(tmp_path, None, database=Database(tmp_path))  # type: ignore[arg-type]
    calls = {"count": 0}

    def flaky_claim():
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("database restarting")
        manager._stop.set()  # noqa: SLF001
        return None

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(manager, "_claim", flaky_claim)
    monkeypatch.setattr("mrk_control_plane.tasks.asyncio.sleep", no_sleep)
    asyncio.run(manager.run())
    assert calls["count"] == 2


def test_block_endpoint_returns_conflict_for_last_upstream(tmp_path: Path) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        csrf = str(login_owner(client)["csrf_token"])
        npm = [
            item
            for item in client.get("/api/v1/upstreams").json()["items"]
            if item["ecosystem"] == "npm"
        ]
        first, second = npm
        ok = client.post(
            f"/api/v1/upstreams/{first['id']}/block",
            headers={"X-CSRF-Token": csrf},
            json={"reason": "maintenance", "duration_seconds": 600},
        )
        assert ok.status_code == 200
        rejected = client.post(
            f"/api/v1/upstreams/{second['id']}/block",
            headers={"X-CSRF-Token": csrf},
            json={"reason": "maintenance", "duration_seconds": 600},
        )
        assert rejected.status_code == 409


def test_database_maintenance_runs(tmp_path: Path) -> None:
    db = Database(tmp_path)
    db.initialize()
    db.maintenance()
