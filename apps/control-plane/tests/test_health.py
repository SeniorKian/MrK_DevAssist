from dataclasses import replace
from pathlib import Path

from fastapi.testclient import TestClient
from mrk_control_plane import __version__
from mrk_control_plane.config import Settings
from mrk_control_plane.main import DATA_DIRECTORIES, create_app

from .helpers import login_owner


def test_health_and_status_contract(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        live = client.get("/health/live")
        ready = client.get("/health/ready")
        login_owner(client)
        status = client.get("/api/v1/system/status")

    assert live.json() == {"status": "ok"}
    assert ready.json() == {"status": "ready"}
    assert status.json()["components"]["npm_registry"] == "not_configured"
    assert status.json()["build"] == {
        "commit": "unknown",
        "built_at": "unknown",
        "ui_version": __version__,
    }
    assert status.json()["uptime_seconds"] >= 0
    assert 0 <= status.json()["storage"]["used_percent"] <= 100
    assert status.json()["storage"]["total_bytes"] > 0
    assert str(tmp_path) not in status.text
    for relative_path in DATA_DIRECTORIES:
        assert (tmp_path / relative_path).is_dir()


def test_security_headers_and_request_id(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        response = client.get("/health/live", headers={"X-Request-ID": "test-123"})

    assert response.headers["x-request-id"] == "test-123"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"


def test_unsafe_request_id_is_replaced(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        response = client.get("/missing", headers={"X-Request-ID": "bad\nvalue"})

    assert response.status_code == 404
    assert response.headers["x-request-id"] != "bad\nvalue"
    assert response.json()["error"]["message"] == "Not found"
    assert response.json()["error"]["request_id"] == response.headers["x-request-id"]


def test_readiness_fails_when_enabled_npm_is_down(
    tmp_path: Path, monkeypatch,
) -> None:
    settings = replace(Settings.for_test(tmp_path), npm_enabled=True)
    monkeypatch.setattr("mrk_control_plane.main.check_http_component", lambda *_args: False)
    app = create_app(settings)

    with TestClient(app) as client:
        ready = client.get("/health/ready")
        login_owner(client)
        status = client.get("/api/v1/system/status")

    assert ready.status_code == 503
    assert ready.json() == {"status": "not_ready", "component": "npm_registry"}
    assert status.json()["components"]["npm_registry"] == "unavailable"


def test_readiness_fails_when_enabled_pypi_is_down(
    tmp_path: Path, monkeypatch,
) -> None:
    settings = replace(Settings.for_test(tmp_path), pypi_enabled=True)
    monkeypatch.setattr("mrk_control_plane.main.check_http_component", lambda *_args: False)
    app = create_app(settings)

    with TestClient(app) as client:
        ready = client.get("/health/ready")
        login_owner(client)
        status = client.get("/api/v1/system/status")

    assert ready.status_code == 503
    assert ready.json() == {"status": "not_ready", "component": "pypi_registry"}
    assert status.json()["components"]["pypi_registry"] == "unavailable"


def test_readiness_waits_for_pypi_bootstrap_marker(
    tmp_path: Path, monkeypatch,
) -> None:
    marker = tmp_path / "pypi" / "auth" / "upstream-configured"
    settings = replace(
        Settings.for_test(tmp_path),
        pypi_enabled=True,
        pypi_bootstrap_state_file=marker,
    )
    monkeypatch.setattr("mrk_control_plane.main.check_http_component", lambda *_args: True)
    app = create_app(settings)

    with TestClient(app) as client:
        before = client.get("/health/ready")
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("https://example.invalid/simple/\n", encoding="utf-8")
        after = client.get("/health/ready")

    assert before.status_code == 503
    assert before.json() == {"status": "not_ready", "component": "pypi_registry"}
    assert after.json() == {"status": "ready"}
