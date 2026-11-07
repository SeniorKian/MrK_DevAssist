import asyncio
import hashlib
import json
import socket
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.pypi_router import (
    ArtifactIntegrityError,
    RouterRuntime,
    RouterSettings,
    Upstream,
    _artifact_links,
    _error_code,
    _expected_sha256,
    _fetch_page,
    _normalized_simple_url,
    _rewrite_project_page,
    _spool_verified_artifact,
    _upstream_request_headers,
    _validate_destination,
    create_router_app,
)
from mrk_control_plane.secret_store import SecretStore


def _settings(tmp_path: Path) -> RouterSettings:
    return RouterSettings(
        upstreams=(
            Upstream(
                "primary",
                "https://pypi.example/simple/",
                frozenset({"pypi.example", "files.example"}),
            ),
            Upstream(
                "fallback",
                "https://fallback.example/simple/",
                frozenset({"fallback.example"}),
            ),
        ),
        offline_file=tmp_path / "offline",
    )


def test_upstream_url_requires_credential_free_https() -> None:
    assert _normalized_simple_url("https://pypi.org/simple") == "https://pypi.org/simple/"
    with pytest.raises(ValueError, match="HTTPS"):
        _normalized_simple_url("http://pypi.org/simple/")
    with pytest.raises(ValueError, match="HTTPS"):
        _normalized_simple_url("https://user:secret@pypi.org/simple/")


def test_project_page_rewrites_artifacts_and_preserves_hash() -> None:
    source = (
        '<a href="https://files.example/packages/demo-1.0.whl#sha256=abc">'
        "demo-1.0.whl</a>"
    )
    rewritten = _rewrite_project_page(
        "demo", "https://pypi.example/simple/demo/", source
    )

    assert 'href="/files/demo/demo-1.0.whl#sha256=abc"' in rewritten
    assert "files.example" not in rewritten
    assert _artifact_links(
        "https://pypi.example/simple/demo/", source
    ) == {"demo-1.0.whl": "https://files.example/packages/demo-1.0.whl#sha256=abc"}


def test_circuit_opens_after_threshold(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    runtime = RouterRuntime(settings)
    upstream = settings.upstreams[0]

    runtime.failure(upstream, "connect_timeout")
    assert runtime.available(upstream)
    runtime.failure(upstream, "connect_timeout")
    assert not runtime.available(upstream)
    runtime.success(upstream)
    assert runtime.available(upstream)


def test_status_exposes_safe_state_and_offline_mode(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    app = create_router_app(settings)

    with TestClient(app) as client:
        online = client.get("/status")
        settings.offline_file.write_text("enabled\n", encoding="utf-8")
        offline = client.get("/status")

    assert online.json()["offline"] is False
    assert offline.json()["offline"] is True
    assert offline.json()["upstreams"][0]["state"] == "closed"
    assert "allowed_artifact_hosts" not in offline.text


def test_ssrf_validation_rejects_unlisted_and_private_hosts(monkeypatch) -> None:
    with pytest.raises(ValueError, match="allowlist"):
        asyncio.run(
            _validate_destination(
                "https://metadata.invalid/latest", frozenset({"pypi.example"}), False
            )
        )

    monkeypatch.setattr(
        "mrk_control_plane.pypi_router.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError, match="non-public"):
        asyncio.run(
            _validate_destination(
                "https://pypi.example/simple/", frozenset({"pypi.example"}), False
            )
        )


@pytest.mark.parametrize(
    ("failure", "error_code"),
    [
        (socket.gaierror("dns failed"), "dns_error"),
        (httpx.ConnectTimeout("connect timed out"), "connect_timeout"),
        (httpx.ReadTimeout("read timed out"), "read_timeout"),
        (httpx.ReadError("connection reset"), "network_error"),
    ],
)
def test_network_chaos_fails_over_to_next_upstream(
    tmp_path: Path, monkeypatch, failure: Exception, error_code: str
) -> None:
    runtime = RouterRuntime(_settings(tmp_path))
    fallback_response = httpx.Response(
        200,
        content=b"fallback",
        request=httpx.Request("GET", "https://fallback.example/simple/"),
    )
    calls = 0

    async def fake_read(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise failure
        return fallback_response

    monkeypatch.setattr("mrk_control_plane.pypi_router._read_response", fake_read)
    selected, response = asyncio.run(_fetch_page(runtime, "")) or (None, None)

    assert selected is not None and selected.name == "fallback"
    assert response is fallback_response
    assert runtime.circuits["primary"].last_error == error_code
    assert runtime.last_selected == "fallback"


def test_retryable_5xx_fails_over_to_next_upstream(tmp_path: Path, monkeypatch) -> None:
    runtime = RouterRuntime(_settings(tmp_path))
    responses = iter(
        [
            httpx.Response(
                503,
                request=httpx.Request("GET", "https://pypi.example/simple/"),
            ),
            httpx.Response(
                200,
                content=b"fallback",
                request=httpx.Request("GET", "https://fallback.example/simple/"),
            ),
        ]
    )

    async def fake_read(*_args, **_kwargs):
        return next(responses)

    monkeypatch.setattr("mrk_control_plane.pypi_router._read_response", fake_read)
    selected, _response = asyncio.run(_fetch_page(runtime, "")) or (None, None)

    assert selected is not None and selected.name == "fallback"
    assert runtime.circuits["primary"].last_error == "http_503"


def test_artifact_checksum_is_verified_before_exposure(tmp_path: Path) -> None:
    payload = b"trusted wheel bytes"
    expected = hashlib.sha256(payload).hexdigest()
    assert _expected_sha256(f"https://files.example/demo.whl#sha256={expected}") == expected

    request = httpx.Request("GET", "https://files.example/demo.whl")
    response = httpx.Response(200, content=payload, request=request)
    client = httpx.AsyncClient()
    path, size, actual = asyncio.run(
        _spool_verified_artifact(response, client, expected, max_bytes=1024)
    )
    try:
        assert path.read_bytes() == payload
        assert size == len(payload)
        assert actual == expected
    finally:
        path.unlink(missing_ok=True)


def test_corrupt_artifact_is_rejected_and_temp_file_removed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mrk_control_plane.pypi_router.tempfile.tempdir", str(tmp_path))
    request = httpx.Request("GET", "https://files.example/demo.whl")
    response = httpx.Response(200, content=b"corrupt", request=request)
    client = httpx.AsyncClient()

    with pytest.raises(ArtifactIntegrityError, match="does not match") as raised:
        asyncio.run(
            _spool_verified_artifact(response, client, "0" * 64, max_bytes=1024)
        )

    assert _error_code(raised.value) == "checksum_mismatch"
    assert list(tmp_path.glob("mrk-pypi-*.artifact")) == []


def test_private_upstream_credential_is_loaded_without_leaking_to_cdn(tmp_path: Path) -> None:
    secret_store = SecretStore(tmp_path)
    reference, _updated_at = secret_store.replace(None, {"token": "private-token"})
    config_file = tmp_path / "upstreams.json"
    config_file.write_text(
        json.dumps(
            [
                {
                    "id": "private",
                    "name": "private",
                    "ecosystem": "pypi",
                    "url": "https://pypi.example/simple/",
                    "priority": 1,
                    "timeout_seconds": 10,
                    "enabled": True,
                    "blocked_until": None,
                    "credential_ref": reference,
                    "credential_type": "bearer",
                }
            ]
        ),
        encoding="utf-8",
    )
    settings = RouterSettings(
        upstreams=(),
        offline_file=tmp_path / "offline",
        config_file=config_file,
        data_dir=tmp_path,
    )
    runtime = RouterRuntime(settings)
    upstream = runtime.upstreams()[0]
    authorization = runtime.authorization_header(upstream)

    assert authorization == "Bearer private-token"
    assert _upstream_request_headers(
        "https://pypi.example/simple/demo/", authorization, "pypi.example"
    )["Authorization"] == authorization
    assert "Authorization" not in _upstream_request_headers(
        "https://files.example/demo.whl", authorization, "pypi.example"
    )

