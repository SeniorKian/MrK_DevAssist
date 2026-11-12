"""S3 engine in its own container (docs/44): token from env, pushed config, wizard connect.

The engine here runs on its own data folder with an EMPTY SecretStore, exactly like the
mrk-s3 image: everything it knows arrives through ``PUT /admin/config``.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from pathlib import Path

import boto3
import pytest
import uvicorn
from botocore.config import Config
from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import s3_client
from mrk_control_plane.s3engine.engine import Engine, load_or_create_token
from mrk_control_plane.s3engine.settings import EngineSettings
from mrk_control_plane.secret_store import SecretStore

from .helpers import login_owner

TOKEN = "t" * 40


def _serve(app) -> tuple[uvicorn.Server, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(app, log_config=None, access_log=False, lifespan="off")
    )
    threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True).start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.02)
    return server, port


@pytest.fixture
def remote_engine(tmp_path: Path, monkeypatch):
    for name in ("MRK_S3_ENGINE_URL", "MRK_S3_ADMIN_URL"):
        monkeypatch.delenv(name, raising=False)
    root = tmp_path / "engine"
    settings = EngineSettings(
        data_root=root / "s3", secret_data_dir=root, link_roots=(root / "links",),
        fsync_policy="none", hash_rate_bytes=0, disk_block_percent=100,
    )
    engine = Engine(settings, SecretStore(root))  # empty: secrets must be pushed
    api, api_port = _serve(engine.api)
    admin, admin_port = _serve(engine.admin)
    yield {"engine": engine, "api": f"http://127.0.0.1:{api_port}",
           "admin": f"http://127.0.0.1:{admin_port}"}
    api.should_exit = admin.should_exit = True
    time.sleep(0.2)
    engine.close()
    s3_client._REMOTE_PATH = None  # noqa: SLF001 - module global set by the panel


def test_seeded_token_is_authoritative(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "admin.token"
    first = load_or_create_token(path)
    monkeypatch.setenv("MRK_S3_ADMIN_TOKEN", TOKEN)
    assert load_or_create_token(path) == TOKEN != first
    assert path.read_text().strip() == TOKEN
    monkeypatch.setenv("MRK_S3_ADMIN_TOKEN", "short")
    with pytest.raises(RuntimeError):
        load_or_create_token(path)


def test_admin_config_push_validates_and_needs_the_token(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MRK_S3_ADMIN_TOKEN", TOKEN)
    settings = EngineSettings(data_root=tmp_path / "s3", secret_data_dir=tmp_path,
                              link_roots=(tmp_path / "links",), fsync_policy="none")
    engine = Engine(settings, SecretStore(tmp_path))
    try:
        with TestClient(engine.admin) as admin:
            assert admin.put("/admin/config", json={}).status_code == 401
            auth = {"X-MRK-Admin-Token": TOKEN}
            assert admin.put("/admin/config", headers=auth, content=b"{").status_code == 400
            bad = admin.put("/admin/config", headers=auth, json=["not", "an", "object"])
            assert bad.status_code == 422
            assert admin.get("/admin/health", headers=auth).json()["config_loaded"] is False
            good = {"version": 1, "enabled": True, "region": "us-east-1", "buckets": [],
                    "identities": [{"id": "u1", "name": "u1", "enabled": True, "keys": [
                        {"access_key_id": "AKIAEXAMPLE000000001", "secret_ref": "r1",
                         "secret_access_key": "inline-secret", "enabled": True}]}]}
            assert admin.put("/admin/config", headers=auth, json=good).status_code == 200
            assert admin.get("/admin/health", headers=auth).json()["config_loaded"] is True
        assert engine.snapshots.secret_for("AKIAEXAMPLE000000001") == "inline-secret"
        assert oct(settings.config_file.stat().st_mode & 0o777) in {"0o600", "0o666"}
    finally:
        engine.close()


def test_wizard_connects_a_separate_engine(tmp_path: Path, remote_engine, monkeypatch) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        items = {i["id"]: i for i in client.get("/api/v1/install/catalog").json()["items"]}
        assert items["s3"]["availability"] == "ready"
        assert items["s3"]["connection"] == "not_connected"

        bundle = client.post("/api/v1/install/s3/bundle", headers=headers, json={}).json()
        token = re.search(r"^MRK_S3_ADMIN_TOKEN=(.+)$", bundle["env"], re.MULTILINE).group(1)
        assert token == (tmp_path / "cp" / "modules" / "s3" / "admin.token").read_text().strip()
        # Files made again keep the same token, so a running engine never breaks.
        again = client.post("/api/v1/install/s3/bundle", headers=headers, json={}).json()
        assert token in again["env"]

        # The engine was started with that token (MRK_S3_ADMIN_TOKEN in the real image).
        remote_engine["engine"].admin_token = token
        result = client.post(
            "/api/v1/install/s3/connect", headers=headers,
            json={"url": remote_engine["admin"], "engine_url": remote_engine["api"]},
        ).json()
        assert result == {"id": "s3", "connection": "connected"}
        assert s3_client.engine_url() == remote_engine["api"]

        # A bucket made in the panel reaches the engine through the pushed config.
        created = client.post("/api/v1/s3/buckets", headers=headers, json={"name": "photos"})
        assert created.status_code == 201, created.text
        assert "photos" in remote_engine["engine"].snapshots.current.buckets
        upload = client.post(
            "/api/v1/s3/buckets/photos/objects?key=hello.txt", headers=headers,
            content=b"hello split world", )
        assert upload.status_code == 200, upload.text
        listed = client.get("/api/v1/s3/buckets/photos/objects")
        assert listed.status_code == 200 and "hello.txt" in listed.text

        services = {i["id"]: i for i in client.get("/api/v1/services").json()["items"]}
        assert services["s3"]["state"] == "running"

        # A user key made in the panel works with a normal S3 client against the engine.
        identity = client.post(
            "/api/v1/s3/identities", headers=headers,
            json={"name": "app", "policy_template": "read_only", "buckets": ["photos"]},
        )
        assert identity.status_code == 201, identity.text
        key = client.post(
            f"/api/v1/s3/identities/{identity.json()['id']}/keys", headers=headers, json={},
        )
        assert key.status_code == 201, key.text
        s3 = boto3.client(
            "s3", endpoint_url=remote_engine["api"], region_name="us-east-1",
            aws_access_key_id=key.json()["access_key_id"],
            aws_secret_access_key=key.json()["secret_access_key"],
            config=Config(s3={"addressing_style": "path"}, signature_version="s3v4",
                          retries={"max_attempts": 1}),
        )
        assert s3.get_object(Bucket="photos", Key="hello.txt")["Body"].read() == (
            b"hello split world")


def test_engine_health_retries_once_and_names_dns_failures(tmp_path: Path, monkeypatch) -> None:
    import asyncio

    import httpx

    token = tmp_path / "admin.token"
    token.write_text(TOKEN)
    monkeypatch.setattr(s3_client, "HEALTH_RETRY_DELAY_SECONDS", 0)
    calls: list[str] = []
    mode = {"value": "flaky"}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if mode["value"] == "dns":
            raise httpx.ConnectError("[Errno -2] Name or service not known", request=request)
        if mode["value"] == "flaky" and len(calls) == 1:
            raise httpx.ReadTimeout("slow", request=request)
        if mode["value"] == "down":
            raise httpx.ConnectError("[Errno 111] Connection refused", request=request)
        return httpx.Response(200, json={"status": "ok"})

    monkeypatch.setattr(s3_client, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(handler))
    admin = s3_client.EngineAdmin(token, "http://mrk-s3:9001")
    # One slow answer is retried instead of reporting "degraded".
    assert asyncio.run(admin.probe()) == (True, None) and len(calls) == 2
    calls.clear()
    mode["value"] = "dns"
    assert asyncio.run(admin.probe()) == (False, "s3_name_unresolved")
    assert len(calls) == 1  # an unknown name will not resolve on a retry
    calls.clear()
    mode["value"] = "down"
    assert asyncio.run(admin.probe()) == (False, "engine_unreachable") and len(calls) == 2


def test_home_warns_when_a_separate_engine_stays_unreachable(
    tmp_path: Path, monkeypatch
) -> None:
    import httpx
    from mrk_control_plane.modules import home

    for name in ("MRK_S3_ENGINE_URL", "MRK_S3_ADMIN_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(s3_client, "HEALTH_RETRY_DELAY_SECONDS", 0)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[Errno -2] Name or service not known", request=request)

    monkeypatch.setattr(s3_client, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(handler))
    try:
        with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
            login_owner(client)
            s3_client.configure_remote(tmp_path / "cp")
            s3_client.save_remote("http://mrk-s3:9000", "http://mrk-s3:9001")
            service = home.LAST_SERVICE
            assert service is not None

            def rules() -> dict[str, dict]:
                service.invalidate()
                service._s3_probed_at = 0.0  # noqa: SLF001 - skip the 30 s spacing
                items = client.get("/api/v1/home").json()["attention"]
                return {item["rule"]: item for item in items}

            assert "s3_unreachable" not in rules()  # one failed check is not an outage
            second = rules()
            assert second["s3_unreachable"]["params"]["code"] == "s3_name_unresolved"
            assert second["s3_unreachable"]["action"]["route"] == "#/services"
    finally:
        s3_client._REMOTE_PATH = None  # noqa: SLF001 - module global set by the panel
