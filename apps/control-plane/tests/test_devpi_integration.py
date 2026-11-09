"""«My space» PyPI against a real devpi-server (docs/43 §0.1).

Starts ``mrk-devpi-server`` (devpi-server + the pre-upload quota tween) in a
temporary directory and drives it through the control plane: index creation, a
scoped upload token, an upload, a foreign token refused, a quota refusal before
the file is stored, version delete. Skipped when devpi-server is not installed.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import io
import os
import secrets
import socket
import subprocess
import sys
import tarfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app

from .test_my_space import Space, User, code, env, unlimited  # noqa: F401 - env is a fixture

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("devpi_server") is None,
    reason="devpi-server is not installed in this environment (pip install devpi-server)",
)

SRC = Path(__file__).resolve().parents[1] / "src"
ROOT_PASSWORD = "root-integration-secret"  # noqa: S105 - test-only


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _sdist(name: str, version: str, padding: int = 0) -> tuple[str, bytes]:
    """A minimal valid sdist; ``padding`` adds incompressible bytes."""
    base = f"{name.replace('-', '_')}-{version}"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        files = {f"{base}/PKG-INFO": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
                 .encode()}
        if padding:
            files[f"{base}/blob.bin"] = os.urandom(padding)
        for path, data in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return f"{base}.tar.gz", buffer.getvalue()


def _upload(base: str, index: str, auth: tuple[str, str], name: str, version: str,
            padding: int = 0) -> httpx.Response:
    filename, content = _sdist(name, version, padding)
    return httpx.post(f"{base}/{index}/", auth=auth, timeout=60, data={
        ":action": "file_upload", "name": name, "version": version, "protocol_version": "1",
        "metadata_version": "2.1", "filetype": "sdist", "pyversion": "source",
    }, files={"content": (filename, content, "application/octet-stream")})


@pytest.fixture
def devpi(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    server_dir = tmp_path / "devpi"
    quota_file = tmp_path / "cp" / "pypi" / "quotas.json"
    password_file = tmp_path / "root-password"
    password_file.write_text(ROOT_PASSWORD)
    secret_file = tmp_path / "devpi-secret"
    secret_file.write_text(secrets.token_urlsafe(48))
    process_env = {**os.environ, "PYTHONPATH": os.pathsep.join(
        [str(SRC), os.environ.get("PYTHONPATH", "")]), "MRK_PYPI_QUOTA_FILE": str(quota_file)}
    init = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, "-c", "import sys; from devpi_server.init import init; sys.exit(init())",
         "--serverdir", str(server_dir), "--root-passwd", ROOT_PASSWORD],
        env=process_env, capture_output=True, text=True, timeout=120, check=False)
    if init.returncode != 0:
        pytest.skip(f"devpi-init failed here: {init.stderr[-400:]}")
    port = _free_port()
    log = (tmp_path / "devpi.log").open("w")
    process = subprocess.Popen(  # noqa: S603 - fixed arguments
        [sys.executable, "-m", "mrk_control_plane.devpi_quota", "--serverdir", str(server_dir),
         "--host", "127.0.0.1", "--port", str(port), "--restrict-modify", "root",
         "--secretfile", str(secret_file)],
        env=process_env, stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 90
        while True:
            try:
                if httpx.get(f"{base}/+api", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if process.poll() is not None or time.monotonic() > deadline:
                log.flush()
                pytest.fail("devpi-server did not start:\n"
                            + (tmp_path / "devpi.log").read_text()[-2000:])
            time.sleep(0.3)
        monkeypatch.setenv("MRK_PYPI_ROOT_PASSWORD_FILE", str(password_file))
        monkeypatch.setenv("MRK_PYPI_SERVER_DIR", str(server_dir))
        monkeypatch.setenv("MRK_PYPI_QUOTA_FILE", str(quota_file))
        yield {"base": base, "port": port, "server_dir": server_dir, "quota_file": quota_file}
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
        log.close()


def test_real_devpi_index_token_quota_and_delete(env: dict[str, Any], devpi: dict[str, Any],  # noqa: F811
                                                 tmp_path: Path) -> None:
    settings = dataclasses.replace(Settings.for_test(tmp_path / "cp"),
                                   pypi_health_port=devpi["port"])
    base = devpi["base"]
    with TestClient(create_app(settings)) as client:
        space = Space(client, env)
        space.settings(enabled=True, verify_domains=False)
        alice, bob = space.user("alice"), space.user("bob")
        unlimited(space, alice)
        unlimited(space, bob)
        index = f"{alice.slug}/dev"

        # Index + scoped upload token.
        made = alice.post("/packages/tokens", {"ecosystem": "pypi", "name": "twine"})
        assert made.status_code == 201, made.text
        auth = (made.json()["username"], made.json()["token"])
        assert "repository = http" in made.json()["setup"]["pypirc"]
        config = httpx.get(f"{base}/{index}", headers={"Accept": "application/json"}).json()
        assert config["result"]["acl_upload"] == [auth[0]]
        assert config["result"]["bases"] == ["root/pypi"]
        quotas = devpi["quota_file"].read_text()
        assert f'"{index}": null' in quotas

        first = _upload(base, index, auth, "demo-pkg", "1.0.0")
        assert first.status_code == 200, first.text

        # Another workspace's token cannot upload here; anonymous cannot either.
        other = bob.post("/packages/tokens", {"ecosystem": "pypi", "name": "bob"})
        assert other.status_code == 201, other.text
        foreign = _upload(base, index, (other.json()["username"], other.json()["token"]),
                          "demo-pkg", "1.0.1")
        assert foreign.status_code == 403, foreign.text
        assert httpx.post(f"{base}/{index}/", data={":action": "file_upload"}).status_code \
            == 401

        # Quota: the limit is checked before the file is stored.
        files_dir = devpi["server_dir"] / "+files" / alice.slug / "dev"
        used = sum(path.stat().st_size for path in files_dir.rglob("*") if path.is_file())
        assert used > 0
        space.workspace_patch(alice.personal, quota_overrides={"pypi_bytes": used + 2000})
        assert f'"{index}": {used + 2000}' in devpi["quota_file"].read_text()
        refused = _upload(base, index, auth, "demo-pkg", "2.0.0", padding=20_000)
        assert refused.status_code == 413, refused.text
        assert "quota_exceeded" in refused.reason_phrase
        assert refused.json()["code"] == "quota_exceeded"
        after = sum(path.stat().st_size for path in files_dir.rglob("*") if path.is_file())
        assert after == used
        listing = alice.get("/packages").json()["pypi"]
        assert listing["packages"] == [{"name": "demo-pkg", "versions": ["1.0.0"]}]
        assert listing["usage_bytes"] == used

        # A small upload still fits.
        small = _upload(base, index, auth, "demo-pkg", "1.1.0")
        assert small.status_code == 200, small.text

        # Delete a version through the panel API: gone from devpi.
        deleted = alice.call("DELETE", "/packages/pypi/demo-pkg/versions/1.0.0")
        assert deleted.status_code == 200, deleted.text
        listing = alice.get("/packages").json()["pypi"]
        assert listing["packages"] == [{"name": "demo-pkg", "versions": ["1.1.0"]}]
        # Bob's delete only ever reaches his own index: Alice's version stays.
        bob.call("DELETE", "/packages/pypi/demo-pkg/versions/1.1.0")
        assert alice.get("/packages").json()["pypi"]["packages"] == [
            {"name": "demo-pkg", "versions": ["1.1.0"]}]
        assert code(alice.post("/packages/tokens", {"ecosystem": "nope", "name": "x"})) \
            == "invalid_request"
