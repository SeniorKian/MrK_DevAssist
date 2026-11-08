"""Gate 19 S8: agent archive allowlist and the package-files route."""

from __future__ import annotations

import base64
import io
import json
import tarfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.agent import package_files, signing
from mrk_control_plane.agent.app import AgentConfig, create_agent_app
from mrk_control_plane.agent.docker_client import DockerNotAllowed, check_allowed

KEY = bytes(range(32))
API = "/v1.47"
CID = "a" * 64
IMAGE_ID = "sha256:" + "b" * 64


def make_tar(*members: tuple[str, bytes | None], link: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif link is not None:
                info.type = tarfile.SYMTYPE
                info.linkname = link
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class FakeDocker:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.files: dict[str, bytes] = {
            "/etc/os-release": make_tar(("os-release", b""), link="../usr/lib/os-release"),
            "/usr/lib/os-release": make_tar(("os-release", b"ID=debian\nVERSION_ID=12\n")),
            "/var/lib/dpkg/status.d": make_tar(
                ("status.d", None),
                ("status.d/base", b"Package: base-files\nVersion: 12.4\n"),
                ("status.d/../../evil", b"x"),
                ("status.d/sub/deeper", b"x"),
            ),
            "/var/lib/rpm/Packages": b"\0" * 10000,
            "/app/package-lock.json": b"x" * (package_files.DEFAULT_FILE_CAP + 70 * 1024),
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/version":
            return httpx.Response(200, json={"Version": "27.3.1", "ApiVersion": "1.47"})
        path = path.removeprefix(API)
        if path in {f"/containers/{CID}/json", "/containers/web/json"}:
            return httpx.Response(
                200,
                json={"Id": CID, "Name": "/web", "Image": IMAGE_ID,
                      "State": {"Running": True, "Status": "running"},
                      "Config": {"Image": "debian:12", "Labels": {}}},
            )
        if path == f"/containers/{CID}/archive" and request.method == "GET":
            target = request.url.params["path"]
            self.paths.append(target)
            if target in self.files:
                return httpx.Response(200, content=self.files[target])
            return httpx.Response(404, json={"message": "Could not find the file"})
        return httpx.Response(500, json={"message": f"unexpected {request.method} {path}"})


def make_agent(tmp_path: Path, fake: FakeDocker):
    proc = tmp_path / "proc"
    proc.mkdir(parents=True, exist_ok=True)
    config = AgentConfig(key=KEY, proc_dir=proc, root_paths=[tmp_path],
                         cgroup_dir=tmp_path / "nocg")
    return create_agent_app(config, docker_transport=httpx.MockTransport(fake.handler))


def signed_get(client: TestClient, path: str):
    return client.get(path, headers=signing.sign_headers(KEY, "GET", path, b""))


def test_archive_allowlist_only_fixed_paths() -> None:
    for path in package_files.PACKAGE_DB_PATHS:
        check_allowed("GET", f"/containers/{CID}/archive", {"path": path})
    rejected = [
        "/etc/shadow",
        "/etc/os-release/../shadow",
        "/var/lib/dpkg/status/../../../etc/shadow",
        "../etc/passwd",
        "/app/.env",
        "/var/lib/dpkg/status ",
        "/var/lib/dpkg/status\n",
        "/proc/self/environ",
        "/",
        "",
    ]
    for path in rejected:
        with pytest.raises(DockerNotAllowed):
            check_allowed("GET", f"/containers/{CID}/archive", {"path": path})
    with pytest.raises(DockerNotAllowed):  # path is required
        check_allowed("GET", f"/containers/{CID}/archive", {})
    with pytest.raises(DockerNotAllowed):  # no extra parameters
        check_allowed("GET", f"/containers/{CID}/archive",
                      {"path": "/etc/os-release", "noOverwriteDirNonDir": "1"})
    with pytest.raises(DockerNotAllowed):  # names are not accepted, only full ids
        check_allowed("GET", "/containers/web/archive", {"path": "/etc/os-release"})
    for method in ("PUT", "HEAD", "POST"):
        with pytest.raises(DockerNotAllowed):
            check_allowed(method, f"/containers/{CID}/archive", {"path": "/etc/os-release"})


def test_package_files_route(tmp_path: Path) -> None:
    fake = FakeDocker()
    with TestClient(make_agent(tmp_path, fake)) as client:
        assert client.get("/v1/vuln/containers/web/package-files").status_code == 401
        response = signed_get(client, "/v1/vuln/containers/web/package-files")
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["container_id"] == CID and payload["image_id"] == IMAGE_ID
        assert payload["running"] is True
        files = {item["path"]: item for item in payload["files"]}
        assert files["/etc/os-release"]["note"] == "symlink"
        assert files["/etc/os-release"]["entries"] == []
        (entry,) = files["/usr/lib/os-release"]["entries"]
        assert base64.b64decode(entry["data_b64"]).startswith(b"ID=debian")
        names = [e["name"] for e in files["/var/lib/dpkg/status.d"]["entries"]]
        assert names == ["status.d/base"]  # traversal and nested entries dropped
        assert files["/var/lib/rpm/Packages"] == {
            "path": "/var/lib/rpm/Packages", "entries": [], "note": "present"
        }
        assert {"path": "/app/package-lock.json", "error": "too_large"} in payload["errors"]
        assert payload["truncated"] is True
        assert "/lib/apk/db/installed" in payload["missing"]
        # Only fixed paths were ever requested from Docker.
        assert set(fake.paths) == set(package_files.PACKAGE_DB_PATHS)
        bad = signed_get(client, "/v1/vuln/containers/..%2Fx/package-files")
        assert bad.status_code in (404, 422)
        json.dumps(payload)  # serialisable


def test_decode_archive_rejects_oversized_member() -> None:
    raw = make_tar(("status", b"x" * 20))
    entries, note = package_files.decode_archive(raw, "/var/lib/dpkg/status")
    assert note is None and entries[0].data == b"x" * 20
    assert package_files.decode_archive(b"not a tar" * 100, "/var/lib/dpkg/status") == (
        [], "invalid_archive"
    )
