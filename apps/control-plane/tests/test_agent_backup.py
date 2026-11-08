"""Gate 18 Host Agent backup sources: exec allowlist, dump templates, volume tar safety."""

from __future__ import annotations

import io
import json
import os
import stat
import struct
import tarfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.agent import backup as agent_backup
from mrk_control_plane.agent import signing
from mrk_control_plane.agent.app import AgentConfig, create_agent_app
from mrk_control_plane.agent.docker_client import DockerNotAllowed, check_allowed

KEY = bytes(range(32))
API = "/v1.47"
PG_ID = "1" * 64
MYSQL_ID = "2" * 64
WEB_ID = "3" * 64
DOKPLOY_PG_ID = "4" * 64
STOPPED_ID = "5" * 64
REDIS_ID = "6" * 64
EXEC_ID = "e" * 64
PG_PASSWORD = "pg-Secret-Value-123"  # noqa: S105 - test fixture
MYSQL_PASSWORD = "my-Root-Secret-456"  # noqa: S105 - test fixture
REDIS_PASSWORD = "redis-Secret-789"  # noqa: S105 - test fixture


def mux(stream: int, payload: bytes) -> bytes:
    return struct.pack(">BxxxI", stream, len(payload)) + payload


def _container(cid, name, image, env=None, running=True, labels=None, cmd=None):
    return {
        "Id": cid,
        "Names": [f"/{name}"],
        "Image": image,
        "State": "running" if running else "exited",
        "Labels": labels or {},
        "inspect": {
            "Id": cid,
            "Name": f"/{name}",
            "State": {"Running": running},
            "Config": {"Image": image, "Env": env or [], "Labels": labels or {},
                       "Cmd": cmd or []},
        },
    }


class FakeDocker:
    def __init__(self, volumes_root: Path | None = None) -> None:
        self.seen: list[httpx.Request] = []
        self.exec_bodies: list[dict] = []
        self.dump_stdout = b"PGDMP" + os.urandom(3000)
        self.dump_stderr = b"pg_dump: connecting with password " + PG_PASSWORD.encode()
        self.exit_code = 0
        self.containers = [
            _container(PG_ID, "app-db", "postgres:16",
                       ["POSTGRES_USER=app", "POSTGRES_DB=appdb",
                        f"POSTGRES_PASSWORD={PG_PASSWORD}"]),
            _container(MYSQL_ID, "shop-mysql", "mysql:8.4",
                       [f"MYSQL_ROOT_PASSWORD={MYSQL_PASSWORD}", "MYSQL_DATABASE=shop"]),
            _container(WEB_ID, "web", "nginx:1.27"),
            _container(DOKPLOY_PG_ID, "dokploy-postgres", "postgres:16",
                       ["POSTGRES_USER=dokploy", f"POSTGRES_PASSWORD={PG_PASSWORD}"]),
            _container(STOPPED_ID, "old-db", "postgres:15", running=False),
            _container(REDIS_ID, "cache", "redis:7",
                       cmd=["redis-server", "--requirepass", REDIS_PASSWORD]),
        ]
        self.volumes = [
            {"Name": "app_data", "Driver": "local",
             "Mountpoint": "/var/lib/docker/volumes/app_data/_data",
             "Labels": {"com.docker.compose.project": "app"}},
            {"Name": "nfs_data", "Driver": "local",
             "Mountpoint": "/mnt/elsewhere"},
            {"Name": "plugin_vol", "Driver": "rexray", "Mountpoint": "/x"},
        ]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        path = request.url.path
        if path == "/version":
            return httpx.Response(200, json={"Version": "27.3.1", "ApiVersion": "1.47"})
        assert path.startswith(API + "/")
        path = path.removeprefix(API)
        by_ref = {c["Id"]: c for c in self.containers}
        by_ref.update({c["Names"][0].lstrip("/"): c for c in self.containers})
        if request.method == "GET" and path == "/containers/json":
            return httpx.Response(200, json=[
                {k: v for k, v in c.items() if k != "inspect"} for c in self.containers
            ])
        if request.method == "GET" and path == "/volumes":
            return httpx.Response(200, json={"Volumes": self.volumes})
        parts = path.split("/")
        if request.method == "GET" and len(parts) == 4 and parts[1] == "containers":
            container = by_ref.get(parts[2])
            if container is None:
                return httpx.Response(404, json={"message": "No such container"})
            return httpx.Response(200, json=container["inspect"])
        if request.method == "POST" and len(parts) == 4 and parts[3] == "exec":
            self.exec_bodies.append(json.loads(request.content))
            return httpx.Response(201, json={"Id": EXEC_ID})
        if request.method == "POST" and path == f"/exec/{EXEC_ID}/start":
            body = mux(1, self.dump_stdout[:1000]) + mux(2, self.dump_stderr)
            body += mux(1, self.dump_stdout[1000:])
            return httpx.Response(200, content=body)
        if request.method == "GET" and path == f"/exec/{EXEC_ID}/json":
            return httpx.Response(200, json={"ExitCode": self.exit_code, "Running": False})
        return httpx.Response(500, json={"message": f"unexpected {request.method} {path}"})


def make_agent(tmp_path: Path, fake: FakeDocker, volumes_root: Path | None = None):
    proc = tmp_path / "proc"
    proc.mkdir(parents=True, exist_ok=True)
    (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 250 kB\n")
    (proc / "loadavg").write_text("0.40 0.30 0.20 1/100 1\n")
    (proc / "stat").write_text("cpu  100 0 100 800 0 0 0 0 0 0\n")
    config = AgentConfig(
        key=KEY, proc_dir=proc, root_paths=[tmp_path], cgroup_dir=tmp_path / "nocg",
        volumes_root=volumes_root or tmp_path / "volumes",
    )
    return create_agent_app(config, docker_transport=httpx.MockTransport(fake.handler))


def signed(client: TestClient, method: str, path: str, body: object | None = None):
    raw = b"" if body is None else json.dumps(body).encode()
    headers = signing.sign_headers(KEY, method, path, raw)
    if raw:
        headers["Content-Type"] = "application/json"
    return client.request(method, path, content=raw, headers=headers)


def parse_frames(raw: bytes) -> tuple[bytes, dict | None]:
    data = bytearray()
    status = None
    offset = 0
    while offset < len(raw):
        kind = raw[offset:offset + 1]
        length = struct.unpack(">I", raw[offset + 1:offset + 5])[0]
        payload = raw[offset + 5:offset + 5 + length]
        offset += 5 + length
        if kind == b"D":
            assert status is None
            data.extend(payload)
        else:
            assert kind == b"E"
            status = json.loads(payload)
    return bytes(data), status


# ----- exec allowlist ----------------------------------------------------------------


def _exec_body(argv, env=()):
    return {"AttachStdin": False, "AttachStdout": True, "AttachStderr": True, "Tty": False,
            "Cmd": list(argv), "Env": list(env)}


def test_exec_allowlist_accepts_only_fixed_templates() -> None:
    good = [
        ["pg_dump", "--format=custom", "--no-password", "--username", "app", "--dbname", "appdb"],
        ["mysqldump", *agent_backup.MYSQL_FLAGS, "--user=root", "--all-databases"],
        ["mariadb-dump", *agent_backup.MYSQL_FLAGS, "--user=root", "--databases", "shop"],
        ["sh", "-c", agent_backup.MONGO_SCRIPT_AUTH],
        ["redis-cli", "--rdb", "-"],
    ]
    for argv in good:
        check_allowed("POST", f"/containers/{PG_ID}/exec", None,
                      _exec_body(argv, ["PGPASSWORD=x"]))
    check_allowed("POST", f"/exec/{EXEC_ID}/start", None, {"Detach": False, "Tty": False})
    check_allowed("GET", f"/exec/{EXEC_ID}/json")

    bad_argv = [
        ["sh", "-c", "cat /etc/shadow"],
        ["pg_dump", "--format=custom", "--no-password", "--username", "app", "--dbname",
         "host=evil"],
        ["pg_dump", "--format=custom", "--no-password", "--username", "app", "--dbname", "a",
         "--file=/tmp/x"],
        ["mysqldump", "--user=root", "--all-databases"],
        ["mysqldump", *agent_backup.MYSQL_FLAGS, "--user=root", "--databases", "-e"],
        ["redis-cli", "FLUSHALL"],
        ["bash"],
        "pg_dump",
    ]
    for argv in bad_argv:
        with pytest.raises(DockerNotAllowed):
            check_allowed("POST", f"/containers/{PG_ID}/exec", None,
                          {**_exec_body(["x"]), "Cmd": argv})
    template = ["redis-cli", "--rdb", "-"]
    for body in (
        {**_exec_body(template), "User": "root"},
        {**_exec_body(template), "Privileged": True},
        {**_exec_body(template), "Tty": True},
        {**_exec_body(template), "AttachStdin": True},
        _exec_body(template, ["LD_PRELOAD=/x.so"]),
        _exec_body(template, ["NOEQUALS"]),
        None,
    ):
        with pytest.raises(DockerNotAllowed):
            check_allowed("POST", f"/containers/{PG_ID}/exec", None, body)
    with pytest.raises(DockerNotAllowed):  # names are not accepted for exec, only full ids
        check_allowed("POST", "/containers/app-db/exec", None, _exec_body(template))
    with pytest.raises(DockerNotAllowed):
        check_allowed("POST", f"/exec/{EXEC_ID}/start", None, {"Detach": True, "Tty": False})
    with pytest.raises(DockerNotAllowed):
        check_allowed("POST", f"/exec/{EXEC_ID}/resize", None, None)
    with pytest.raises(DockerNotAllowed):  # body on a body-less rule
        check_allowed("POST", f"/containers/{PG_ID}/start", None, {"x": 1})


def _inspect(image, env=(), cmd=()):
    return {"Config": {"Image": image, "Env": list(env), "Cmd": list(cmd)}}


def test_dump_specs_keep_credentials_out_of_argv() -> None:
    spec = agent_backup.build_dump_spec(
        "postgres", None, _inspect("postgres", ["POSTGRES_USER=app", "POSTGRES_DB=appdb",
                                                f"POSTGRES_PASSWORD={PG_PASSWORD}"]))
    assert spec.argv[-1] == "appdb" and "app" in spec.argv
    assert PG_PASSWORD not in " ".join(spec.argv) and spec.env == [f"PGPASSWORD={PG_PASSWORD}"]
    assert agent_backup.exec_spec_allowed(spec.argv, spec.env)
    assert spec.redact(f"x {PG_PASSWORD} y") == "x *** y"

    spec = agent_backup.build_dump_spec(
        "mysql", "shop", _inspect("mysql", [f"MYSQL_ROOT_PASSWORD={MYSQL_PASSWORD}"]))
    assert spec.argv[0] == "mysqldump" and "--single-transaction" in spec.argv
    assert spec.argv[-2:] == ["--databases", "shop"] and "--user=root" in spec.argv
    assert spec.env == [f"MYSQL_PWD={MYSQL_PASSWORD}"]
    assert MYSQL_PASSWORD not in " ".join(spec.argv)

    spec = agent_backup.build_dump_spec(
        "mariadb", None, _inspect("mariadb", ["MARIADB_USER=u", "MARIADB_PASSWORD=pw",
                                              "MARIADB_DATABASE=d"]))
    assert spec.argv[0] == "mariadb-dump" and spec.argv[-1] == "d" and "--user=u" in spec.argv
    with pytest.raises(agent_backup.BackupSourceError) as missing:
        agent_backup.build_dump_spec("mysql", None, _inspect("mysql"))
    assert missing.value.code == "credentials_unavailable"

    spec = agent_backup.build_dump_spec(
        "mongo", "app", _inspect("mongo", ["MONGO_INITDB_ROOT_USERNAME=root",
                                           "MONGO_INITDB_ROOT_PASSWORD=mongo-pw"]))
    assert spec.argv == ["sh", "-c", agent_backup.MONGO_SCRIPT_AUTH_DB]
    assert "MRK_DB_PASSWORD=mongo-pw" in spec.env and "MRK_DB_NAME=app" in spec.env
    assert "mongo-pw" not in " ".join(spec.argv)

    spec = agent_backup.build_dump_spec(
        "redis", None, _inspect("redis", cmd=["redis-server", "--requirepass", REDIS_PASSWORD]))
    assert spec.argv == ["redis-cli", "--rdb", "-"]
    assert spec.env == [f"REDISCLI_AUTH={REDIS_PASSWORD}"]
    for engine, database in (("postgres", "x;rm"), ("postgres", "-oops"), ("bogus", None)):
        with pytest.raises(agent_backup.BackupSourceError):
            agent_backup.build_dump_spec(engine, database, _inspect("postgres"))
    with pytest.raises(agent_backup.BackupSourceError) as newline:
        agent_backup.build_dump_spec(
            "postgres", None, _inspect("postgres", ["POSTGRES_PASSWORD=a\nb"]))
    assert newline.value.code == "credentials_unsupported"


def test_detect_engine_heuristics() -> None:
    cases = {
        "postgres:16": "postgres", "bitnami/postgresql:16": "postgres",
        "postgis/postgis": "postgres", "mysql:8": "mysql", "percona:8": "mysql",
        "mariadb:11@sha256:" + "a" * 64: "mariadb", "mongo:7": "mongo",
        "bitnami/mongodb": "mongo", "redis:7-alpine": "redis", "valkey/valkey:8": "redis",
        "nginx:1.27": None, "registry.example.com:5000/team/app:1": None, "": None,
    }
    for image, expected in cases.items():
        assert agent_backup.detect_engine(image) == expected, image


# ----- agent endpoints ---------------------------------------------------------------


def test_dump_endpoint_streams_stdout_and_never_echoes_credentials(tmp_path: Path) -> None:
    fake = FakeDocker()
    client = TestClient(make_agent(tmp_path, fake))
    response = signed(client, "POST", f"/v1/backup/db/{PG_ID}/dump", {"engine": "postgres"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/x-mrk-agent-stream"
    data, status = parse_frames(response.content)
    assert data == fake.dump_stdout
    assert status == {"ok": True, "exit_code": 0, "bytes": len(fake.dump_stdout)}
    assert PG_PASSWORD.encode() not in response.content
    body = fake.exec_bodies[-1]
    assert body["Cmd"] == ["pg_dump", "--format=custom", "--no-password", "--username", "app",
                           "--dbname", "appdb"]
    assert body["Env"] == [f"PGPASSWORD={PG_PASSWORD}"]
    assert "User" not in body and "Privileged" not in body

    # A protected (Dokploy) database may be dumped: read-only.
    response = signed(client, "POST", "/v1/backup/db/dokploy-postgres/dump",
                      {"engine": "postgres", "database": "dokploy"})
    assert response.status_code == 200 and parse_frames(response.content)[1]["ok"] is True

    # Failing tool: stderr (which contains the password) stays in the agent.
    fake.exit_code = 1
    response = signed(client, "POST", f"/v1/backup/db/{PG_ID}/dump", {"engine": "postgres"})
    data, status = parse_frames(response.content)
    assert status["ok"] is False and status["error"] == "dump_failed"
    assert PG_PASSWORD.encode() not in response.content and b"connecting" not in response.content


def test_dump_endpoint_rejections(tmp_path: Path) -> None:
    fake = FakeDocker()
    client = TestClient(make_agent(tmp_path, fake))
    cases = [
        (f"/v1/backup/db/{WEB_ID}/dump", {"engine": "postgres"}, 422, "engine_mismatch"),
        (f"/v1/backup/db/{PG_ID}/dump", {"engine": "mysql"}, 422, "engine_mismatch"),
        (f"/v1/backup/db/{STOPPED_ID}/dump", {"engine": "postgres"}, 409,
         "container_not_running"),
        (f"/v1/backup/db/{PG_ID}/dump", {"engine": "postgres", "command": "sh"}, 422,
         "invalid_body"),
        (f"/v1/backup/db/{PG_ID}/dump", {"engine": "shell"}, 422, "invalid_engine"),
        (f"/v1/backup/db/{PG_ID}/dump", {"engine": "postgres", "database": "a b"}, 422,
         "invalid_database"),
        (f"/v1/backup/db/{MYSQL_ID}/dump", {"engine": "mysql", "database": "--all"}, 422,
         "invalid_database"),
        ("/v1/backup/db/missing/dump", {"engine": "postgres"}, 404, "not_found"),
    ]
    for path, body, status_code, code in cases:
        response = signed(client, "POST", path, body)
        assert response.status_code == status_code, (path, body, response.text)
        assert response.json()["error"] == code
    assert fake.exec_bodies == []
    # Unsigned requests and other methods are refused before any Docker call.
    assert client.post(f"/v1/backup/db/{PG_ID}/dump", json={"engine": "postgres"}).status_code \
        == 401
    assert signed(client, "PUT", f"/v1/backup/db/{PG_ID}/dump", {}).status_code == 405


def test_sources_endpoint(tmp_path: Path) -> None:
    fake = FakeDocker()
    client = TestClient(make_agent(tmp_path, fake))
    payload = signed(client, "GET", "/v1/backup/sources").json()
    names = {item["name"]: item for item in payload["databases"]}
    assert set(names) == {"app-db", "shop-mysql", "dokploy-postgres", "old-db", "cache"}
    assert names["dokploy-postgres"]["protected"] is True
    assert names["app-db"]["protected"] is False and names["cache"]["engine"] == "redis"
    assert "Env" not in json.dumps(payload) and PG_PASSWORD not in json.dumps(payload)
    volumes = {item["name"]: item for item in payload["volumes"]}
    assert volumes["app_data"]["supported"] is True
    assert volumes["plugin_vol"]["supported"] is False


def _tar_members(data: bytes) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        return {member.name: member for member in archive.getmembers()}


def test_volume_archive_endpoint(tmp_path: Path) -> None:
    volumes = tmp_path / "volumes"
    data_dir = volumes / "app_data" / "_data"
    (data_dir / "sub").mkdir(parents=True)
    (data_dir / "a.txt").write_bytes(b"hello")
    (data_dir / "sub" / "b.bin").write_bytes(os.urandom(700_000))
    fake = FakeDocker()
    client = TestClient(make_agent(tmp_path, fake, volumes))
    response = signed(client, "GET", "/v1/backup/volumes/app_data/archive")
    assert response.status_code == 200
    data, status = parse_frames(response.content)
    assert status["ok"] is True and status["stats"]["files"] == 2
    members = _tar_members(data)
    assert set(members) == {"a.txt", "sub", "sub/b.bin"}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        assert archive.extractfile("a.txt").read() == b"hello"
    for name, code, status_code in (
        ("nfs_data", "volume_unsupported", 422),
        ("plugin_vol", "volume_unsupported", 422),
        ("missing", "not_found", 404),
        ("-x", "invalid_volume", 422),
    ):
        response = signed(client, "GET", f"/v1/backup/volumes/{name}/archive")
        assert response.status_code == status_code, name
        assert response.json()["error"] == code


# ----- volume tar safety ---------------------------------------------------------------


def _st(mode: int, size: int = 0) -> os.stat_result:
    return os.stat_result((mode, 1, 1, 1, 0, 0, size, 0, 1_700_000_000, 0))


class FakeFs(agent_backup.VolumeFs):
    """In-memory tree: node = ('dir', {name: node}) | ('file', bytes) | ('link', target) | ..."""

    def __init__(self, tree: dict) -> None:
        self.fd_mode = False
        self.tree = ("dir", tree)
        self.opened_links: list[str] = []

    def _node(self, handle):
        return handle

    def open_root(self, path):
        return self.tree

    def close_dir(self, handle):
        return None

    def list(self, handle):
        return sorted(handle[1])

    def lstat(self, parent, name):
        node = parent[1][name]
        kind = node[0]
        if kind == "dir":
            return _st(stat.S_IFDIR | 0o755)
        if kind in {"file", "swapped"}:
            return _st(stat.S_IFREG | 0o644, len(node[1]) if kind == "file" else 10)
        if kind == "link":
            return _st(stat.S_IFLNK | 0o777)
        if kind == "fifo":
            return _st(stat.S_IFIFO | 0o644)
        if kind == "device":
            return _st(stat.S_IFCHR | 0o600)
        return _st(stat.S_IFSOCK | 0o600)

    def open_dir(self, parent, name):
        node = parent[1][name]
        if node[0] != "dir":
            raise NotADirectoryError(name)
        return node

    def open_file(self, parent, name):
        node = parent[1][name]
        if node[0] == "swapped":  # replaced by a symlink after lstat: O_NOFOLLOW -> ELOOP
            raise OSError(40, "Too many levels of symbolic links")
        if node[0] == "fifo_race":
            return io.BytesIO(b""), _st(stat.S_IFIFO | 0o644)
        if node[0] != "file":
            raise AssertionError(f"opened a {node[0]}")
        return io.BytesIO(node[1]), _st(stat.S_IFREG | 0o644, len(node[1]))

    def readlink(self, parent, name):
        return parent[1][name][1]


def test_volume_tar_never_follows_symlinks_and_skips_special_files() -> None:
    secret_tree = {"shadow": ("file", b"root:secret")}
    tree = {
        "ok.txt": ("file", b"data"),
        "escape": ("link", "/etc"),
        "escape_file": ("link", "../../../agent/agent.key"),
        "dirlink": ("link", "/host/volumes/other/_data"),
        "fifo": ("fifo",),
        "dev": ("device",),
        "sock": ("socket",),
        "swapped": ("swapped", b""),
        "nested": ("dir", {"inner.txt": ("file", b"x" * 10)}),
        "outside_target": ("dir", secret_tree),
    }
    fs = FakeFs(tree)
    # A symlink to a directory is recorded as a link, never descended into.
    out = io.BytesIO()
    stats = agent_backup.write_volume_tar(Path("/unused"), out, fs=fs)
    members = _tar_members(out.getvalue())
    assert members["escape"].issym() and members["escape"].linkname == "/etc"
    assert members["escape_file"].issym() and members["dirlink"].issym()
    assert "fifo" not in members and "dev" not in members and "sock" not in members
    assert "swapped" not in members
    assert "nested/inner.txt" in members and "ok.txt" in members
    assert not any(name.startswith("escape/") or name.startswith("dirlink/") for name in members)
    assert stats.skipped_special == 3 and stats.symlinks == 3 and stats.changed == 1

    race = FakeFs({"pipe": ("fifo_race",)})
    race.lstat = lambda parent, name: _st(stat.S_IFREG | 0o644, 5)  # type: ignore[method-assign]
    stats = agent_backup.write_volume_tar(Path("/unused"), io.BytesIO(), fs=race)
    assert stats.skipped_special == 1 and stats.files == 0


def test_volume_tar_pads_files_that_shrink(tmp_path: Path) -> None:
    class Shrinking(FakeFs):
        def open_file(self, parent, name):
            return io.BytesIO(b"abc"), _st(stat.S_IFREG | 0o644, 10)

    out = io.BytesIO()
    stats = agent_backup.write_volume_tar(Path("/unused"), out,
                                          fs=Shrinking({"f": ("file", b"abc")}))
    assert stats.changed == 1
    with tarfile.open(fileobj=io.BytesIO(out.getvalue()), mode="r:") as archive:
        assert archive.extractfile("f").read() == b"abc" + b"\0" * 7


def _can_symlink(tmp_path: Path) -> bool:
    try:
        os.symlink(tmp_path, tmp_path / "probe-link")
    except (OSError, NotImplementedError):
        return False
    (tmp_path / "probe-link").unlink()
    return True


def test_volume_tar_real_filesystem_symlinks(tmp_path: Path) -> None:
    if not _can_symlink(tmp_path):
        pytest.skip("symlinks are not available on this platform")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    root = tmp_path / "vol"
    root.mkdir()
    (root / "file.txt").write_text("ok")
    os.symlink(outside, root / "dir-link")
    os.symlink(outside / "secret.txt", root / "file-link")
    if hasattr(os, "mkfifo"):
        os.mkfifo(root / "fifo")
    out = io.BytesIO()
    stats = agent_backup.write_volume_tar(root, out)
    data = out.getvalue()
    members = _tar_members(data)
    assert members["dir-link"].issym() and members["file-link"].issym()
    assert b"secret" not in data.replace(b"secret.txt", b"")
    assert "fifo" not in members
    assert stats.skipped_special == (1 if hasattr(os, "mkfifo") else 0)
    # The volume root itself must not be a symlink.
    os.symlink(outside, tmp_path / "vol-link")
    with pytest.raises(agent_backup.BackupSourceError):
        agent_backup.write_volume_tar(tmp_path / "vol-link", io.BytesIO())


def test_exec_demuxer_and_frames() -> None:
    demux = agent_backup.ExecDemuxer(stderr_limit=4)
    stream = mux(1, b"hello") + mux(2, b"err-long") + mux(1, b" world")
    out = b"".join(demux.feed(stream[i:i + 3]) for i in range(0, len(stream), 3))
    assert out == b"hello world" and bytes(demux.stderr_tail) == b"long" and demux.pending == 0
    frames = list(agent_backup.data_frames(b"x" * (agent_backup.MAX_FRAME_BYTES + 5)))
    assert len(frames) == 2


# ----- update tracking helpers (Gate 18 S10) -------------------------------------------


def test_images_endpoint_and_container_image_id(tmp_path: Path) -> None:
    from mrk_control_plane.agent.docker_client import summarize_container

    fake = FakeDocker()
    image_id = "sha256:" + "a" * 64
    original = fake.handler

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == f"{API}/images/json":
            fake.seen.append(request)
            return httpx.Response(200, json=[
                {"Id": image_id, "RepoTags": ["nginx:1.27", "<none>:<none>"],
                 "RepoDigests": ["nginx@sha256:" + "b" * 64, "<none>@<none>"]},
                {"Id": "sha256:" + "c" * 64, "RepoTags": None, "RepoDigests": None},
                "junk",
            ])
        return original(request)

    fake.handler = handler  # type: ignore[method-assign]
    client = TestClient(make_agent(tmp_path, fake))
    assert client.get("/v1/docker/images").status_code == 401
    payload = signed(client, "GET", "/v1/docker/images").json()
    assert payload == {"items": [
        {"id": image_id, "repo_tags": ["nginx:1.27"],
         "repo_digests": ["nginx@sha256:" + "b" * 64]},
        {"id": "sha256:" + "c" * 64, "repo_tags": [], "repo_digests": []},
    ]}
    assert all(r.method == "GET" for r in fake.seen)

    summary = summarize_container(
        {"Id": WEB_ID, "Names": ["/web"], "Image": "nginx:1.27", "ImageID": image_id}, False, ()
    )
    assert summary["image_id"] == image_id
    assert summarize_container({"Id": WEB_ID}, False, ())["image_id"] is None
