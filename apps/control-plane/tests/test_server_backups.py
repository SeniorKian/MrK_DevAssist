"""Gate 18 S6 server & database backups (docs/31 §4)."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, unquote

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane import s3sigv4
from mrk_control_plane.agent import signing
from mrk_control_plane.backup import BackupError
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import host_agent, server_backups
from mrk_control_plane.modules import server_backups_dest as dest
from mrk_control_plane.modules import server_backups_s3 as s3mod
from mrk_control_plane.modules.server_backups_cron import CronError, parse_cron
from mrk_control_plane.modules.server_backups_crypto import (
    StreamEncryptor,
    decrypt_stream,
)
from mrk_control_plane.modules.server_backups_crypto import (
    main as decrypt_main,
)
from mrk_control_plane.netresolve import NetworkSettingsStore
from mrk_control_plane.secret_store import SecretStore

from .helpers import login_owner
from .test_agent_backup import KEY, PG_PASSWORD, FakeDocker, make_agent

KEY_TEXT = signing.encode_key(KEY)
S3_AKID = "AKIDEXAMPLE123"
S3_SECRET = "s3-secret-value-abcdef"  # noqa: S105 - test fixture
TEHRAN = "Asia/Tehran"


def ts(text: str) -> float:
    return datetime.fromisoformat(text).replace(tzinfo=UTC).timestamp()


# ----- cron ------------------------------------------------------------------------------


def test_cron_parser_fields_and_next_run() -> None:
    nightly = parse_cron("30 2 * * *")
    # 2026-11-08 00:00Z = 03:30 Tehran; next 02:30 Tehran = 2026-11-08 23:00Z.
    assert nightly.next_after(ts("2026-11-08T00:00:00"), TEHRAN) == ts("2026-11-08T23:00:00")
    assert nightly.next_after(ts("2026-11-08T00:00:00"), "UTC") == ts("2026-11-08T02:30:00")
    every15 = parse_cron("*/15 * * * *")
    assert every15.minutes == frozenset({0, 15, 30, 45})
    assert every15.next_after(ts("2026-11-08T10:15:00"), "UTC") == ts("2026-11-08T10:30:00")
    ranged = parse_cron("0 9-17/4 * * mon-fri")
    assert ranged.hours == frozenset({9, 13, 17}) and ranged.weekdays == frozenset(range(1, 6))
    # 2026-11-07 is a Saturday -> Monday 09:00 UTC.
    assert ranged.next_after(ts("2026-11-07T12:00:00"), "UTC") == ts("2026-11-09T09:00:00")
    assert parse_cron("0 0 * jan,JUL sun").months == frozenset({1, 7})
    assert parse_cron("0 0 * * 7").weekdays == frozenset({0})
    assert parse_cron("5/20 * * * *").minutes == frozenset({5, 25, 45})
    # Day-of-month OR day-of-week when both are restricted (Vixie semantics).
    either = parse_cron("0 0 1 * fri")
    assert either.next_after(ts("2026-11-02T00:00:00"), "UTC") == ts("2026-11-06T00:00:00")
    assert either.next_after(ts("2026-11-28T00:00:00"), "UTC") == ts("2026-12-01T00:00:00")
    leap = parse_cron("0 0 29 2 *")
    assert leap.next_after(ts("2026-03-01T00:00:00"), "UTC") == ts("2028-02-29T00:00:00")
    for bad in ("", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *",
                "* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *", "0 0 30 2 *",
                "1,,2 * * * *", "* * * * * *", 12345):
        with pytest.raises(CronError):
            parse_cron(bad)


def test_cron_dst_gap_is_skipped() -> None:
    schedule = parse_cron("30 2 * * *")
    # Europe/Berlin springs forward 2026-03-29 02:00 -> 03:00: no 02:30 that day.
    after = ts("2026-03-28T12:00:00")
    assert schedule.next_after(after, "Europe/Berlin") == ts("2026-03-30T00:30:00")


# ----- retention -------------------------------------------------------------------------


def test_select_expired() -> None:
    now = ts("2026-11-08T00:00:00")
    day = 86400
    runs = [(f"r{i}", int(now - i * day)) for i in range(10)]
    assert server_backups.select_expired(runs, None, None, now) == []
    assert server_backups.select_expired(runs, 3, None, now) == [f"r{i}" for i in range(3, 10)]
    assert server_backups.select_expired(runs, None, 5, now) == [f"r{i}" for i in range(6, 10)]
    # Union: newest 2 OR younger than 4 days.
    assert server_backups.select_expired(runs, 2, 4, now) == [f"r{i}" for i in range(5, 10)]
    # The newest run always survives even if keep_days excludes everything.
    old = [("a", int(now - 100 * day)), ("b", int(now - 200 * day))]
    assert server_backups.select_expired(old, None, 7, now) == ["b"]
    assert server_backups.validate_retention({"keep_last": 0, "keep_days": 7}) == {
        "keep_last": None, "keep_days": 7}
    for bad in ({"keep_last": -1}, {"keep_days": 4000}, {"keep_last": True}, {"x": 1}, []):
        with pytest.raises(server_backups.BackupApiError):
            server_backups.validate_retention(bad)


def test_source_validation() -> None:
    assert server_backups.validate_source({"kind": "volume", "volume": "app_data"}) == {
        "kind": "volume", "volume": "app_data"}
    assert server_backups.validate_source(
        {"kind": "postgres", "container": "app-db", "database": ""}
    ) == {"kind": "postgres", "container": "app-db", "database": None}
    for bad in (
        {"kind": "volume", "volume": "../etc"},
        {"kind": "postgres", "container": "a/b"},
        {"kind": "postgres", "container": "db", "database": "x;drop"},
        {"kind": "redis", "container": "cache", "database": "0"},
        {"kind": "shell", "container": "db"},
        {"kind": "postgres", "container": "db", "command": "sh"},
    ):
        with pytest.raises(server_backups.BackupApiError):
            server_backups.validate_source(bad)


# ----- destination validation ----------------------------------------------------------------


def test_destination_validation(tmp_path: Path) -> None:
    data = tmp_path / "data"
    (data / "control-plane").mkdir(parents=True)
    network = NetworkSettingsStore(data)

    def check(kind, config, secret=None, **kw):
        return dest.validate(kind, config, secret, data_dir=data, network=network, **kw)

    default = check("local", {})
    assert Path(default.config["path"]) == (data / dest.LOCAL_DEFAULT).resolve()
    assert check("local", {"path": str(data / "backups-x")}).config["path"].endswith("backups-x")
    for path, code in (
        (str(tmp_path / "elsewhere"), "path_outside_data"),
        (str(data / "control-plane" / "x"), "path_forbidden"),
        (str(data / "modules" / "s3" / "buckets"), "path_forbidden"),
        (str(data), "path_forbidden"),
        (str(data / "a" / ".." / ".." / "x"), "invalid_path"),
        ("relative/dir", "invalid_path"),
    ):
        with pytest.raises(dest.DestinationError) as error:
            check("local", {"path": path})
        assert error.value.code == code, path

    good = {"endpoint": "https://s3.ir-thr-at1.arvanstorage.ir/", "bucket": "my-backups",
            "region": "ir-thr-at1", "prefix": "/srv/db/", "access_key_id": S3_AKID}
    result = check("s3", good, {"secret_access_key": S3_SECRET})
    assert result.config == {
        "endpoint": "https://s3.ir-thr-at1.arvanstorage.ir", "bucket": "my-backups",
        "region": "ir-thr-at1", "prefix": "srv/db/", "path_style": True,
        "access_key_id": S3_AKID, "proxy_id": None,
    }
    assert result.secret == S3_SECRET
    for change, code in (
        ({"endpoint": "ftp://x.example.com"}, "invalid_endpoint"),
        ({"endpoint": "https://user:pw@x.example.com"}, "invalid_endpoint"),
        ({"endpoint": "https://x.example.com/path"}, "invalid_endpoint"),
        ({"bucket": "UPPER"}, "invalid_bucket"),
        ({"bucket": "192.168.1.1"}, "invalid_bucket"),
        ({"prefix": "a/../b"}, "invalid_prefix"),
        ({"access_key_id": "has space"}, "invalid_access_key"),
        ({"proxy_id": "nope"}, "proxy_not_found"),
        ({"path_style": "yes"}, "invalid_destination"),
    ):
        with pytest.raises(dest.DestinationError) as error:
            check("s3", {**good, **change}, {"secret_access_key": S3_SECRET})
        assert error.value.code == code, change
    with pytest.raises(dest.DestinationError) as error:
        check("s3", good)
    assert error.value.code == "secret_required"
    # PATCH: same endpoint keeps the stored secret; a new endpoint needs it again.
    assert check("s3", {"prefix": "x"}, previous=result.config, has_secret=True).secret is None
    with pytest.raises(dest.DestinationError) as error:
        check("s3", {"endpoint": "https://evil.example.com"}, previous=result.config,
              has_secret=True)
    assert error.value.code == "secret_required"
    mrk = check("mrk_s3", {"bucket": "backups", "access_key_id": "MRKAAAA"}, known_mrk_key=True)
    assert mrk.config == {"bucket": "backups", "prefix": "", "access_key_id": "MRKAAAA"}
    with pytest.raises(dest.DestinationError):
        check("mrk_s3", {"bucket": "backups", "access_key_id": "MRKAAAA"})
    with pytest.raises(dest.DestinationError):
        check("ftp", {})


# ----- encryption + decrypt CLI ------------------------------------------------------------


def _encrypt(payload: bytes, passphrase: str, compression: str, key_ref: str = "ref") -> bytes:
    encryptor = StreamEncryptor(
        passphrase, backup_id="srv-test", source={"kind": "volume", "volume": "v"},
        payload_name="v.tar", compression=compression, job_id="job1", key_ref=key_ref,
    )
    out = bytearray()
    for offset in range(0, len(payload), 300_000):
        out += encryptor.update(payload[offset:offset + 300_000])
    out += encryptor.finish()
    assert encryptor.artifact_bytes == len(out)
    assert encryptor.artifact_digest.hexdigest() == hashlib.sha256(out).hexdigest()
    return bytes(out)


def test_encryption_round_trip_and_decrypt_cli(tmp_path: Path) -> None:
    passphrase = "p" * 43
    payload = os.urandom(5 * 1024 * 1024) + b"tail"  # crosses the 4 MiB record size
    artifact = _encrypt(payload, passphrase, "none")
    assert payload[:4096] not in artifact
    out = io.BytesIO()
    info = decrypt_stream(io.BytesIO(artifact), out, passphrase)
    assert out.getvalue() == payload and info["trailer"]["source_bytes"] == len(payload)
    assert info["kind"] == "server-backup" and info["payload_name"] == "v.tar"

    text = (b"line of sql\n" * 50_000)
    gz = _encrypt(text, passphrase, "gzip")
    assert len(gz) < len(text) // 10
    raw = io.BytesIO()
    decrypt_stream(io.BytesIO(gz), raw, passphrase)
    assert gzip.decompress(raw.getvalue()) == text

    # CLI: passphrase file, decompress, and --data-dir via the job's key_ref.
    (tmp_path / "a.mrkbak").write_bytes(gz)
    (tmp_path / "key.txt").write_text(passphrase + "\n")
    assert decrypt_main([str(tmp_path / "a.mrkbak"), "-o", str(tmp_path / "out.sql"),
                         "--passphrase-file", str(tmp_path / "key.txt"), "--decompress"]) == 0
    assert (tmp_path / "out.sql").read_bytes() == text
    data_dir = tmp_path / "data"
    store = SecretStore(data_dir)
    reference, _ = store.replace(None, {"passphrase": passphrase})
    (tmp_path / "b.mrkbak").write_bytes(_encrypt(b"abc" * 1000, passphrase, "none", reference))
    assert decrypt_main([str(tmp_path / "b.mrkbak"), "-o", str(tmp_path / "b.out"),
                         "--data-dir", str(data_dir)]) == 0
    assert (tmp_path / "b.out").read_bytes() == b"abc" * 1000
    assert decrypt_main([str(tmp_path / "b.mrkbak"), "--info"]) == 0

    # Tampering, truncation and a wrong key are detected; no partial output survives.
    tampered = bytearray(artifact)
    tampered[len(tampered) // 2] ^= 1
    (tmp_path / "bad.mrkbak").write_bytes(bytes(tampered))
    with pytest.raises(BackupError) as error:
        decrypt_main([str(tmp_path / "bad.mrkbak"), "-o", str(tmp_path / "bad.out"),
                      "--passphrase-file", str(tmp_path / "key.txt")])
    assert error.value.error_code == "authentication_failed"
    assert not list(tmp_path.glob("*bad.out*"))
    for broken in (artifact[:-10], artifact[: len(artifact) // 3]):
        with pytest.raises(BackupError):
            decrypt_stream(io.BytesIO(broken), io.BytesIO(), passphrase)
    with pytest.raises(BackupError):
        decrypt_stream(io.BytesIO(artifact), io.BytesIO(), "q" * 43)


# ----- SigV4 --------------------------------------------------------------------------------


def test_fallback_signer_matches_shared_verifier() -> None:
    url = "https://s3.example.com/bucket/dir/a%20b%2Bc.mrkbak?partNumber=2&uploadId=x%2By"
    body = b"payload"
    digest = hashlib.sha256(body).hexdigest()
    now = ts("2026-11-08T10:00:00")
    for signer in (s3mod.sign_request, s3mod.sign_request_fallback):
        headers = signer("PUT", url, {"Content-Type": "application/octet-stream"}, digest,
                         S3_AKID, S3_SECRET, "us-east-1", now=now)
        verified = s3sigv4.verify_request(
            "PUT", "/bucket/dir/a%20b%2Bc.mrkbak", "partNumber=2&uploadId=x%2By",
            list(headers.items()), lambda akid: S3_SECRET if akid == S3_AKID else None,
            now=datetime.fromtimestamp(now, UTC),
        )
        assert verified is not None and verified.access_key_id == S3_AKID
    assert s3mod.encode_key("a b/c+d") == "a%20b/c%2Bd"


# ----- fake S3 -------------------------------------------------------------------------------


class FakeS3:
    """Path-style S3 double that verifies every request's SigV4 signature."""

    def __init__(self, bucket: str = "backups") -> None:
        self.bucket = bucket
        self.objects: dict[str, bytes] = {}
        self.uploads: dict[str, dict[int, bytes]] = {}
        self.calls: list[str] = []
        self.secret = S3_SECRET
        self.hosts: set[str] = set()

    @staticmethod
    def _error(status: int, code: str) -> httpx.Response:
        return httpx.Response(status, content=f"<Error><Code>{code}</Code></Error>".encode())

    def handler(self, request: httpx.Request) -> httpx.Response:
        raw = request.url.raw_path.decode()
        path, _, query = raw.partition("?")
        self.hosts.add(request.headers.get("host", ""))
        try:
            s3sigv4.verify_request(
                request.method, path, query, list(request.headers.items()),
                lambda akid: self.secret if akid == S3_AKID else None,
            )
        except s3sigv4.SigV4Error:
            return self._error(403, "SignatureDoesNotMatch")
        content = request.content
        declared = request.headers.get("x-amz-content-sha256")
        if declared != hashlib.sha256(content).hexdigest():
            return self._error(400, "XAmzContentSHA256Mismatch")
        params = {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}
        segments = path.lstrip("/").split("/", 1)
        if segments[0] != self.bucket:
            return self._error(404, "NoSuchBucket")
        key = unquote(segments[1]) if len(segments) > 1 else ""
        method = request.method
        if method == "GET" and not key:
            self.calls.append("list")
            prefix = params.get("prefix", "")
            items = "".join(
                f"<Contents><Key>{k}</Key><Size>{len(v)}</Size></Contents>"
                for k, v in sorted(self.objects.items()) if k.startswith(prefix)
            )
            return httpx.Response(200, content=f"<ListBucketResult>{items}</ListBucketResult>"
                                  .encode())
        if method == "POST" and "uploads" in params:
            upload_id = f"up{len(self.uploads) + 1}"
            self.uploads[upload_id] = {}
            self.calls.append("create")
            return httpx.Response(
                200, content=f"<InitiateMultipartUploadResult><UploadId>{upload_id}</UploadId>"
                             "</InitiateMultipartUploadResult>".encode())
        if method == "PUT" and "partNumber" in params:
            self.uploads[params["uploadId"]][int(params["partNumber"])] = content
            self.calls.append("part")
            return httpx.Response(200, headers={"ETag": f'"{hashlib.md5(content).hexdigest()}"'})  # noqa: S324
        if method == "POST" and "uploadId" in params:
            parts = self.uploads.pop(params["uploadId"])
            numbers = [int(n) for n in re.findall(r"<PartNumber>(\d+)</PartNumber>",
                                                  content.decode())]
            assert numbers == sorted(parts)
            self.objects[key] = b"".join(parts[n] for n in numbers)
            self.calls.append("complete")
            return httpx.Response(200, content=b"<CompleteMultipartUploadResult/>")
        if method == "DELETE" and "uploadId" in params:
            self.uploads.pop(params["uploadId"], None)
            self.calls.append("abort")
            return httpx.Response(204)
        if method == "PUT":
            self.objects[key] = content
            self.calls.append("put")
            return httpx.Response(200, headers={"ETag": '"x"'})
        if method == "GET":
            if key not in self.objects:
                return self._error(404, "NoSuchKey")
            return httpx.Response(200, content=self.objects[key])
        if method == "DELETE":
            self.objects.pop(key, None)
            self.calls.append("delete")
            return httpx.Response(204)
        return self._error(400, "InvalidRequest")


# ----- end-to-end through the API -------------------------------------------------------------


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    fake = FakeDocker()
    volumes = tmp_path / "volumes"
    data = volumes / "app_data" / "_data"
    (data / "nested").mkdir(parents=True)
    (data / "readme.txt").write_text("volume file")
    (data / "nested" / "blob.bin").write_bytes(os.urandom(600_000))
    agent = make_agent(tmp_path / "agent", fake, volumes)

    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return await httpx.ASGITransport(app=agent).handle_async_request(request)

    s3 = FakeS3()
    monkeypatch.setattr(host_agent, "TRANSPORT_FACTORY", Transport)
    monkeypatch.delenv("MRK_AGENT_URL", raising=False)
    monkeypatch.delenv("MRK_AGENT_KEY_FILE", raising=False)
    monkeypatch.setattr(dest, "S3_TRANSPORT", httpx.MockTransport(s3.handler))
    monkeypatch.setattr(dest, "S3_RESOLVER", lambda host, port, dns: ["93.184.216.34"])
    monkeypatch.setattr(dest, "PART_SIZE", 64 * 1024)
    app = create_app(Settings.for_test(tmp_path / "cp"))
    events: list = []
    with TestClient(app) as client:
        async def collect(event) -> None:
            events.append(event)

        app.state.events.subscribe(collect)
        csrf = str(login_owner(client)["csrf_token"])
        headers = {"X-CSRF-Token": csrf}
        paired = client.put("/api/v1/agent/config", headers=headers,
                            json={"url": "http://mrk-agent:7070", "key": KEY_TEXT})
        assert paired.status_code == 200, paired.text
        yield {"client": client, "headers": headers, "fake": fake, "s3": s3, "events": events,
               "data_dir": tmp_path / "cp", "app": app}


def wait_runs(client: TestClient, job_id: str, count: int = 1, timeout: float = 30.0) -> list:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        items = client.get(f"/api/v1/server-backups/runs?job_id={job_id}").json()["items"]
        if len(items) >= count and all(item["state"] != "running" for item in items):
            return items
        time.sleep(0.05)
    raise AssertionError("backup did not finish")


def make_job(client, headers, name, source, destination_id, **extra):
    body = {"name": name, "source": source, "destination_id": destination_id,
            "schedule": "0 3 * * *", **extra}
    response = client.post("/api/v1/server-backups/jobs", headers=headers, json=body)
    assert response.status_code == 201, response.text
    return response.json()


def test_postgres_dump_to_local_destination(env) -> None:
    client, headers, fake = env["client"], env["headers"], env["fake"]
    base = "/api/v1/server-backups"
    created = client.post(f"{base}/destinations", headers=headers,
                          json={"name": "Local disk", "kind": "local", "config": {}})
    assert created.status_code == 201, created.text
    destination = created.json()
    assert destination["config"]["path"].endswith(os.path.join("server-backups", "local"))
    test = client.post(f"{base}/destinations/{destination['id']}/test", headers=headers).json()
    assert test["ok"] is True and test["latency_ms"] >= 0

    sources = client.get(f"{base}/sources").json()
    by_name = {item["name"]: item for item in sources["databases"]}
    assert by_name["dokploy-postgres"]["note"] and by_name["app-db"]["note"] is None
    assert PG_PASSWORD not in json.dumps(sources)

    job = make_job(client, headers, "App DB", {"kind": "postgres", "container": "app-db"},
                   destination["id"], retention={"keep_last": 2})
    assert job["next_run_at"] > time.time() and job["note"] is None
    protected = make_job(client, headers, "Dokploy DB",
                         {"kind": "postgres", "container": "dokploy-postgres"}, destination["id"])
    assert "Dokploy" in protected["note"]

    run = client.post(f"{base}/jobs/{job['id']}/run", headers=headers)
    assert run.status_code == 202
    runs = wait_runs(client, job["id"])
    assert runs[0]["id"] == run.json()["run_id"] and runs[0]["state"] == "succeeded", runs
    record = runs[0]
    assert record["source_bytes"] == len(fake.dump_stdout) and record["bytes"] > 0
    assert record["details"]["compression"] == "none"

    downloaded = client.get(f"{base}/runs/{record['id']}/download")
    assert downloaded.status_code == 200
    assert "attachment" in downloaded.headers["content-disposition"]
    assert hashlib.sha256(downloaded.content).hexdigest() == record["sha256"]
    assert fake.dump_stdout[:64] not in downloaded.content
    key = client.post(f"{base}/jobs/{job['id']}/key", headers=headers).json()
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(downloaded.content), out, key["passphrase"])
    assert out.getvalue() == fake.dump_stdout

    # Nothing secret in the database rows, the job key or the stored destination.
    stored = (env["data_dir"] / "control-plane" / "upstream-secrets.json").read_text()
    assert key["passphrase"] not in stored
    audit = client.get("/api/v1/audit-events?limit=200").json()
    actions = {item["action"] for item in audit.get("items", [])}
    assert {"server_backup.job.create", "server_backup.job.run", "server_backup.run",
            "server_backup.run.download", "server_backup.key.export"} <= actions
    assert key["passphrase"] not in json.dumps(audit)

    # A failing dump fails the run, publishes the event and leaves no partial file.
    fake.exit_code = 2
    failed_id = client.post(f"{base}/jobs/{job['id']}/run", headers=headers).json()["run_id"]
    runs = {item["id"]: item for item in wait_runs(client, job["id"], 2)}
    assert runs[failed_id]["state"] == "failed"
    assert runs[failed_id]["error_code"] == "dump_failed"
    root = Path(destination["config"]["path"])
    assert not [p for p in root.rglob("*") if p.name.endswith(".partial")]
    assert client.get(f"{base}/runs/{failed_id}/download").status_code == 409
    types = [event.type for event in env["events"] if event.module == "server_backups"]
    assert types[:2] == ["server_backup.succeeded", "server_backup.failed"]

    # Deleting a destination in use is refused; jobs must go first.
    in_use = client.request("DELETE", f"{base}/destinations/{destination['id']}",
                            headers=headers, json={"confirmation": "Local disk"})
    assert in_use.status_code == 409
    removed = client.request("DELETE", f"{base}/jobs/{job['id']}", headers=headers,
                             json={"confirmation": "App DB", "delete_artifacts": True})
    assert removed.status_code == 200
    assert not list(root.rglob("*.mrkbak")) or all(
        job["id"] not in str(path) for path in root.rglob("*.mrkbak"))


def test_volume_backup_to_s3_with_multipart_retention_and_download(env) -> None:
    client, headers, s3 = env["client"], env["headers"], env["s3"]
    base = "/api/v1/server-backups"
    body = {"name": "Arvan", "kind": "s3",
            "config": {"endpoint": "https://s3.example.com", "bucket": "backups",
                       "region": "us-east-1", "prefix": "prod", "access_key_id": S3_AKID},
            "secret": {"secret_access_key": S3_SECRET}}
    created = client.post(f"{base}/destinations", headers=headers, json=body)
    assert created.status_code == 201, created.text
    destination = created.json()
    assert destination["secret_configured"] is True
    assert S3_SECRET not in json.dumps(client.get(f"{base}/destinations").json())
    assert client.post(f"{base}/destinations/{destination['id']}/test",
                       headers=headers).json()["ok"] is True
    assert s3.hosts == {"s3.example.com"}

    job = make_job(client, headers, "Volume", {"kind": "volume", "volume": "app_data"},
                   destination["id"], retention={"keep_last": 1})
    first = second = None
    for _ in range(2):
        deadline = time.monotonic() + 30
        while True:  # the previous run may still be finishing (409 job_running)
            started = client.post(f"{base}/jobs/{job['id']}/run", headers=headers)
            if started.status_code != 409 or time.monotonic() > deadline:
                break
            time.sleep(0.05)
        run_id = started.json()["run_id"]
        first, second = second, run_id
        while time.monotonic() < deadline:
            items = wait_runs(client, job["id"])
            if any(item["id"] == run_id and item["state"] != "running" for item in items):
                break
            time.sleep(0.05)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:  # retention runs right after the run is recorded
        runs = wait_runs(client, job["id"])
        if len(runs) == 1:
            break
        time.sleep(0.05)
    assert runs[0]["id"] == second and first not in {item["id"] for item in runs}
    # keep_last=1: the first artifact and its run row were removed after the second success.
    assert len(runs) == 1 and runs[0]["state"] == "succeeded", runs
    assert "part" in s3.calls and "complete" in s3.calls and "delete" in s3.calls
    keys = list(s3.objects)
    assert keys == [runs[0]["object_key"]] and keys[0].startswith(f"prod/{job['id']}/")
    assert runs[0]["details"]["stats"]["files"] == 2

    downloaded = client.get(f"{base}/runs/{runs[0]['id']}/download")
    assert downloaded.status_code == 200 and downloaded.content == s3.objects[keys[0]]
    passphrase = client.post(f"{base}/jobs/{job['id']}/key", headers=headers).json()["passphrase"]
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(downloaded.content), out, passphrase, decompress=True)
    with tarfile.open(fileobj=io.BytesIO(out.getvalue()), mode="r:") as archive:
        assert archive.extractfile("readme.txt").read() == b"volume file"

    # Wrong credentials surface as a stable code; a moved endpoint needs the secret again.
    s3.secret = "other"  # noqa: S105
    failed = client.post(f"{base}/destinations/{destination['id']}/test", headers=headers).json()
    assert failed == {"ok": False, "latency_ms": failed["latency_ms"],
                      "error_code": "s3_auth_failed"}
    moved = client.patch(f"{base}/destinations/{destination['id']}", headers=headers,
                         json={"config": {"endpoint": "https://other.example.com"}})
    assert moved.json()["error"]["code"] == "secret_required"
    entries = client.get("/api/v1/settings/outbound-services").json()["items"]
    assert any(item["kind"] == "server_backup_destination" for item in entries)


def test_mrk_s3_destination_and_scheduler(env) -> None:
    client, headers, s3 = env["client"], env["headers"], env["s3"]
    base = "/api/v1/server-backups"
    created = client.post(f"{base}/destinations", headers=headers, json={
        "name": "Native", "kind": "mrk_s3",
        "config": {"bucket": "backups", "access_key_id": S3_AKID},
        "secret": {"secret_access_key": S3_SECRET}})
    assert created.status_code == 201, created.text
    destination = created.json()
    assert destination["config"]["endpoint"] == "http://127.0.0.1:9000"
    assert client.post(f"{base}/destinations/{destination['id']}/test",
                       headers=headers).json()["ok"] is True
    assert "127.0.0.1:9000" in s3.hosts

    settings = client.put(f"{base}/settings", headers=headers, json={"timezone": "UTC"})
    assert settings.json() == {"timezone": "UTC"}
    assert client.put(f"{base}/settings", headers=headers,
                      json={"timezone": "Mars/Base"}).status_code == 422
    job = make_job(client, headers, "Redis", {"kind": "redis", "container": "cache"},
                   destination["id"])
    service = server_backups.ACTIVE_SERVICE
    assert service is not None
    started = client.portal.call(service.tick, float(job["next_run_at"]) + 1)
    assert len(started) == 1
    runs = wait_runs(client, job["id"])
    assert runs[0]["trigger"] == "schedule" and runs[0]["state"] == "succeeded", runs
    assert client.get(f"{base}/jobs").json()["items"][0]["next_run_at"] > job["next_run_at"]
    # Disabled jobs are never scheduled.
    client.patch(f"{base}/jobs/{job['id']}", headers=headers, json={"enabled": False})
    assert client.portal.call(service.tick, time.time() + 10 * 86400) == []
    bad = client.patch(f"{base}/jobs/{job['id']}", headers=headers,
                       json={"schedule": "* * * * x"})
    assert bad.json()["error"]["code"] == "invalid_schedule"


def _login_as(client: TestClient, owner_headers, username: str, role: str) -> dict:
    password = f"a-long-{role}-password-123"
    created = client.post("/api/v1/users", headers=owner_headers,
                          json={"username": username, "password": password, "role": role})
    assert created.status_code == 201, created.text
    client.cookies.clear()
    session = client.post("/api/v1/auth/login",
                          json={"username": username, "password": password}).json()
    return {"X-CSRF-Token": str(session["csrf_token"])}


def test_rbac(env) -> None:
    client, owner = env["client"], env["headers"]
    base = "/api/v1/server-backups"
    destination = client.post(f"{base}/destinations", headers=owner,
                              json={"name": "L", "kind": "local", "config": {}}).json()
    job = make_job(client, owner, "J", {"kind": "volume", "volume": "app_data"},
                   destination["id"])
    assert client.post(f"{base}/destinations", json={"name": "x", "kind": "local"}).status_code \
        == 403  # CSRF
    owner_cookies = dict(client.cookies)

    for role, can_read, can_write in (("viewer", False, False), ("developer", False, False),
                                      ("operator", True, False), ("admin", True, True)):
        client.cookies.clear()
        client.cookies.update(owner_cookies)
        headers = _login_as(client, owner, f"user-{role}", role)
        reads = [client.get(f"{base}/{path}").status_code
                 for path in ("destinations", "jobs", "runs", "settings")]
        assert all((code == 200) == can_read for code in reads), (role, reads)
        if not can_read:
            assert set(reads) == {403}
        writes = [
            client.post(f"{base}/jobs/{job['id']}/run", headers=headers).status_code,
            client.post(f"{base}/jobs/{job['id']}/key", headers=headers).status_code,
            client.post(f"{base}/destinations/{destination['id']}/test",
                        headers=headers).status_code,
            client.put(f"{base}/settings", headers=headers,
                       json={"timezone": "Asia/Tehran"}).status_code,
        ]
        if can_write:
            assert writes[0] in {202, 409} and writes[1:] == [200, 200, 200], (role, writes)
        else:
            assert set(writes) == {403}, (role, writes)
        if job["id"]:
            wait_runs(client, job["id"], 0) if can_read else None
