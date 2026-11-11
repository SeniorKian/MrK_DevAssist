"""Gate 18 S3 module (control plane): settings, buckets, links, identities, file manager."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.auth import ROLE_PERMISSIONS
from mrk_control_plane.config import Settings
from mrk_control_plane.database import Database
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import s3 as s3_module
from mrk_control_plane.modules import s3_client
from mrk_control_plane.modules.s3_policy import (
    PolicyError,
    bucket_name_error,
    template_policy,
    validate_policy,
)
from mrk_control_plane.modules.s3_store import PANEL_SECRET_REF
from sqlalchemy import inspect

from .helpers import login_owner

try:  # the engine's verifier, when the shared module is present
    from mrk_control_plane import s3sigv4
except ImportError:  # pragma: no cover - engine agent not merged yet
    s3sigv4 = None  # type: ignore[assignment]

API = "/api/v1/s3"
AUTH_RE = re.compile(
    r"^AWS4-HMAC-SHA256 Credential=(MRK[A-Z0-9]{17})/\d{8}/[a-z0-9-]+/s3/aws4_request, "
    r"SignedHeaders=[a-z0-9;-]+, Signature=[0-9a-f]{64}$"
)


class FakeEngine:
    """In-memory S3 engine + admin API that verifies every S3 request's SigV4 signature."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.objects: dict[tuple[str, str], dict[str, Any]] = {}
        self.uploads: dict[str, dict[str, Any]] = {}
        self.calls: list[tuple[str, str, str]] = []
        self.stats_override: dict[str, int] = {}
        self.ensured: list[str] = []
        self.deleted: list[tuple[str, str]] = []
        self.down = False

    def panel_secret(self, akid: str) -> str | None:
        assert s3_module.ACTIVE_STORE is not None
        panel_akid, secret = s3_module.ACTIVE_STORE.panel_credentials()
        return secret if akid == panel_akid else None

    def _error(self, status: int, code: str) -> httpx.Response:
        body = f"<?xml version='1.0'?><Error><Code>{code}</Code><Message>{code}</Message></Error>"
        return httpx.Response(
            status, content=body.encode(), headers={"content-type": "application/xml"}
        )

    async def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("refused", request=request)
        if request.url.port == 9001:
            return self.admin(request)
        return await self.s3(request)

    def admin(self, request: httpx.Request) -> httpx.Response:
        token = (self.data_dir / "modules" / "s3" / "admin.token").read_text().strip()
        if request.headers.get("x-mrk-admin-token") != token:
            return httpx.Response(401)
        path = request.url.path
        if path == "/admin/health":
            return httpx.Response(200, json={"ok": True})
        match = re.fullmatch(
            r"/admin/buckets/([^/]+)(/stats|/ensure|/lifecycle|/lifecycle/preview)?", path
        )
        assert match, path
        bucket, action = match.group(1), match.group(2)
        if action == "/lifecycle":
            return httpx.Response(
                200,
                json={
                    "rules": [{"id": "logs", "status": "Enabled", "expiration_days": 7}],
                    "versioning": None,
                    "last_run": None,
                    "supported": True,
                },
            )
        if action == "/lifecycle/preview":
            self.calls.append(("POST", bucket, "lifecycle-preview"))
            return httpx.Response(
                200, json={"objects": 3, "bytes": 30, "dry_run": True, "sample": []}
            )
        if action == "/stats":
            items = [obj for (b, _k), obj in self.objects.items() if b == bucket]
            count = self.stats_override.get(bucket, len(items))
            return httpx.Response(
                200, json={"objects": count, "bytes": sum(len(o["data"]) for o in items)}
            )
        if action == "/ensure":
            self.ensured.append(bucket)
            return httpx.Response(200, json={"ok": True})
        force = request.url.params.get("force")
        if force != "1" and (
            self.stats_override.get(bucket) or any(b == bucket for b, _k in self.objects)
        ):
            return httpx.Response(409, json={"error": "BucketNotEmpty"})
        self.deleted.append((bucket, force or "0"))
        for item in [k for k in self.objects if k[0] == bucket]:
            del self.objects[item]
        return httpx.Response(204)

    async def s3(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        assert AUTH_RE.fullmatch(auth), auth
        assert request.headers.get("x-amz-date")
        assert request.headers.get("x-amz-content-sha256")
        raw = request.url.raw_path.decode("ascii")
        raw_path, _, raw_query = raw.partition("?")
        if s3sigv4 is not None:
            s3sigv4.verify_request(
                request.method,
                raw_path,
                raw_query,
                list(request.headers.items()),
                self.panel_secret,
                region="us-east-1",
            )
        body = await request.aread()
        sha = request.headers["x-amz-content-sha256"]
        if sha != "UNSIGNED-PAYLOAD":
            assert sha == hashlib.sha256(body).hexdigest()
        segments = raw_path.lstrip("/").split("/", 1)
        bucket = unquote(segments[0])
        key = unquote(segments[1]) if len(segments) > 1 else None
        params = dict(request.url.params)
        method = request.method
        self.calls.append((method, bucket, key or ""))
        if key is None and method == "GET":
            return self.list(bucket, params)
        assert key is not None
        if method == "POST" and "uploads" in params:
            upload_id = f"up{len(self.uploads) + 1}"
            self.uploads[upload_id] = {"parts": {}, "type": request.headers.get("content-type")}
            return httpx.Response(
                200,
                content=(
                    "<InitiateMultipartUploadResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>"
                    f"<Bucket>{bucket}</Bucket><Key>{key}</Key><UploadId>{upload_id}</UploadId>"
                    "</InitiateMultipartUploadResult>"
                ).encode(),
            )
        if method == "PUT" and "uploadId" in params:
            assert int(request.headers["content-length"]) == len(body)
            etag = hashlib.md5(body).hexdigest()  # noqa: S324 - S3 ETag
            self.uploads[params["uploadId"]]["parts"][int(params["partNumber"])] = (body, etag)
            return httpx.Response(200, headers={"etag": f'"{etag}"'})
        if method == "POST" and "uploadId" in params:
            upload = self.uploads.pop(params["uploadId"])
            data = b"".join(upload["parts"][n][0] for n in sorted(upload["parts"]))
            self.objects[(bucket, key)] = {
                "data": data,
                "type": upload["type"] or "binary/octet-stream",
                "etag": f"multi-{len(upload['parts'])}",
            }
            return httpx.Response(
                200,
                content=(
                    '<CompleteMultipartUploadResult><ETag>"multi-'
                    f'{len(upload["parts"])}"</ETag></CompleteMultipartUploadResult>'
                ).encode(),
            )
        if method == "DELETE" and "uploadId" in params:
            self.uploads.pop(params["uploadId"], None)
            return httpx.Response(204)
        if method == "PUT" and "x-amz-copy-source" in request.headers:
            source = unquote(request.headers["x-amz-copy-source"]).lstrip("/").split("/", 1)
            original = self.objects.get((source[0], source[1]))
            if original is None:
                return self._error(404, "NoSuchKey")
            self.objects[(bucket, key)] = dict(original)
            return httpx.Response(
                200, content=b"<CopyObjectResult><ETag>x</ETag></CopyObjectResult>"
            )
        if method == "PUT":
            etag = hashlib.md5(body).hexdigest()  # noqa: S324 - S3 ETag
            self.objects[(bucket, key)] = {
                "data": body,
                "type": request.headers.get("content-type"),
                "etag": etag,
            }
            return httpx.Response(200, headers={"etag": f'"{etag}"'})
        item = self.objects.get((bucket, key))
        if method == "DELETE":
            self.objects.pop((bucket, key), None)
            return httpx.Response(204)
        if item is None:
            return self._error(404, "NoSuchKey")
        headers = {
            "etag": f'"{item["etag"]}"',
            "content-type": item["type"] or "binary/octet-stream",
            "content-length": str(len(item["data"])),
        }
        if method == "HEAD":
            return httpx.Response(200, headers=headers)
        return httpx.Response(200, headers=headers, content=item["data"])

    def list(self, bucket: str, params: dict[str, str]) -> httpx.Response:
        assert params.get("list-type") == "2"
        prefix = params.get("prefix", "")
        delimiter = params.get("delimiter", "")
        keys = sorted(k for b, k in self.objects if b == bucket and k.startswith(prefix))
        contents, prefixes = [], []
        for key in keys:
            rest = key[len(prefix) :]
            if delimiter and delimiter in rest:
                common = prefix + rest.split(delimiter, 1)[0] + delimiter
                if common not in prefixes:
                    prefixes.append(common)
            else:
                contents.append(key)
        url = params.get("encoding-type") == "url"

        def enc(value: str) -> str:
            return quote(value, safe="/") if url else value

        xml = ["<ListBucketResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>"]
        if url:
            xml.append("<EncodingType>url</EncodingType>")
        xml.append("<IsTruncated>false</IsTruncated>")
        for key in contents:
            item = self.objects[(bucket, key)]
            xml.append(
                f"<Contents><Key>{enc(key)}</Key><Size>{len(item['data'])}</Size>"
                f'<ETag>"{item["etag"]}"</ETag>'
                "<LastModified>2026-11-08T00:00:00.000Z</LastModified></Contents>"
            )
        for common in prefixes:
            xml.append(f"<CommonPrefixes><Prefix>{enc(common)}</Prefix></CommonPrefixes>")
        xml.append("</ListBucketResult>")
        return httpx.Response(200, content="".join(xml).encode())


@pytest.fixture
def links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "links"
    (root / "files" / "photos").mkdir(parents=True)
    (root / "media").mkdir()
    (root / "files" / "keep.txt").write_text("host file")
    monkeypatch.setenv("MRK_S3_LINKS_ROOT", str(root))
    return root


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, links: Path) -> FakeEngine:
    fake = FakeEngine(tmp_path / "cp")
    monkeypatch.setattr(s3_client, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(fake.handler))
    return fake


@pytest.fixture
def client(tmp_path: Path, engine: FakeEngine) -> Any:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as test_client:
        yield test_client


def owner(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}


def make_bucket(client: TestClient, headers: dict[str, str], name: str, **extra: Any) -> Any:
    return client.post(f"{API}/buckets", headers=headers, json={"name": name, **extra})


def snapshot(tmp_path: Path) -> dict[str, Any]:
    return json.loads((tmp_path / "cp" / "modules" / "s3" / "config.json").read_text("utf-8"))


# ---------------------------------------------------------------- unit


def test_bucket_name_rules() -> None:
    for good in ("abc", "my-bucket.v2", "a" * 63, "0backups9"):
        assert bucket_name_error(good) is None, good
    for bad in (
        "ab",
        "a" * 64,
        "Upper",
        "-start",
        "end-",
        "a..b",
        "192.168.1.1",
        "xn--abc",
        "foo-s3alias",
        "bar--ol-s3",
        "under_score",
        "admin",
        "mrk",
        "sp ace",
    ):
        assert bucket_name_error(bad) is not None, bad


def test_policy_templates_and_validation() -> None:
    backup = template_policy("backup_client", ["backups"])
    actions = {
        a
        for s in backup["Statement"]
        for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])
    }
    assert {"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"} <= actions
    assert validate_policy(backup) == backup
    for template in ("read_only", "read_write", "admin"):
        validate_policy(template_policy(template, ["a1b", "c2d"]))
    assert template_policy("admin", [])["Statement"][0]["Resource"] == "*"
    ok = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::backups",
                "Condition": {"StringLike": {"s3:prefix": ["dokploy/*"]}},
            },
            {
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::backups/*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }
    assert validate_policy(json.dumps(ok))["Statement"][1]["Effect"] == "Deny"
    bad_docs = [
        {"Version": "2012-10-17", "Statement": []},
        {"Version": "2001-01-01", "Statement": [ok["Statement"][0]]},
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ec2:Run", "Resource": "*"}],
        },
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:Nope", "Resource": "*"}],
        },
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:iam::x"}],
        },
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Principal": "*"}],
        },
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Maybe", "Action": "s3:*", "Resource": "*"}],
        },
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                    "Condition": {"Bogus": {"aws:SourceIp": "1.2.3.4"}},
                }
            ],
        },
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:Nope": "x"}},
                }
            ],
        },
    ]
    for document in bad_docs:
        with pytest.raises(PolicyError):
            validate_policy(document)


def test_signer_matches_botocore() -> None:
    botocore = pytest.importorskip("botocore")
    from botocore.auth import S3SigV4Auth, S3SigV4QueryAuth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    del botocore
    moment = dt.datetime(2026, 11, 8, 12, 0, 0, tzinfo=dt.UTC)
    creds = Credentials("MRKAAAAAAAAAAAAAAAAA", "s" * 40)
    key = "dir with space/ünï+code~.txt"
    url, headers = s3_client.sign_headers(
        method="GET",
        endpoint="http://127.0.0.1:9000",
        path=s3_client.object_path("bkt", key),
        params=[("list-type", "2"), ("prefix", "a b/")],
        access_key=creds.access_key,
        secret=creds.secret_key,
        region="us-east-1",
        now=moment,
    )
    request = AWSRequest(
        method="GET",
        url=url,
        headers={"x-amz-date": headers["x-amz-date"], "x-amz-content-sha256": "UNSIGNED-PAYLOAD"},
    )
    signer = S3SigV4Auth(creds, "s3", "us-east-1")
    signer._timestamp = lambda: headers["x-amz-date"]  # noqa: SLF001 - pin the clock
    request.context["timestamp"] = headers["x-amz-date"]
    canonical = signer.canonical_request(request)
    string_to_sign = signer.string_to_sign(request, canonical)
    expected = signer.signature(string_to_sign, request)
    assert headers["Authorization"].endswith(f"Signature={expected}")

    presigned = s3_client.presign_url(
        method="GET",
        endpoint="https://s3.example.com",
        bucket="bkt",
        key=key,
        access_key=creds.access_key,
        secret=creds.secret_key,
        region="us-east-1",
        expires_seconds=600,
        now=moment,
    )
    parts = urlsplit(presigned)
    query_signer = S3SigV4QueryAuth(creds, "s3", "us-east-1", expires=600)
    base = presigned.split("&X-Amz-Signature=")[0]
    qrequest = AWSRequest(method="GET", url=base)
    qrequest.context["timestamp"] = moment.strftime("%Y%m%dT%H%M%SZ")
    canonical = query_signer.canonical_request(qrequest)
    expected = query_signer.signature(query_signer.string_to_sign(qrequest, canonical), qrequest)
    assert parts.query.endswith(f"X-Amz-Signature={expected}")

    virtual = s3_client.presign_url(
        method="GET",
        endpoint="https://s3.sedamod.example",
        bucket="sedamod",
        key=key,
        access_key=creds.access_key,
        secret=creds.secret_key,
        region="us-east-1",
        expires_seconds=600,
        path_style=False,
        now=moment,
    )
    assert urlsplit(virtual).path == "/dir%20with%20space/%C3%BCn%C3%AF%2Bcode~.txt"


def test_migration_on_fresh_sqlite(tmp_path: Path) -> None:
    database = Database(tmp_path)
    database.initialize()
    names = set(inspect(database.engine).get_table_names())
    assert {"s3_buckets", "s3_identities", "s3_access_keys"} <= names
    with database.engine.connect() as connection:
        version = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
    assert version is not None and version >= "20261108_0006"
    database.dispose()


# ---------------------------------------------------------------- API


def test_settings_snapshot_and_secrets(
    client: TestClient, tmp_path: Path, engine: FakeEngine
) -> None:
    headers = owner(client)
    initial = snapshot(tmp_path)
    assert initial["version"] == 1 and initial["buckets"] == []
    panel = initial["identities"][0]
    assert panel["name"] == "__mrk_panel__" and panel["system"] is True
    assert panel["keys"][0]["secret_ref"] == PANEL_SECRET_REF
    assert re.fullmatch(r"MRK[A-Z0-9]{17}", panel["keys"][0]["access_key_id"])

    settings = client.get(f"{API}/settings").json()
    assert settings["region"] == "us-east-1" and settings["public_endpoint"] is None
    assert client.put(f"{API}/settings", json={"region": "us-east-1"}).status_code == 403  # CSRF
    bad = client.put(f"{API}/settings", headers=headers, json={"public_endpoint": "ftp://x"})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_public_endpoint"
    updated = client.put(
        f"{API}/settings",
        headers=headers,
        json={
            "public_endpoint": "https://S3.Example.com/",
            "virtual_host_suffix": "s3.example.com",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["public_endpoint"] == "https://s3.example.com"
    assert snapshot(tmp_path)["public_endpoint"] == "https://s3.example.com"

    assert make_bucket(client, headers, "backups").status_code == 201
    ident = client.post(
        f"{API}/identities",
        headers=headers,
        json={"name": "dokploy", "policy_template": "backup_client", "buckets": ["backups"]},
    ).json()
    key = client.post(f"{API}/identities/{ident['id']}/keys", headers=headers).json()
    secret = key["secret_access_key"]
    assert len(secret) == 40 and re.fullmatch(r"[A-Za-z0-9+/]{40}", secret)

    snap = snapshot(tmp_path)
    assert [b["name"] for b in snap["buckets"]] == ["backups"]
    dokploy = next(i for i in snap["identities"] if i["name"] == "dokploy")
    assert dokploy["keys"][0]["access_key_id"] == key["access_key_id"]
    assert dokploy["system"] is False
    # Secrets are never in the snapshot, the database or the encrypted store in plaintext.
    _akid, panel_secret = s3_module.ACTIVE_STORE.panel_credentials()
    cp = tmp_path / "cp" / "control-plane"
    blobs = [
        (tmp_path / "cp" / "modules" / "s3" / "config.json").read_bytes(),
        (cp / "upstream-secrets.json").read_bytes(),
    ]
    blobs += [p.read_bytes() for p in cp.glob("control-plane.sqlite3*")]
    for blob in blobs:
        assert secret.encode() not in blob and panel_secret.encode() not in blob
    listing = client.get(f"{API}/identities").text
    assert secret not in listing and "secret_access_key" not in listing
    assert "__mrk_panel__" not in listing
    audit = client.get("/api/v1/audit-events?limit=200").text
    assert secret not in audit

    # The panel secret is generated once and survives restarts.
    assert s3_module.ACTIVE_STORE.panel_credentials()[1] == panel_secret


def test_snapshot_write_is_atomic(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = owner(client)
    assert make_bucket(client, headers, "first").status_code == 201
    path = tmp_path / "cp" / "modules" / "s3" / "config.json"
    before = path.read_bytes()

    def broken_replace(src: Any, dst: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", broken_replace)
    with pytest.raises(OSError):
        s3_module.ACTIVE_STORE.write_snapshot()
    monkeypatch.undo()
    assert path.read_bytes() == before
    assert [p.name for p in path.parent.iterdir() if p.name.endswith(".tmp")] == []
    json.loads(before)


def test_bucket_crud_rules(client: TestClient, tmp_path: Path, engine: FakeEngine) -> None:
    headers = owner(client)
    for bad in ("ab", "Bad_Name", "10.0.0.1", "admin"):
        response = make_bucket(client, headers, bad)
        assert (
            response.status_code == 422
            and response.json()["error"]["code"] == "invalid_bucket_name"
        )
    created = make_bucket(client, headers, "data", quota_bytes=1024)
    assert created.status_code == 201, created.text
    assert created.json()["mode"] == "managed" and created.json()["quota_bytes"] == 1024
    assert "data" in engine.ensured
    assert make_bucket(client, headers, "data").json()["error"]["code"] == "bucket_exists"
    assert (
        make_bucket(client, headers, "x1y", mode="weird").json()["error"]["code"]
        == "invalid_bucket_mode"
    )

    patched = client.patch(f"{API}/buckets/data", headers=headers, json={"public_read": True})
    assert patched.status_code == 200 and patched.json()["public_read"] is True
    assert snapshot(tmp_path)["buckets"][0]["public_read"] is True
    assert (
        client.patch(f"{API}/buckets/data", headers=headers, json={"link_mode": "rw"}).json()[
            "error"
        ]["code"]
        == "invalid_link_mode"
    )
    assert client.patch(f"{API}/buckets/nope", headers=headers, json={}).status_code == 404

    listed = client.get(f"{API}/buckets").json()["items"]
    assert listed[0]["objects"] == 0 and listed[0]["bytes"] == 0
    status = client.get(f"{API}/status").json()
    assert status["engine_reachable"] is True and status["buckets"] == 1
    assert status["endpoint"] == "http://127.0.0.1:9000" and status["endpoint_is_fallback"] is True

    wrong = client.request(
        "DELETE", f"{API}/buckets/data", headers=headers, json={"confirmation": "x"}
    )
    assert wrong.json()["error"]["code"] == "confirmation_mismatch"
    engine.stats_override["data"] = 3
    busy = client.request(
        "DELETE", f"{API}/buckets/data", headers=headers, json={"confirmation": "data"}
    )
    assert busy.status_code == 409 and busy.json()["error"]["code"] == "bucket_not_empty"
    engine.down = True
    down = client.request(
        "DELETE", f"{API}/buckets/data", headers=headers, json={"confirmation": "data"}
    )
    assert down.status_code == 503 and down.json()["error"]["code"] == "engine_unreachable"
    assert client.get(f"{API}/status").json()["engine_reachable"] is False
    assert client.get(f"{API}/buckets").json()["items"][0]["objects"] is None
    engine.down = False
    forced = client.request(
        "DELETE",
        f"{API}/buckets/data",
        headers=headers,
        json={"confirmation": "data", "force": True},
    )
    assert forced.status_code == 200, forced.text
    assert ("data", "1") in engine.deleted
    assert snapshot(tmp_path)["buckets"] == []


def test_default_quota_applies_to_new_managed_buckets(client: TestClient) -> None:
    headers = owner(client)
    client.put(f"{API}/settings", headers=headers, json={"default_quota_bytes": 5000})
    assert make_bucket(client, headers, "quoted").json()["quota_bytes"] == 5000


def _login_as(client: TestClient, owner_csrf: str, role: str) -> dict[str, str]:
    username, password = f"{role}1", f"a-long-{role}-password-123"
    created = client.post(
        "/api/v1/users",
        headers={"X-CSRF-Token": owner_csrf},
        json={"username": username, "password": password, "role": role},
    )
    assert created.status_code == 201, created.text
    session = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    return {"X-CSRF-Token": str(session.json()["csrf_token"])}


def test_linked_buckets_owner_only_and_path_rules(
    client: TestClient, links: Path, tmp_path: Path, engine: FakeEngine
) -> None:
    headers = owner(client)
    found = client.get(f"{API}/links").json()
    paths = {item["path"] for item in found["items"]}
    root = str(links)
    assert f"{root}/files" in paths and f"{root}/files/photos" in paths and f"{root}/media" in paths
    assert "/mnt/links" in found["compose_hint"]

    outside = tmp_path / "outside"
    outside.mkdir()
    for bad in (
        str(outside),
        f"{root}/missing",
        root,
        f"{root}/files/../../outside",
        f"{root}/files/keep.txt",
    ):
        response = make_bucket(client, headers, "linked1", mode="linked", link_path=bad)
        assert response.status_code == 422, (bad, response.text)
        assert response.json()["error"]["code"] == "link_path_invalid"
    ok = make_bucket(
        client, headers, "files", mode="linked", link_path=f"{root}/files", link_mode="rw"
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["link_path"] == f"{root}/files" and ok.json()["link_mode"] == "rw"
    relative = make_bucket(client, headers, "media", mode="linked", link_path="media")
    assert relative.status_code == 201 and relative.json()["link_mode"] == "ro"
    nested = make_bucket(client, headers, "photos", mode="linked", link_path=f"{root}/files/photos")
    assert nested.status_code == 409 and nested.json()["error"]["code"] == "link_path_in_use"
    assert snapshot(tmp_path)["buckets"][0]["mode"] == "linked"
    marked = {i["path"]: i["bucket"] for i in client.get(f"{API}/links").json()["items"]}
    assert marked[f"{root}/files"] == "files"

    # Read-only linked bucket refuses writes before reaching the engine.
    upload = client.post(f"{API}/buckets/media/objects?key=a.txt", headers=headers, content=b"x")
    assert upload.status_code == 409 and upload.json()["error"]["code"] == "bucket_read_only"

    # Admins manage S3 but cannot link host folders or change a link.
    admin = _login_as(client, headers["X-CSRF-Token"], "admin")
    denied = make_bucket(client, admin, "other", mode="linked", link_path=f"{root}/media")
    assert denied.status_code == 403 and denied.json()["error"]["code"] == "linked_requires_owner"
    assert (
        client.patch(f"{API}/buckets/files", headers=admin, json={"link_mode": "ro"}).json()[
            "error"
        ]["code"]
        == "linked_requires_owner"
    )
    assert make_bucket(client, admin, "managed-by-admin").status_code == 201

    client.cookies.clear()
    headers = owner(client)
    deleted = client.request(
        "DELETE", f"{API}/buckets/files", headers=headers, json={"confirmation": "files"}
    )
    assert deleted.status_code == 200 and deleted.json()["files_removed"] is False
    assert (links / "files" / "keep.txt").read_text() == "host file"


def test_identities_keys_and_templates(client: TestClient, tmp_path: Path) -> None:
    headers = owner(client)
    make_bucket(client, headers, "backups")
    make_bucket(client, headers, "public1")
    missing = client.post(
        f"{API}/identities",
        headers=headers,
        json={"name": "x", "policy_template": "read_only", "buckets": ["nope"]},
    )
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "bucket_not_found"
    assert (
        client.post(
            f"{API}/identities",
            headers=headers,
            json={"name": "__mrk_panel__", "policy_template": "admin"},
        ).json()["error"]["code"]
        == "invalid_identity_name"
    )
    assert (
        client.post(
            f"{API}/identities", headers=headers, json={"name": "x", "policy_template": "nope"}
        ).json()["error"]["code"]
        == "invalid_policy_template"
    )
    bad_custom = client.post(
        f"{API}/identities",
        headers=headers,
        json={
            "name": "c",
            "policy_template": "custom",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
            },
        },
    )
    assert bad_custom.status_code == 422 and bad_custom.json()["error"]["code"] == "invalid_policy"

    ro = client.post(
        f"{API}/identities",
        headers=headers,
        json={"name": "reader", "policy_template": "read_only", "buckets": ["backups"]},
    )
    assert ro.status_code == 201, ro.text
    item = ro.json()
    assert item["policy_template"] == "read_only" and item["buckets"] == ["backups"]
    assert item["policy"]["Statement"][0]["Resource"] == ["arn:aws:s3:::backups"]
    assert (
        client.post(
            f"{API}/identities",
            headers=headers,
            json={"name": "reader", "policy_template": "admin"},
        ).json()["error"]["code"]
        == "identity_exists"
    )
    custom = client.post(
        f"{API}/identities",
        headers=headers,
        json={
            "name": "custom1",
            "policy_template": "custom",
            "policy": template_policy("read_write", ["public1"]),
        },
    )
    assert custom.status_code == 201

    ident = item["id"]
    first = client.post(f"{API}/identities/{ident}/keys", headers=headers).json()
    second = client.post(f"{API}/identities/{ident}/keys", headers=headers).json()
    for key in (first, second):
        assert re.fullmatch(r"MRK[A-Z0-9]{17}", key["access_key_id"])
        assert re.fullmatch(r"[A-Za-z0-9+/]{40}", key["secret_access_key"])
    third = client.post(f"{API}/identities/{ident}/keys", headers=headers)
    assert third.status_code == 409 and third.json()["error"]["code"] == "key_limit_reached"
    disabled = client.patch(
        f"{API}/identities/{ident}/keys/{first['access_key_id']}",
        headers=headers,
        json={"enabled": False},
    )
    assert disabled.status_code == 200 and disabled.json()["enabled"] is False
    third = client.post(f"{API}/identities/{ident}/keys", headers=headers)
    assert third.status_code == 201
    again = client.patch(
        f"{API}/identities/{ident}/keys/{first['access_key_id']}",
        headers=headers,
        json={"enabled": True},
    )
    assert again.status_code == 409
    snap_keys = next(i for i in snapshot(tmp_path)["identities"] if i["id"] == ident)["keys"]
    assert {k["access_key_id"]: k["enabled"] for k in snap_keys}[first["access_key_id"]] is False
    removed = client.delete(
        f"{API}/identities/{ident}/keys/{first['access_key_id']}", headers=headers
    )
    assert removed.status_code == 200
    assert (
        client.delete(
            f"{API}/identities/{ident}/keys/{first['access_key_id']}", headers=headers
        ).status_code
        == 404
    )

    patched = client.patch(
        f"{API}/identities/{ident}",
        headers=headers,
        json={"policy_template": "read_write", "buckets": ["backups", "public1"], "enabled": False},
    )
    assert patched.status_code == 200
    assert patched.json()["enabled"] is False and patched.json()["buckets"] == [
        "backups",
        "public1",
    ]
    listed = client.get(f"{API}/identities").json()["items"]
    reader = next(i for i in listed if i["id"] == ident)
    assert len(reader["keys"]) == 2 and "secret_access_key" not in json.dumps(listed)

    # Deleting a bucket strips it from templated identities.
    client.request(
        "DELETE", f"{API}/buckets/public1", headers=headers, json={"confirmation": "public1"}
    )
    assert client.get(f"{API}/identities").json()["items"][1]["buckets"] in (["backups"], [])
    reader = next(i for i in client.get(f"{API}/identities").json()["items"] if i["id"] == ident)
    assert reader["buckets"] == ["backups"]

    wrong = client.request(
        "DELETE", f"{API}/identities/{ident}", headers=headers, json={"confirmation": "x"}
    )
    assert wrong.json()["error"]["code"] == "confirmation_mismatch"
    gone = client.request(
        "DELETE", f"{API}/identities/{ident}", headers=headers, json={"confirmation": "reader"}
    )
    assert gone.status_code == 200
    assert all(i["id"] != ident for i in snapshot(tmp_path)["identities"])

    connection = client.get(f"{API}/connection?bucket=backups").json()
    assert connection["path_style"] is True and connection["region"] == "us-east-1"
    assert set(connection["snippets"]) >= {"aws_cli", "rclone", "mc", "boto3", "restic", "dokploy"}
    assert "s3:http://127.0.0.1:9000/backups/restic" in connection["snippets"]["restic"]
    assert "force_path_style = true" in connection["snippets"]["rclone"]


def test_file_manager_proxy(
    client: TestClient, engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = owner(client)
    make_bucket(client, headers, "files")
    base = f"{API}/buckets/files"
    assert client.post(f"{base}/objects?key=a.txt", content=b"x").status_code == 403  # CSRF
    up = client.post(
        f"{base}/objects?key=docs/hello%20w%C3%B6rld.txt",
        headers={**headers, "Content-Type": "text/plain"},
        content=b"hello",
    )
    assert up.status_code == 200, up.text
    assert up.json() == {
        "key": "docs/hello wörld.txt",
        "size": 5,
        "etag": hashlib.md5(b"hello").hexdigest(),  # noqa: S324 - S3 ETag
    }
    assert engine.objects[("files", "docs/hello wörld.txt")]["type"] == "text/plain"
    assert (
        client.post(f"{base}/objects?key=../x", headers=headers, content=b"x").json()["error"][
            "code"
        ]
        == "invalid_key"
    )
    assert (
        client.post(f"{API}/buckets/none/objects?key=a", headers=headers, content=b"x").json()[
            "error"
        ]["code"]
        == "bucket_not_found"
    )

    folder = client.post(f"{base}/folders", headers=headers, json={"prefix": "empty"})
    assert folder.status_code == 201 and folder.json()["key"] == "empty/"
    assert engine.objects[("files", "empty/")]["data"] == b""

    root = client.get(f"{base}/objects").json()
    assert root["prefixes"] == ["docs/", "empty/"] and root["objects"] == []
    docs = client.get(f"{base}/objects?prefix=docs/").json()
    assert docs["objects"][0]["key"] == "docs/hello wörld.txt" and docs["objects"][0]["size"] == 5
    assert client.get(f"{base}/objects?limit=0").json()["error"]["code"] == "invalid_limit"

    download = client.get(f"{base}/objects/download?key=docs/hello%20w%C3%B6rld.txt")
    assert download.status_code == 200 and download.content == b"hello"
    assert download.headers["content-disposition"].startswith("attachment;")
    assert "filename*=UTF-8''hello%20w%C3%B6rld.txt" in download.headers["content-disposition"]
    missing = client.get(f"{base}/objects/download?key=nope")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "object_not_found"

    # Multipart for bodies above the threshold (scaled down for the test).
    monkeypatch.setattr(s3_module, "MULTIPART_THRESHOLD", 1024)
    monkeypatch.setattr(s3_module, "PART_SIZE", 1000)
    big = os.urandom(2500)
    multi = client.post(f"{base}/objects?key=big.bin", headers=headers, content=big)
    assert multi.status_code == 200, multi.text
    assert multi.json()["size"] == 2500 and multi.json()["etag"] == "multi-3"
    assert engine.objects[("files", "big.bin")]["data"] == big

    def chunks() -> Any:  # unknown length (chunked request body)
        yield big[:1500]
        yield big[1500:]

    streamed = client.post(f"{base}/objects?key=big2.bin", headers=headers, content=chunks())
    assert streamed.status_code == 200, streamed.text
    assert engine.objects[("files", "big2.bin")]["data"] == big
    small = client.post(f"{base}/objects?key=small.bin", headers=headers, content=iter([b"ab"]))
    assert small.status_code == 200 and small.json()["size"] == 2

    moved = client.post(
        f"{base}/objects/move", headers=headers, json={"from": "big.bin", "to": "arch/big.bin"}
    )
    assert moved.status_code == 200 and moved.json()["moved"] == 1
    assert ("files", "big.bin") not in engine.objects and (
        "files",
        "arch/big.bin",
    ) in engine.objects
    folder_move = client.post(
        f"{base}/objects/move", headers=headers, json={"from": "docs/", "to": "notes/"}
    )
    assert folder_move.status_code == 200 and folder_move.json()["moved"] == 1
    assert ("files", "notes/hello wörld.txt") in engine.objects
    assert (
        client.post(
            f"{base}/objects/move", headers=headers, json={"from": "notes/", "to": "notes/sub/"}
        ).json()["error"]["code"]
        == "invalid_move"
    )

    share = client.post(
        f"{base}/share", headers=headers, json={"key": "arch/big.bin", "expires_seconds": 600}
    )
    assert share.status_code == 200, share.text
    payload = share.json()
    assert payload["warning"] == "public_endpoint_not_configured"
    assert payload["url"].startswith("http://127.0.0.1:9000/files/arch/big.bin?")
    assert "X-Amz-Expires=600" in payload["url"] and "X-Amz-Signature=" in payload["url"]
    too_long = client.post(
        f"{base}/share", headers=headers, json={"key": "arch/big.bin", "expires_seconds": 8 * 86400}
    )
    assert too_long.json()["error"]["code"] == "invalid_expiry"
    client.put(
        f"{API}/settings", headers=headers, json={"public_endpoint": "https://s3.example.com"}
    )
    share = client.post(f"{base}/share", headers=headers, json={"key": "arch/big.bin"}).json()
    assert (
        share["url"].startswith("https://s3.example.com/files/arch/big.bin?")
        and share["warning"] is None
    )
    if s3sigv4 is not None:
        parts = urlsplit(share["url"])
        s3sigv4.verify_request(
            "GET",
            parts.path,
            parts.query,
            [("host", "s3.example.com")],
            engine.panel_secret,
            region="us-east-1",
        )

    removed = client.request(
        "DELETE",
        f"{base}/objects",
        headers=headers,
        json={"keys": ["arch/big.bin", "empty/", "small.bin"]},
    )
    assert removed.status_code == 200
    assert removed.json() == {"deleted": ["arch/big.bin", "empty/", "small.bin"], "errors": []}
    assert (
        client.request("DELETE", f"{base}/objects", headers=headers, json={"keys": []}).json()[
            "error"
        ]["code"]
        == "invalid_request"
    )

    engine.down = True
    down = client.get(f"{base}/objects")
    assert down.status_code == 503 and down.json()["error"]["code"] == "engine_unreachable"

    audit = client.get("/api/v1/audit-events?limit=200").text
    for action in (
        "s3.object.upload",
        "s3.folder.create",
        "s3.object.move",
        "s3.object.share",
        "s3.object.delete",
        "s3.bucket.create",
    ):
        assert action in audit


def test_upload_respects_max_object_bytes(client: TestClient) -> None:
    headers = owner(client)
    make_bucket(client, headers, "tiny")
    client.put(f"{API}/settings", headers=headers, json={"max_object_bytes": 10})
    response = client.post(f"{API}/buckets/tiny/objects?key=a", headers=headers, content=b"x" * 11)
    assert response.status_code == 413 and response.json()["error"]["code"] == "object_too_large"


def test_rbac(client: TestClient) -> None:
    headers = owner(client)
    make_bucket(client, headers, "shared")
    client.post(f"{API}/buckets/shared/objects?key=a.txt", headers=headers, content=b"a")
    expected = {
        # role: (read, write, admin)
        "viewer": (False, False, False),
        "developer": (True, False, False),
        "operator": (True, True, False),
        "admin": (True, True, True),
    }
    for role, (can_read, can_write, can_admin) in expected.items():
        assert ("s3:read" in ROLE_PERMISSIONS[role]) is can_read
        client.cookies.clear()
        owner_csrf = owner(client)["X-CSRF-Token"]
        role_headers = _login_as(client, owner_csrf, role)
        read = client.get(f"{API}/buckets/shared/objects").status_code
        assert (read == 200) is can_read, (role, read)
        assert (client.get(f"{API}/connection").status_code == 200) is can_read
        write = client.post(
            f"{API}/buckets/shared/folders", headers=role_headers, json={"prefix": f"{role}/"}
        ).status_code
        assert (write == 201) is can_write, (role, write)
        admin = client.post(
            f"{API}/buckets", headers=role_headers, json={"name": f"{role}-bucket"}
        ).status_code
        assert (admin == 201) is can_admin, (role, admin)
        assert (client.get(f"{API}/identities").status_code == 200) is can_admin
        assert (client.get(f"{API}/links").status_code == 200) is can_admin
    for role in ("owner", "admin", "operator"):
        perms = ROLE_PERMISSIONS[role]
        assert "*" in perms or {"backup:server:read", "updates:read", "updates:write"} <= perms
    assert "backup:server:write" in ROLE_PERMISSIONS["admin"]
    assert "backup:server:write" not in ROLE_PERMISSIONS["operator"]
    assert ROLE_PERMISSIONS["developer"] >= {"updates:read"}
    assert "updates:write" not in ROLE_PERMISSIONS["developer"]
    assert "updates:read" in ROLE_PERMISSIONS["viewer"]


def test_lifecycle_rules_and_dry_run_preview(client: TestClient, engine: FakeEngine) -> None:
    headers = owner(client)
    assert make_bucket(client, headers, "logs").status_code == 201
    info = client.get(f"{API}/buckets/logs/lifecycle")
    assert info.status_code == 200 and info.json()["rules"][0]["id"] == "logs"
    assert client.get(f"{API}/buckets/nope/lifecycle").status_code == 404
    # The preview is a state-free POST but still needs CSRF + s3:admin.
    assert client.post(f"{API}/buckets/logs/lifecycle/preview").status_code == 403
    preview = client.post(f"{API}/buckets/logs/lifecycle/preview", headers=headers)
    assert preview.status_code == 200, preview.text
    assert preview.json() == {"objects": 3, "bytes": 30, "dry_run": True, "sample": []}
    assert ("POST", "logs", "lifecycle-preview") in engine.calls
