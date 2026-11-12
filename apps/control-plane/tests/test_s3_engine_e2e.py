# ruff: noqa: E501, S105, S106, S311, S324 - fixed test credentials (AWS doc examples),
# MD5 only to compare S3 ETags, seeded RNG for the listing model, long test vectors.
"""End-to-end tests: boto3 / raw HTTP against a real uvicorn-served S3 engine."""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import os
import socket
import threading
import time
import warnings
from pathlib import Path

import httpx
import pytest
import uvicorn

boto3 = pytest.importorskip("boto3")
from botocore.config import Config  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402
from mrk_control_plane import s3sigv4  # noqa: E402
from mrk_control_plane.s3engine import checksums  # noqa: E402
from mrk_control_plane.s3engine.engine import Engine  # noqa: E402
from mrk_control_plane.s3engine.settings import MIB, EngineSettings  # noqa: E402
from mrk_control_plane.secret_store import SecretStore  # noqa: E402

ADMIN_AK = "MRKADMIN000000000001"
ADMIN_SECRET = "admin-secret-0123456789abcdefghijklmnopqr"
RO_AK = "MRKREADONLY000000001"
RO_SECRET = "readonly-secret-0123456789abcdefghijklmn"
BACKUP_AK = "MRKBACKUP00000000001"
BACKUP_SECRET = "backup-secret-0123456789abcdefghijklmnop"


class Harness:
    def __init__(self, root: Path, *, tls: bool = False) -> None:
        self.root = root
        self.links = root / "links"
        (self.links / "files").mkdir(parents=True)
        (self.links / "readonly").mkdir(parents=True)
        self.store = SecretStore(root)
        refs = {}
        for akid, secret in (
            (ADMIN_AK, ADMIN_SECRET),
            (RO_AK, RO_SECRET),
            (BACKUP_AK, BACKUP_SECRET),
        ):
            refs[akid], _ = self.store.replace(
                None, {"access_key_id": akid, "secret_access_key": secret}
            )
        self.settings = EngineSettings(
            data_root=root / "modules" / "s3",
            secret_data_dir=root,
            link_roots=(self.links,),
            fsync_policy="none",
            hash_rate_bytes=0,
            # The fill-watermark guard has its own unit tests; don't let a nearly
            # full developer disk make these protocol tests fail.
            disk_block_percent=100,
        )
        self.config = {
            "version": 1,
            "enabled": True,
            "region": "us-east-1",
            "public_endpoint": "",
            "virtual_host_suffix": "s3.test.localhost",
            "max_object_bytes": 5 * 1024**4,
            "buckets": [
                {
                    "name": "backups",
                    "mode": "managed",
                    "public_read": False,
                    "quota_bytes": None,
                    "created_at": 1700000000,
                },
                {"name": "public-site", "mode": "managed", "public_read": True},
                {"name": "small", "mode": "managed", "quota_bytes": 1000},
                {
                    "name": "files",
                    "mode": "linked",
                    "link_path": str(self.links / "files"),
                    "link_mode": "rw",
                },
                {
                    "name": "readonly",
                    "mode": "linked",
                    "link_path": str(self.links / "readonly"),
                    "link_mode": "ro",
                },
            ],
            "identities": [
                {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "__mrk_panel__",
                    "enabled": True,
                    "system": True,
                    "policy": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
                    },
                    "keys": [
                        {"access_key_id": ADMIN_AK, "secret_ref": refs[ADMIN_AK], "enabled": True}
                    ],
                },
                {
                    "id": "00000000-0000-0000-0000-000000000002",
                    "name": "reader",
                    "enabled": True,
                    "policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:GetObject", "s3:ListBucket"],
                                "Resource": ["arn:aws:s3:::backups", "arn:aws:s3:::backups/*"],
                            },
                            {
                                "Effect": "Deny",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::backups/secret/*",
                            },
                        ],
                    },
                    "keys": [{"access_key_id": RO_AK, "secret_ref": refs[RO_AK], "enabled": True}],
                },
                {
                    "id": "00000000-0000-0000-0000-000000000003",
                    "name": "dokploy",
                    "enabled": True,
                    "policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:GetObject",
                                    "s3:PutObject",
                                    "s3:DeleteObject",
                                    "s3:AbortMultipartUpload",
                                    "s3:ListMultipartUploadParts",
                                ],
                                "Resource": "arn:aws:s3:::backups/dokploy/*",
                            },
                            {
                                "Effect": "Allow",
                                "Action": "s3:ListBucket",
                                "Resource": "arn:aws:s3:::backups",
                            },
                        ],
                    },
                    "keys": [
                        {"access_key_id": BACKUP_AK, "secret_ref": refs[BACKUP_AK], "enabled": True}
                    ],
                },
            ],
        }
        self.write_config()
        self.engine = Engine(self.settings, self.store)
        self.tls = tls
        self.server, self.port = self._start(self.engine.api, tls)
        self.admin_server, self.admin_port = self._start(self.engine.admin, False)
        self.endpoint = f"{'https' if tls else 'http'}://127.0.0.1:{self.port}"

    def write_config(self) -> None:
        path = self.settings.config_file
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.config), encoding="utf-8")
        os.replace(tmp, path)

    def reload(self) -> None:
        self.write_config()
        self.engine.snapshots.reload(force=True)

    def _start(self, app, tls: bool):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        kwargs = {}
        if tls:
            cert, key = _self_signed(self.root)
            kwargs = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
        config = uvicorn.Config(app, log_config=None, access_log=False, lifespan="off", **kwargs)
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        for _ in range(200):
            if server.started:
                break
            time.sleep(0.02)
        return server, port

    def client(self, akid: str = ADMIN_AK, secret: str = ADMIN_SECRET, **extra):
        config = Config(
            s3={"addressing_style": "path"},
            signature_version="s3v4",
            retries={"max_attempts": 1},
            **extra,
        )
        return boto3.client(
            "s3",
            endpoint_url=self.endpoint,
            region_name="us-east-1",
            aws_access_key_id=akid,
            aws_secret_access_key=secret,
            config=config,
            verify=False,
        )

    def stop(self) -> None:
        self.server.should_exit = True
        self.admin_server.should_exit = True
        time.sleep(0.2)
        self.engine.close()


def _self_signed(root: Path) -> tuple[Path, Path]:
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = root / "cert.pem", root / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def s3(tmp_path):
    harness = Harness(tmp_path)
    yield harness
    harness.stop()


@pytest.fixture
def s3_tls(tmp_path):
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    harness = Harness(tmp_path, tls=True)
    yield harness
    harness.stop()


def _code(exc: pytest.ExceptionInfo) -> str:
    return exc.value.response["Error"]["Code"]


# ----------------------------------------------------------------------------- managed basics


def test_list_buckets_put_get_head_delete(s3: Harness) -> None:
    client = s3.client()
    names = [b["Name"] for b in client.list_buckets()["Buckets"]]
    assert names == ["backups", "files", "public-site", "readonly", "small"]
    put = client.put_object(
        Bucket="backups",
        Key="dir/a b+c€.txt",
        Body=b"hello world",
        ContentType="text/plain",
        Metadata={"md5chksum": "x"},
    )
    assert put["ETag"] == f'"{hashlib.md5(b"hello world").hexdigest()}"'
    head = client.head_object(Bucket="backups", Key="dir/a b+c€.txt")
    assert head["ContentLength"] == 11 and head["ContentType"] == "text/plain"
    assert head["Metadata"] == {"md5chksum": "x"}
    got = client.get_object(Bucket="backups", Key="dir/a b+c€.txt")
    assert got["Body"].read() == b"hello world"
    assert client.get_bucket_location(Bucket="backups")["LocationConstraint"] is None
    client.head_bucket(Bucket="backups")
    client.delete_object(Bucket="backups", Key="dir/a b+c€.txt")
    client.delete_object(Bucket="backups", Key="never-existed")  # always 204
    with pytest.raises(ClientError) as missing:
        client.get_object(Bucket="backups", Key="dir/a b+c€.txt")
    assert _code(missing) == "NoSuchKey"
    with pytest.raises(ClientError) as nobucket:
        client.head_bucket(Bucket="nope-bucket")
    assert nobucket.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404
    with pytest.raises(ClientError) as create:
        client.create_bucket(Bucket="new-bucket")
    assert _code(create) == "AccessDenied"
    with pytest.raises(ClientError) as owned:
        client.create_bucket(Bucket="backups")
    assert _code(owned) == "BucketAlreadyOwnedByYou"


def test_list_objects_v1_v2_delimiter_paging(s3: Harness) -> None:
    client = s3.client()
    keys = ["a/1", "a/2", "a/b/3", "b", "c/4", "c/5", "space key", "plus+key"]
    for key in keys:
        client.put_object(Bucket="backups", Key=key, Body=key.encode())
    listed = client.list_objects_v2(Bucket="backups", Delimiter="/")
    assert [c["Key"] for c in listed["Contents"]] == ["b", "plus+key", "space key"]
    assert [p["Prefix"] for p in listed["CommonPrefixes"]] == ["a/", "c/"]
    paginator = client.get_paginator("list_objects_v2")
    pages = list(paginator.paginate(Bucket="backups", PaginationConfig={"PageSize": 2}))
    assert [obj["Key"] for page in pages for obj in page.get("Contents", [])] == sorted(keys)
    assert len(pages) == 4
    v1 = list(
        client.get_paginator("list_objects").paginate(
            Bucket="backups", Prefix="a/", Delimiter="/", PaginationConfig={"PageSize": 1}
        )
    )
    flat = [o["Key"] for p in v1 for o in p.get("Contents", [])] + [
        c["Prefix"] for p in v1 for c in p.get("CommonPrefixes", [])
    ]
    assert sorted(flat) == ["a/1", "a/2", "a/b/"]
    after = client.list_objects_v2(Bucket="backups", StartAfter="b", MaxKeys=1)
    assert after["Contents"][0]["Key"] == "c/4" and after["IsTruncated"]
    with pytest.raises(ClientError) as token:
        client.list_objects_v2(Bucket="backups", ContinuationToken="forged")
    assert _code(token) == "InvalidArgument"


def test_range_and_conditionals(s3: Harness) -> None:
    client = s3.client()
    body = bytes(range(256)) * 4
    etag = client.put_object(Bucket="backups", Key="r", Body=body)["ETag"]
    part = client.get_object(Bucket="backups", Key="r", Range="bytes=10-19")
    assert part["Body"].read() == body[10:20] and part["ContentRange"] == "bytes 10-19/1024"
    assert (
        client.get_object(Bucket="backups", Key="r", Range="bytes=-5")["Body"].read() == body[-5:]
    )
    assert (
        client.get_object(Bucket="backups", Key="r", Range="bytes=1000-")["Body"].read()
        == body[1000:]
    )
    with pytest.raises(ClientError) as bad:
        client.get_object(Bucket="backups", Key="r", Range="bytes=5000-6000")
    assert _code(bad) == "InvalidRange"
    with pytest.raises(ClientError) as not_modified:
        client.get_object(Bucket="backups", Key="r", IfNoneMatch=etag)
    assert not_modified.value.response["ResponseMetadata"]["HTTPStatusCode"] == 304
    with pytest.raises(ClientError) as failed:
        client.get_object(Bucket="backups", Key="r", IfMatch='"0000"')
    assert _code(failed) == "PreconditionFailed"
    assert client.get_object(Bucket="backups", Key="r", IfMatch=etag)["ContentLength"] == 1024
    with pytest.raises(ClientError) as exists:
        client.put_object(Bucket="backups", Key="r", Body=b"x", IfNoneMatch="*")
    assert _code(exists) == "PreconditionFailed"


def test_copy_object_and_metadata_directive(s3: Harness) -> None:
    client = s3.client()
    client.put_object(
        Bucket="backups", Key="src", Body=b"copy me", Metadata={"a": "1"}, ContentType="text/x"
    )
    result = client.copy_object(
        Bucket="backups", Key="dst", CopySource={"Bucket": "backups", "Key": "src"}
    )
    assert result["CopyObjectResult"]["ETag"] == f'"{hashlib.md5(b"copy me").hexdigest()}"'
    head = client.head_object(Bucket="backups", Key="dst")
    assert head["Metadata"] == {"a": "1"} and head["ContentType"] == "text/x"
    client.copy_object(
        Bucket="backups",
        Key="dst",
        CopySource="backups/src",
        MetadataDirective="REPLACE",
        Metadata={"b": "2"},
    )
    assert client.head_object(Bucket="backups", Key="dst")["Metadata"] == {"b": "2"}
    with pytest.raises(ClientError) as itself:
        client.copy_object(Bucket="backups", Key="src", CopySource="backups/src")
    assert _code(itself) == "InvalidRequest"
    client.copy_object(Bucket="files", Key="copied/from-managed.txt", CopySource="backups/src")
    assert (s3.links / "files" / "copied" / "from-managed.txt").read_bytes() == b"copy me"
    client.delete_object(Bucket="backups", Key="src")
    assert client.get_object(Bucket="backups", Key="dst")["Body"].read() == b"copy me"


def test_batch_delete_quiet_and_verbose(s3: Harness) -> None:
    client = s3.client()
    for index in range(5):
        client.put_object(Bucket="backups", Key=f"del/{index}", Body=b"x")
    result = client.delete_objects(
        Bucket="backups",
        Delete={"Objects": [{"Key": "del/0"}, {"Key": "del/1"}, {"Key": "missing"}]},
    )
    assert sorted(d["Key"] for d in result["Deleted"]) == ["del/0", "del/1", "missing"]
    quiet = client.delete_objects(
        Bucket="backups", Delete={"Objects": [{"Key": "del/2"}], "Quiet": True}
    )
    assert "Deleted" not in quiet
    remaining = [
        o["Key"] for o in client.list_objects_v2(Bucket="backups", Prefix="del/")["Contents"]
    ]
    assert remaining == ["del/3", "del/4"]


def test_presigned_get_and_put(s3: Harness) -> None:
    client = s3.client()
    put_url = client.generate_presigned_url(
        "put_object", Params={"Bucket": "backups", "Key": "share/up.bin"}, ExpiresIn=300
    )
    assert httpx.put(put_url, content=b"presigned body").status_code == 200
    get_url = client.generate_presigned_url(
        "get_object", Params={"Bucket": "backups", "Key": "share/up.bin"}, ExpiresIn=300
    )
    response = httpx.get(get_url)
    assert response.status_code == 200 and response.content == b"presigned body"
    tampered = get_url.replace("share/up.bin", "share/other.bin")
    assert httpx.get(tampered).status_code == 403
    ours = s3sigv4.presign_url(
        "GET",
        f"{s3.endpoint}/backups/share/up.bin",
        access_key_id=ADMIN_AK,
        secret_access_key=ADMIN_SECRET,
        region="us-east-1",
        expires=60,
        extra_params={"x-mrk-share": "abc"},
    )
    assert httpx.get(ours).content == b"presigned body"
    expired = s3sigv4.presign_url(
        "GET",
        f"{s3.endpoint}/backups/share/up.bin",
        access_key_id=ADMIN_AK,
        secret_access_key=ADMIN_SECRET,
        region="us-east-1",
        expires=1,
        now=dt.datetime.now(dt.UTC) - dt.timedelta(seconds=30),
    )
    response = httpx.get(expired)
    assert response.status_code == 403 and b"Request has expired" in response.content


def test_multipart_upload_with_large_parts(s3: Harness) -> None:
    client = s3.client()
    part1 = os.urandom(5 * MIB)
    part2 = os.urandom(6 * MIB + 3)
    part3 = b"tail"
    upload = client.create_multipart_upload(
        Bucket="backups", Key="dokploy/db.sql.gz", ContentType="application/gzip"
    )
    upload_id = upload["UploadId"]
    etags = []
    for number, data in enumerate([part1, part2, part3], start=1):
        etags.append(
            client.upload_part(
                Bucket="backups",
                Key="dokploy/db.sql.gz",
                UploadId=upload_id,
                PartNumber=number,
                Body=data,
            )["ETag"]
        )
    listed = client.list_parts(Bucket="backups", Key="dokploy/db.sql.gz", UploadId=upload_id)
    assert [p["PartNumber"] for p in listed["Parts"]] == [1, 2, 3]
    uploads = client.list_multipart_uploads(Bucket="backups")
    assert uploads["Uploads"][0]["UploadId"] == upload_id
    with pytest.raises(ClientError) as order:
        client.complete_multipart_upload(
            Bucket="backups",
            Key="dokploy/db.sql.gz",
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [{"PartNumber": 2, "ETag": etags[1]}, {"PartNumber": 1, "ETag": etags[0]}]
            },
        )
    assert _code(order) == "InvalidPartOrder"
    done = client.complete_multipart_upload(
        Bucket="backups",
        Key="dokploy/db.sql.gz",
        UploadId=upload_id,
        MultipartUpload={"Parts": [{"PartNumber": n + 1, "ETag": e} for n, e in enumerate(etags)]},
    )
    md5s = b"".join(hashlib.md5(p).digest() for p in (part1, part2, part3))
    assert done["ETag"] == f'"{hashlib.md5(md5s).hexdigest()}-3"'
    whole = part1 + part2 + part3
    assert client.get_object(Bucket="backups", Key="dokploy/db.sql.gz")["Body"].read() == whole
    middle = client.get_object(
        Bucket="backups", Key="dokploy/db.sql.gz", Range=f"bytes={5 * MIB - 2}-{5 * MIB + 1}"
    )
    assert middle["Body"].read() == whole[5 * MIB - 2 : 5 * MIB + 2]
    assert client.list_multipart_uploads(Bucket="backups").get("Uploads", []) == []


def test_multipart_small_part_and_abort(s3: Harness) -> None:
    client = s3.client()
    upload_id = client.create_multipart_upload(Bucket="backups", Key="small-parts")["UploadId"]
    e1 = client.upload_part(
        Bucket="backups", Key="small-parts", UploadId=upload_id, PartNumber=1, Body=b"a" * 100
    )["ETag"]
    e2 = client.upload_part(
        Bucket="backups", Key="small-parts", UploadId=upload_id, PartNumber=2, Body=b"b"
    )["ETag"]
    with pytest.raises(ClientError) as small:
        client.complete_multipart_upload(
            Bucket="backups",
            Key="small-parts",
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [{"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2}]
            },
        )
    assert _code(small) == "EntityTooSmall"
    client.abort_multipart_upload(Bucket="backups", Key="small-parts", UploadId=upload_id)
    with pytest.raises(ClientError) as gone:
        client.list_parts(Bucket="backups", Key="small-parts", UploadId=upload_id)
    assert _code(gone) == "NoSuchUpload"


def test_upload_part_copy(s3: Harness) -> None:
    client = s3.client()
    source = os.urandom(6 * MIB)
    client.put_object(Bucket="backups", Key="big-src", Body=source)
    upload_id = client.create_multipart_upload(Bucket="backups", Key="big-dst")["UploadId"]
    p1 = client.upload_part_copy(
        Bucket="backups",
        Key="big-dst",
        UploadId=upload_id,
        PartNumber=1,
        CopySource="backups/big-src",
        CopySourceRange=f"bytes=0-{5 * MIB - 1}",
    )
    p2 = client.upload_part_copy(
        Bucket="backups",
        Key="big-dst",
        UploadId=upload_id,
        PartNumber=2,
        CopySource="backups/big-src",
        CopySourceRange=f"bytes={5 * MIB}-{6 * MIB - 1}",
    )
    client.complete_multipart_upload(
        Bucket="backups",
        Key="big-dst",
        UploadId=upload_id,
        MultipartUpload={
            "Parts": [
                {"PartNumber": 1, "ETag": p1["CopyPartResult"]["ETag"]},
                {"PartNumber": 2, "ETag": p2["CopyPartResult"]["ETag"]},
            ]
        },
    )
    assert client.get_object(Bucket="backups", Key="big-dst")["Body"].read() == source


def test_transfer_manager_upload_download(s3: Harness) -> None:
    from boto3.s3.transfer import TransferConfig

    client = s3.client()
    data = os.urandom(12 * MIB + 17)
    config = TransferConfig(
        multipart_threshold=5 * MIB, multipart_chunksize=5 * MIB, max_concurrency=4
    )
    client.upload_fileobj(io.BytesIO(data), "backups", "tm/file.bin", Config=config)
    out = io.BytesIO()
    client.download_fileobj("backups", "tm/file.bin", out, Config=config)
    assert out.getvalue() == data


# ----------------------------------------------------------------------------- policy / quota / anonymous


def test_policy_deny_and_scoped_identity(s3: Harness) -> None:
    admin = s3.client()
    admin.put_object(Bucket="backups", Key="public/a", Body=b"a")
    admin.put_object(Bucket="backups", Key="secret/b", Body=b"b")
    reader = s3.client(RO_AK, RO_SECRET)
    assert reader.get_object(Bucket="backups", Key="public/a")["Body"].read() == b"a"
    with pytest.raises(ClientError) as denied:
        reader.get_object(Bucket="backups", Key="secret/b")
    assert _code(denied) == "AccessDenied"
    with pytest.raises(ClientError) as write:
        reader.put_object(Bucket="backups", Key="public/new", Body=b"x")
    assert _code(write) == "AccessDenied"
    assert [b["Name"] for b in reader.list_buckets()["Buckets"]] == ["backups"]
    backup = s3.client(BACKUP_AK, BACKUP_SECRET)
    backup.put_object(Bucket="backups", Key="dokploy/x", Body=b"x")
    with pytest.raises(ClientError) as outside:
        backup.put_object(Bucket="backups", Key="other/x", Body=b"x")
    assert _code(outside) == "AccessDenied"
    bad = s3.client(ADMIN_AK, "wrong-secret")
    with pytest.raises(ClientError) as mismatch:
        bad.list_buckets()
    assert _code(mismatch) == "SignatureDoesNotMatch"


def test_anonymous_only_on_public_buckets(s3: Harness) -> None:
    admin = s3.client()
    admin.put_object(
        Bucket="public-site", Key="index.html", Body=b"<h1>hi</h1>", ContentType="text/html"
    )
    admin.put_object(Bucket="backups", Key="private", Body=b"p")
    response = httpx.get(f"{s3.endpoint}/public-site/index.html")
    assert response.status_code == 200 and response.headers["x-content-type-options"] == "nosniff"
    assert httpx.get(f"{s3.endpoint}/backups/private").status_code == 403
    assert httpx.get(f"{s3.endpoint}/public-site/").status_code == 403  # listing not public
    assert httpx.put(f"{s3.endpoint}/public-site/x", content=b"x").status_code == 403
    assert httpx.get(f"{s3.endpoint}/").status_code == 403


def test_quota_enforced(s3: Harness) -> None:
    client = s3.client()
    client.put_object(Bucket="small", Key="a", Body=b"x" * 600)
    with pytest.raises(ClientError) as quota:
        client.put_object(Bucket="small", Key="b", Body=b"x" * 600)
    assert _code(quota) == "QuotaExceeded"
    client.put_object(Bucket="small", Key="a", Body=b"x" * 900)  # replacing fits


def test_disabled_snapshot_returns_503(s3: Harness) -> None:
    s3.config["enabled"] = False
    s3.reload()
    response = httpx.get(f"{s3.endpoint}/")
    assert response.status_code == 503 and b"ServiceUnavailable" in response.content


def test_virtual_host_addressing(s3: Harness) -> None:
    client = s3.client()
    client.put_object(Bucket="backups", Key="vh/key.txt", Body=b"vhost")
    signed = s3sigv4.sign_request(
        "GET",
        f"http://backups.s3.test.localhost:{s3.port}/vh/key.txt",
        {},
        access_key_id=ADMIN_AK,
        secret_access_key=ADMIN_SECRET,
        region="us-east-1",
    )
    response = httpx.get(f"{s3.endpoint}/vh/key.txt", headers=signed)
    assert response.status_code == 200 and response.content == b"vhost"


# ----------------------------------------------------------------------------- checksums / chunked


def test_checksum_trailers_over_https_boto3_defaults(s3_tls: Harness) -> None:
    client = s3_tls.client()
    data = os.urandom(70000)
    for algorithm in ("CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"):
        result = client.put_object(
            Bucket="backups", Key=f"ck/{algorithm}", Body=data, ChecksumAlgorithm=algorithm
        )
        assert result[f"Checksum{algorithm}"] == checksums.compute(algorithm, data)
        got = client.get_object(Bucket="backups", Key=f"ck/{algorithm}", ChecksumMode="ENABLED")
        assert got["Body"].read() == data
        assert got[f"Checksum{algorithm}"] == checksums.compute(algorithm, data)
    default = client.put_object(Bucket="backups", Key="ck/default", Body=b"default-checksum")
    assert default["ChecksumCRC32"] == checksums.compute("CRC32", b"default-checksum")


def test_multipart_full_object_crc64_and_composite(s3_tls: Harness) -> None:
    client = s3_tls.client()
    parts = [os.urandom(5 * MIB), os.urandom(1234)]
    for algorithm in ("CRC64NVME", "CRC32"):
        key = f"mp/{algorithm}"
        upload = client.create_multipart_upload(
            Bucket="backups", Key=key, ChecksumAlgorithm=algorithm
        )
        done = []
        for number, data in enumerate(parts, start=1):
            result = client.upload_part(
                Bucket="backups",
                Key=key,
                UploadId=upload["UploadId"],
                PartNumber=number,
                Body=data,
                ChecksumAlgorithm=algorithm,
            )
            done.append(
                {
                    "PartNumber": number,
                    "ETag": result["ETag"],
                    f"Checksum{algorithm}": result[f"Checksum{algorithm}"],
                }
            )
        complete = client.complete_multipart_upload(
            Bucket="backups", Key=key, UploadId=upload["UploadId"], MultipartUpload={"Parts": done}
        )
        if algorithm == "CRC64NVME":
            assert complete["ChecksumCRC64NVME"] == checksums.compute("CRC64NVME", b"".join(parts))
        else:
            assert complete["ChecksumCRC32"].endswith("-2")
        assert client.get_object(Bucket="backups", Key=key, ChecksumMode="ENABLED")[
            "Body"
        ].read() == b"".join(parts)


def test_bad_checksum_and_md5_rejected(s3: Harness) -> None:
    signed_headers = {
        "x-amz-checksum-crc32": checksums.compute("CRC32", b"other"),
        "content-length": "4",
    }
    payload = hashlib.sha256(b"data").hexdigest()
    headers = s3sigv4.sign_request(
        "PUT",
        f"{s3.endpoint}/backups/bad",
        signed_headers,
        access_key_id=ADMIN_AK,
        secret_access_key=ADMIN_SECRET,
        region="us-east-1",
        payload_hash=payload,
    )
    response = httpx.put(f"{s3.endpoint}/backups/bad", content=b"data", headers=headers)
    assert response.status_code == 400 and b"BadDigest" in response.content
    client = s3.client()
    with pytest.raises(ClientError) as md5:
        client.put_object(
            Bucket="backups", Key="bad2", Body=b"data", ContentMD5="1B2M2Y8AsgTpgAmY7PhCfg=="
        )
    assert _code(md5) == "BadDigest"
    headers = s3sigv4.sign_request(
        "PUT",
        f"{s3.endpoint}/backups/bad3",
        {"content-length": "4"},
        access_key_id=ADMIN_AK,
        secret_access_key=ADMIN_SECRET,
        region="us-east-1",
        payload_hash=hashlib.sha256(b"else").hexdigest(),
    )
    response = httpx.put(f"{s3.endpoint}/backups/bad3", content=b"data", headers=headers)
    assert response.status_code == 400 and b"XAmzContentSHA256Mismatch" in response.content
    assert s3.client().list_objects_v2(Bucket="backups").get("KeyCount") == 0


def test_signed_streaming_upload_like_minio_go(s3: Harness) -> None:
    data = os.urandom(200_000)
    chunk = 64 * 1024
    url = f"{s3.endpoint}/backups/streamed.bin"
    base = {
        "content-encoding": "aws-chunked",
        "x-amz-decoded-content-length": str(len(data)),
        "x-amz-trailer": "x-amz-checksum-crc32c",
    }
    headers = s3sigv4.sign_request(
        "PUT",
        url,
        base,
        access_key_id=ADMIN_AK,
        secret_access_key=ADMIN_SECRET,
        region="us-east-1",
        payload_hash=s3sigv4.STREAMING_SIGNED_TRAILER,
    )
    seed = headers["authorization"].rsplit("Signature=", 1)[1]
    key = s3sigv4.derive_signing_key(ADMIN_SECRET, headers["x-amz-date"][:8], "us-east-1")
    scope = f"{headers['x-amz-date'][:8]}/us-east-1/s3/aws4_request"
    signer = s3sigv4.ChunkedPayloadSigner(key, headers["x-amz-date"], scope, seed)
    body = b"".join(signer.chunk(data[i : i + chunk]) for i in range(0, len(data), chunk))
    body += signer.final([("x-amz-checksum-crc32c", checksums.compute("CRC32C", data))])
    response = httpx.put(url, content=body, headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["x-amz-checksum-crc32c"] == checksums.compute("CRC32C", data)
    assert s3.client().get_object(Bucket="backups", Key="streamed.bin")["Body"].read() == data


def test_rclone_rcat_semantics_unknown_size_multipart(s3: Harness) -> None:
    """rclone rcat: path-style, no bucket check, multipart of unknown total size, X-Amz-Meta-Md5chksum."""
    client = s3.client(BACKUP_AK, BACKUP_SECRET)
    stream = io.BytesIO(os.urandom(11 * MIB + 5))
    whole = hashlib.md5(stream.getvalue())
    upload = client.create_multipart_upload(
        Bucket="backups", Key="dokploy/pg.dump", Metadata={"md5chksum": "placeholder"}
    )
    parts = []
    number = 1
    while block := stream.read(5 * MIB):
        etag = client.upload_part(
            Bucket="backups",
            Key="dokploy/pg.dump",
            UploadId=upload["UploadId"],
            PartNumber=number,
            Body=block,
        )["ETag"]
        parts.append({"PartNumber": number, "ETag": etag})
        number += 1
    client.complete_multipart_upload(
        Bucket="backups",
        Key="dokploy/pg.dump",
        UploadId=upload["UploadId"],
        MultipartUpload={"Parts": parts},
    )
    listed = client.list_objects_v2(Bucket="backups", Prefix="dokploy/")
    assert listed["Contents"][0]["Size"] == 11 * MIB + 5
    body = client.get_object(Bucket="backups", Key="dokploy/pg.dump")["Body"].read()
    assert hashlib.md5(body).hexdigest() == whole.hexdigest()
    client.delete_object(Bucket="backups", Key="dokploy/pg.dump")  # retention


# ----------------------------------------------------------------------------- linked folders


def test_linked_folder_external_files_and_writes(s3: Harness) -> None:
    root = s3.links / "files"
    (root / "photos" / "2026").mkdir(parents=True)
    (root / "photos" / "2026" / "a.jpg").write_bytes(b"jpeg-bytes")
    (root / "photos" / "b.txt").write_text("hello", encoding="utf-8")
    (root / "empty-dir").mkdir()
    (root / ".mrk-tmp-leftover").write_bytes(b"hidden")
    client = s3.client()
    top = client.list_objects_v2(Bucket="files", Delimiter="/")
    assert [p["Prefix"] for p in top["CommonPrefixes"]] == ["empty-dir/", "photos/"]
    flat = [o["Key"] for o in client.list_objects_v2(Bucket="files")["Contents"]]
    assert flat == ["empty-dir/", "photos/2026/a.jpg", "photos/b.txt"]
    head = client.head_object(Bucket="files", Key="photos/b.txt")
    assert head["ContentLength"] == 5 and head["ContentType"] == "text/plain"
    synthetic = head["ETag"]
    got = client.get_object(Bucket="files", Key="photos/b.txt")
    assert got["Body"].read() == b"hello"
    # The full GET cached the real MD5, which replaces the synthetic ETag.
    assert (
        client.head_object(Bucket="files", Key="photos/b.txt")["ETag"]
        == f'"{hashlib.md5(b"hello").hexdigest()}"'
    )
    assert synthetic != f'"{hashlib.md5(b"hello").hexdigest()}"'
    client.put_object(
        Bucket="files", Key="docs/new.txt", Body=b"via s3", ContentType="text/x-custom"
    )
    assert (root / "docs" / "new.txt").read_bytes() == b"via s3"
    assert client.head_object(Bucket="files", Key="docs/new.txt")["ContentType"] == "text/x-custom"
    client.put_object(
        Bucket="files", Key="folder-marker/", Body=b"", ContentType="application/x-directory"
    )
    assert (root / "folder-marker").is_dir()
    with pytest.raises(ClientError) as conflict:
        client.put_object(Bucket="files", Key="photos/b.txt/child", Body=b"x")
    assert _code(conflict) == "InvalidArgument"
    client.delete_object(Bucket="files", Key="docs/new.txt")
    assert not (root / "docs").exists()  # empty parent pruned
    big = os.urandom(5 * MIB + 10)
    upload = client.create_multipart_upload(Bucket="files", Key="mp/joined.bin")
    p1 = client.upload_part(
        Bucket="files",
        Key="mp/joined.bin",
        UploadId=upload["UploadId"],
        PartNumber=1,
        Body=big[: 5 * MIB],
    )
    p2 = client.upload_part(
        Bucket="files",
        Key="mp/joined.bin",
        UploadId=upload["UploadId"],
        PartNumber=2,
        Body=big[5 * MIB :],
    )
    client.complete_multipart_upload(
        Bucket="files",
        Key="mp/joined.bin",
        UploadId=upload["UploadId"],
        MultipartUpload={
            "Parts": [{"PartNumber": 1, "ETag": p1["ETag"]}, {"PartNumber": 2, "ETag": p2["ETag"]}]
        },
    )
    assert (root / "mp" / "joined.bin").read_bytes() == big
    assert not [
        o["Key"] for o in client.list_objects_v2(Bucket="files", Prefix=".mrk").get("Contents", [])
    ]


def test_linked_folder_traversal_and_readonly(s3: Harness) -> None:
    client = s3.client()
    secret = s3.root / "outside.txt"
    secret.write_text("secret", encoding="utf-8")
    for key in ["../outside.txt", "a/../../outside.txt", "./x", "a//b", ".mrk/uploads/x", "/abs"]:
        with pytest.raises(ClientError) as exc:
            client.put_object(Bucket="files", Key=key, Body=b"pwn")
        assert _code(exc) in {"InvalidArgument", "KeyTooLongError"}, key
        with pytest.raises(ClientError):
            client.get_object(Bucket="files", Key=key)
    raw = httpx.get(
        f"{s3.endpoint}/files/%2e%2e/outside.txt",
        headers=s3sigv4.sign_request(
            "GET",
            f"{s3.endpoint}/files/%2e%2e/outside.txt",
            {},
            access_key_id=ADMIN_AK,
            secret_access_key=ADMIN_SECRET,
            region="us-east-1",
        ),
    )
    assert raw.status_code in {403, 404} and b"secret" not in raw.content
    assert secret.read_text(encoding="utf-8") == "secret"
    try:
        os.symlink(secret, s3.links / "files" / "link.txt")
    except (OSError, NotImplementedError):
        pass
    else:
        keys = [o["Key"] for o in client.list_objects_v2(Bucket="files").get("Contents", [])]
        assert "link.txt" not in keys
        with pytest.raises(ClientError):
            client.get_object(Bucket="files", Key="link.txt")
    readonly = s3.links / "readonly"
    (readonly / "report.csv").write_text("a,b", encoding="utf-8")
    assert client.get_object(Bucket="readonly", Key="report.csv")["Body"].read() == b"a,b"
    for call in (
        lambda: client.put_object(Bucket="readonly", Key="new.txt", Body=b"x"),
        lambda: client.delete_object(Bucket="readonly", Key="report.csv"),
        lambda: client.create_multipart_upload(Bucket="readonly", Key="big"),
        lambda: client.copy_object(
            Bucket="readonly", Key="copy.csv", CopySource="readonly/report.csv"
        ),
    ):
        with pytest.raises(ClientError) as exc:
            call()
        assert _code(exc) == "AccessDenied"
    assert (readonly / "report.csv").exists()


# ----------------------------------------------------------------------------- admin API and GC


def test_admin_api(s3: Harness) -> None:
    base = f"http://127.0.0.1:{s3.admin_port}"
    token = s3.settings.admin_token_file.read_text(encoding="ascii").strip()
    assert httpx.get(f"{base}/admin/health").status_code == 401
    headers = {"X-MRK-Admin-Token": token}
    assert httpx.get(f"{base}/admin/health", headers=headers).json()["enabled"] is True
    client = s3.client()
    client.put_object(Bucket="backups", Key="a", Body=b"12345")
    assert httpx.get(f"{base}/admin/buckets/backups/stats", headers=headers).json() == {
        "objects": 1,
        "bytes": 5,
    }
    assert httpx.post(f"{base}/admin/buckets/backups/ensure", headers=headers).json()["ok"] is True
    assert httpx.delete(f"{base}/admin/buckets/backups?force=0", headers=headers).status_code == 409
    links = httpx.get(f"{base}/admin/links", headers=headers).json()["items"]
    assert {Path(item["path"]).name for item in links} == {"files", "readonly"}
    (s3.links / "files" / "keep.txt").write_text("keep", encoding="utf-8")
    assert httpx.delete(f"{base}/admin/buckets/files?force=0", headers=headers).status_code == 200
    assert (s3.links / "files" / "keep.txt").exists()
    assert httpx.delete(f"{base}/admin/buckets/backups?force=1", headers=headers).status_code == 200
    assert not (s3.settings.buckets_dir / "backups").exists()
    if os.name != "nt":
        assert (s3.settings.admin_token_file.stat().st_mode & 0o777) == 0o600


def test_gc_removes_stale_uploads_and_trash(s3: Harness) -> None:
    client = s3.client()
    client.put_object(Bucket="backups", Key="k", Body=b"old")
    client.put_object(Bucket="backups", Key="k", Body=b"new")
    upload_id = client.create_multipart_upload(Bucket="backups", Key="stale")["UploadId"]
    client.upload_part(Bucket="backups", Key="stale", UploadId=upload_id, PartNumber=1, Body=b"x")
    bucket = s3.engine.bucket("backups")
    future = time.time_ns() + 8 * 86400 * 1_000_000_000
    bucket.gc(future)
    bucket.gc(future)
    assert bucket.index.get_upload(upload_id) is None
    files = [p for p in (s3.settings.buckets_dir / "backups" / "objects").rglob("*") if p.is_file()]
    assert len(files) == 1
    assert client.get_object(Bucket="backups", Key="k")["Body"].read() == b"new"


def test_public_bucket_in_a_browser_and_repeated_bucket_name(s3: Harness) -> None:
    """A browser at a public bucket's root gets index.html or a short page, and a
    path-style link opened on the bucket's own domain still finds the file."""
    s3.config["bucket_hosts"] = {"files.example.test": "public-site"}
    s3.reload()
    admin = s3.client()
    admin.put_object(Bucket="public-site", Key="img/a.png", Body=b"PNG")
    html = {"Accept": "text/html,application/xhtml+xml"}
    domain = {"Host": "files.example.test"}

    # No index.html: a short page for browsers, the S3 error for S3 clients.
    page = httpx.get(f"{s3.endpoint}/public-site/", headers=html)
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    assert "public-site" in page.text and "<script" not in page.text
    assert httpx.get(f"{s3.endpoint}/public-site/").status_code == 403
    assert httpx.get(f"{s3.endpoint}/public-site/?list-type=2", headers=html).status_code == 403
    head = httpx.head(f"{s3.endpoint}/", headers={**html, **domain})
    assert head.status_code == 200 and int(head.headers["content-length"]) > 0
    # A private bucket never gets the page.
    assert httpx.get(f"{s3.endpoint}/backups/", headers=html).status_code == 403

    admin.put_object(Bucket="public-site", Key="index.html", Body=b"<h1>site</h1>",
                     ContentType="text/html")
    site = httpx.get(f"{s3.endpoint}/", headers={**html, **domain})
    assert site.status_code == 200 and site.text == "<h1>site</h1>"

    # /<bucket>/<key> on the bucket's own domain: the key without the bucket name.
    plain = httpx.get(f"{s3.endpoint}/img/a.png?v=1", headers=domain)
    doubled = httpx.get(f"{s3.endpoint}/public-site/img/a.png?v=1", headers=domain)
    assert plain.status_code == doubled.status_code == 200 and doubled.content == b"PNG"
    # Only on a bucket domain, and only when nothing has the full key.
    assert httpx.get(f"{s3.endpoint}/public-site/public-site/img/a.png").status_code == 403
    admin.put_object(Bucket="public-site", Key="public-site/img/a.png", Body=b"REAL")
    assert httpx.get(f"{s3.endpoint}/public-site/img/a.png", headers=domain).content == b"REAL"
    assert httpx.get(f"{s3.endpoint}/public-site/missing.png", headers=domain).status_code == 403
