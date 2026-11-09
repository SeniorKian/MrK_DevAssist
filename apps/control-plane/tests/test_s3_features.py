# ruff: noqa: E501, S105, S106 - fixed test credentials, long XML/test lines.
"""S3 P1 features: object/bucket tagging, lifecycle (+ worker, dry run) and versioning."""

from __future__ import annotations

import time

import httpx
import pytest

boto3 = pytest.importorskip("boto3")
from botocore.exceptions import ClientError  # noqa: E402
from mrk_control_plane.s3engine import lifecycle  # noqa: E402
from mrk_control_plane.s3engine.engine import Engine  # noqa: E402
from mrk_control_plane.s3engine.errors import S3Error  # noqa: E402
from mrk_control_plane.s3engine.index import BucketIndex, ObjectRecord  # noqa: E402

from .test_s3_engine_e2e import RO_AK, RO_SECRET, Harness  # noqa: E402

DAY_NS = 86400 * 1_000_000_000

TAGGER_AK = "MRKTAGGER00000000001"
TAGGER_SECRET = "tagger-secret-0123456789abcdefghijklmno"


@pytest.fixture
def s3(tmp_path):
    harness = Harness(tmp_path)
    # A user that may read/write objects but has no tagging/lifecycle/versioning rights.
    ref, _ = harness.store.replace(
        None, {"access_key_id": TAGGER_AK, "secret_access_key": TAGGER_SECRET}
    )
    harness.config["identities"].append(
        {
            "id": "00000000-0000-0000-0000-000000000004",
            "name": "writer",
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
                            "s3:ListBucket",
                            "s3:GetObjectTagging",
                        ],
                        "Resource": ["arn:aws:s3:::backups", "arn:aws:s3:::backups/*"],
                    }
                ],
            },
            "keys": [{"access_key_id": TAGGER_AK, "secret_ref": ref, "enabled": True}],
        }
    )
    harness.reload()
    yield harness
    harness.stop()


def _code(exc: pytest.ExceptionInfo) -> str:
    return exc.value.response["Error"]["Code"]


def _tags(response) -> dict[str, str]:
    return {item["Key"]: item["Value"] for item in response["TagSet"]}


# ----------------------------------------------------------------------------- object tagging


def test_object_tagging_roundtrip_and_limits(s3: Harness) -> None:
    client = s3.client()
    client.put_object(Bucket="backups", Key="t.txt", Body=b"x", Tagging="a=1&b=two%20words")
    assert _tags(client.get_object_tagging(Bucket="backups", Key="t.txt")) == {
        "a": "1",
        "b": "two words",
    }
    assert (
        client.head_object(Bucket="backups", Key="t.txt")["ResponseMetadata"]["HTTPHeaders"][
            "x-amz-tagging-count"
        ]
        == "2"
    )
    client.put_object_tagging(
        Bucket="backups",
        Key="t.txt",
        Tagging={"TagSet": [{"Key": "env", "Value": "prod"}, {"Key": "é", "Value": "ü"}]},
    )
    assert _tags(client.get_object_tagging(Bucket="backups", Key="t.txt")) == {
        "env": "prod",
        "é": "ü",
    }
    # Tagging does not touch the data or the ETag.
    assert client.get_object(Bucket="backups", Key="t.txt")["Body"].read() == b"x"
    client.delete_object_tagging(Bucket="backups", Key="t.txt")
    assert client.get_object_tagging(Bucket="backups", Key="t.txt")["TagSet"] == []

    too_many = {"TagSet": [{"Key": f"k{i}", "Value": "v"} for i in range(11)]}
    with pytest.raises(ClientError) as exc:
        client.put_object_tagging(Bucket="backups", Key="t.txt", Tagging=too_many)
    assert _code(exc) == "InvalidTag"
    with pytest.raises(ClientError) as exc:
        client.put_object_tagging(
            Bucket="backups", Key="t.txt", Tagging={"TagSet": [{"Key": "k" * 129, "Value": ""}]}
        )
    assert _code(exc) == "InvalidTag"
    with pytest.raises(ClientError) as exc:
        client.put_object_tagging(
            Bucket="backups", Key="t.txt", Tagging={"TagSet": [{"Key": "k", "Value": "v" * 257}]}
        )
    assert _code(exc) == "InvalidTag"
    with pytest.raises(ClientError) as exc:
        client.put_object(Bucket="backups", Key="bad", Body=b"", Tagging="a=1&a=2")
    assert _code(exc) == "InvalidTag"
    with pytest.raises(ClientError) as exc:
        client.get_object_tagging(Bucket="backups", Key="missing")
    assert _code(exc) == "NoSuchKey"


def test_object_tagging_copy_directive_and_multipart(s3: Harness) -> None:
    client = s3.client()
    client.put_object(Bucket="backups", Key="src", Body=b"data", Tagging="keep=yes")
    client.copy_object(Bucket="backups", Key="copy1", CopySource="backups/src")
    assert _tags(client.get_object_tagging(Bucket="backups", Key="copy1")) == {"keep": "yes"}
    client.copy_object(
        Bucket="backups",
        Key="copy2",
        CopySource="backups/src",
        TaggingDirective="REPLACE",
        Tagging="new=1",
    )
    assert _tags(client.get_object_tagging(Bucket="backups", Key="copy2")) == {"new": "1"}
    # Copy onto itself is allowed when only the tags change.
    client.copy_object(
        Bucket="backups",
        Key="src",
        CopySource="backups/src",
        TaggingDirective="REPLACE",
        Tagging="",
    )
    assert client.get_object_tagging(Bucket="backups", Key="src")["TagSet"] == []
    upload = client.create_multipart_upload(Bucket="backups", Key="mp", Tagging="mp=1")
    part = client.upload_part(
        Bucket="backups", Key="mp", UploadId=upload["UploadId"], PartNumber=1, Body=b"z"
    )
    client.complete_multipart_upload(
        Bucket="backups",
        Key="mp",
        UploadId=upload["UploadId"],
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": part["ETag"]}]},
    )
    assert _tags(client.get_object_tagging(Bucket="backups", Key="mp")) == {"mp": "1"}


def test_object_tagging_on_linked_folder(s3: Harness) -> None:
    client = s3.client()
    (s3.links / "files" / "ext.txt").write_text("external", encoding="utf-8")
    client.put_object_tagging(
        Bucket="files", Key="ext.txt", Tagging={"TagSet": [{"Key": "a", "Value": "b"}]}
    )
    assert _tags(client.get_object_tagging(Bucket="files", Key="ext.txt")) == {"a": "b"}
    assert (s3.links / "files" / "ext.txt").read_text(encoding="utf-8") == "external"
    (s3.links / "readonly" / "ro.txt").write_text("ro", encoding="utf-8")
    with pytest.raises(ClientError) as exc:
        client.put_object_tagging(
            Bucket="readonly", Key="ro.txt", Tagging={"TagSet": [{"Key": "a", "Value": "b"}]}
        )
    assert _code(exc) == "AccessDenied"


def test_tagging_policy_denials(s3: Harness) -> None:
    admin = s3.client()
    admin.put_object(Bucket="backups", Key="p", Body=b"1", Tagging="a=1")
    writer = s3.client(TAGGER_AK, TAGGER_SECRET)
    assert _tags(writer.get_object_tagging(Bucket="backups", Key="p")) == {"a": "1"}
    tagset = {"TagSet": [{"Key": "x", "Value": "y"}]}
    for call in (
        lambda: writer.put_object_tagging(Bucket="backups", Key="p", Tagging=tagset),
        lambda: writer.delete_object_tagging(Bucket="backups", Key="p"),
        lambda: writer.put_bucket_tagging(Bucket="backups", Tagging=tagset),
        lambda: writer.get_bucket_tagging(Bucket="backups"),
        lambda: writer.get_bucket_lifecycle_configuration(Bucket="backups"),
        lambda: writer.put_bucket_versioning(
            Bucket="backups", VersioningConfiguration={"Status": "Enabled"}
        ),
        lambda: writer.list_object_versions(Bucket="backups"),
    ):
        with pytest.raises(ClientError) as exc:
            call()
        assert _code(exc) == "AccessDenied"
    reader = s3.client(RO_AK, RO_SECRET)
    with pytest.raises(ClientError) as exc:
        reader.get_object_tagging(Bucket="backups", Key="p")
    assert _code(exc) == "AccessDenied"
    assert _tags(admin.get_object_tagging(Bucket="backups", Key="p")) == {"a": "1"}


# ----------------------------------------------------------------------------- bucket tagging


def test_bucket_tagging(s3: Harness) -> None:
    client = s3.client()
    with pytest.raises(ClientError) as exc:
        client.get_bucket_tagging(Bucket="backups")
    assert _code(exc) == "NoSuchTagSet"
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404
    client.put_bucket_tagging(
        Bucket="backups", Tagging={"TagSet": [{"Key": "team", "Value": "ops"}]}
    )
    assert _tags(client.get_bucket_tagging(Bucket="backups")) == {"team": "ops"}
    many = {"TagSet": [{"Key": f"k{i}", "Value": "v"} for i in range(50)]}
    client.put_bucket_tagging(Bucket="backups", Tagging=many)
    assert len(client.get_bucket_tagging(Bucket="backups")["TagSet"]) == 50
    many["TagSet"].append({"Key": "k50", "Value": "v"})
    with pytest.raises(ClientError) as exc:
        client.put_bucket_tagging(Bucket="backups", Tagging=many)
    assert _code(exc) == "InvalidTag"
    client.delete_bucket_tagging(Bucket="backups")
    with pytest.raises(ClientError) as exc:
        client.get_bucket_tagging(Bucket="backups")
    assert _code(exc) == "NoSuchTagSet"
    # The bucket itself is still there (DELETE ?tagging must not hit the bucket delete path).
    client.head_bucket(Bucket="backups")


# ----------------------------------------------------------------------------- lifecycle


LIFECYCLE = {
    "Rules": [
        {
            "ID": "logs",
            "Status": "Enabled",
            "Filter": {"Prefix": "logs/"},
            "Expiration": {"Days": 1},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 2},
        },
        {
            "ID": "tmp-tagged",
            "Status": "Enabled",
            "Filter": {"And": {"Prefix": "data/", "Tags": [{"Key": "tmp", "Value": "1"}]}},
            "Expiration": {"Days": 3},
        },
        {"ID": "off", "Status": "Disabled", "Filter": {}, "Expiration": {"Days": 1}},
    ]
}


def test_lifecycle_config_roundtrip_and_validation(s3: Harness) -> None:
    client = s3.client()
    with pytest.raises(ClientError) as exc:
        client.get_bucket_lifecycle_configuration(Bucket="backups")
    assert _code(exc) == "NoSuchLifecycleConfiguration"
    client.put_bucket_lifecycle_configuration(Bucket="backups", LifecycleConfiguration=LIFECYCLE)
    rules = client.get_bucket_lifecycle_configuration(Bucket="backups")["Rules"]
    assert [rule["ID"] for rule in rules] == ["logs", "tmp-tagged", "off"]
    assert rules[0]["Filter"] == {"Prefix": "logs/"}
    assert rules[0]["AbortIncompleteMultipartUpload"] == {"DaysAfterInitiation": 2}
    assert rules[1]["Filter"]["And"]["Tags"] == [{"Key": "tmp", "Value": "1"}]
    assert rules[2]["Status"] == "Disabled"

    with pytest.raises(ClientError) as exc:
        client.put_bucket_lifecycle_configuration(
            Bucket="backups",
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "t",
                        "Status": "Enabled",
                        "Filter": {},
                        "Transitions": [{"Days": 30, "StorageClass": "GLACIER"}],
                    }
                ]
            },
        )
    assert _code(exc) == "NotImplemented"
    with pytest.raises(ClientError) as exc:
        client.put_bucket_lifecycle_configuration(
            Bucket="backups",
            LifecycleConfiguration={
                "Rules": [
                    {"ID": "a", "Status": "Enabled", "Filter": {}, "Expiration": {"Days": 1}},
                    {"ID": "a", "Status": "Enabled", "Filter": {}, "Expiration": {"Days": 2}},
                ]
            },
        )
    assert _code(exc) == "InvalidArgument"
    client.delete_bucket_lifecycle(Bucket="backups")
    with pytest.raises(ClientError) as exc:
        client.get_bucket_lifecycle_configuration(Bucket="backups")
    assert _code(exc) == "NoSuchLifecycleConfiguration"
    client.head_bucket(Bucket="backups")


def test_lifecycle_worker_dry_run_and_apply(s3: Harness) -> None:
    client = s3.client()
    client.put_bucket_lifecycle_configuration(Bucket="backups", LifecycleConfiguration=LIFECYCLE)
    client.put_object(Bucket="backups", Key="logs/a.log", Body=b"12345")
    client.put_object(Bucket="backups", Key="logs/b.log", Body=b"123")
    client.put_object(Bucket="backups", Key="keep.txt", Body=b"k")
    client.put_object(Bucket="backups", Key="data/x", Body=b"x", Tagging="tmp=1")
    client.put_object(Bucket="backups", Key="data/y", Body=b"y", Tagging="tmp=0")
    stale = client.create_multipart_upload(Bucket="backups", Key="logs/big")["UploadId"]
    bucket = s3.engine.bucket("backups")

    now = time.time_ns()
    nothing = lifecycle.run_bucket(bucket, now, dry_run=True)
    assert nothing["objects"] == 0 and nothing["uploads"] == 0

    later = now + 2 * DAY_NS + 60 * 1_000_000_000
    preview = lifecycle.run_bucket(bucket, later, dry_run=True)
    assert preview["objects"] == 2 and preview["bytes"] == 8
    assert preview["rules"] == {"logs": 2}
    assert preview["dry_run"] is True
    # Dry run deletes nothing.
    assert client.get_object(Bucket="backups", Key="logs/a.log")["Body"].read() == b"12345"

    much_later = now + 5 * DAY_NS
    report = s3.engine.lifecycle_once(much_later)["backups"]
    assert report["objects"] == 3 and report["uploads"] == 1
    assert report["rules"] == {"logs": 3, "tmp-tagged": 1}
    keys = sorted(item["Key"] for item in client.list_objects_v2(Bucket="backups")["Contents"])
    assert keys == ["data/y", "keep.txt"]
    assert bucket.index.get_upload(stale) is None
    assert lifecycle.last_run(bucket)["objects"] == 3

    # Admin API: config + dry-run preview for the panel.
    base = f"http://127.0.0.1:{s3.admin_port}"
    headers = {"X-MRK-Admin-Token": s3.engine.admin_token}
    info = httpx.get(f"{base}/admin/buckets/backups/lifecycle", headers=headers).json()
    assert [rule["id"] for rule in info["rules"]] == ["logs", "tmp-tagged", "off"]
    assert info["last_run"]["objects"] == 3
    dry = httpx.post(f"{base}/admin/buckets/backups/lifecycle/preview", headers=headers).json()
    assert dry["dry_run"] is True and dry["objects"] == 0
    assert httpx.post(f"{base}/admin/lifecycle/run", headers=headers).json()["ok"] is True


def test_lifecycle_policy_denied(s3: Harness) -> None:
    writer = s3.client(TAGGER_AK, TAGGER_SECRET)
    with pytest.raises(ClientError) as exc:
        writer.put_bucket_lifecycle_configuration(
            Bucket="backups", LifecycleConfiguration=LIFECYCLE
        )
    assert _code(exc) == "AccessDenied"
    with pytest.raises(ClientError) as exc:
        writer.delete_bucket_lifecycle(Bucket="backups")
    assert _code(exc) == "AccessDenied"


def test_lifecycle_parse_rules_unit() -> None:
    body = (
        b"<LifecycleConfiguration><Rule><ID>d</ID><Prefix>old/</Prefix><Status>Enabled</Status>"
        b"<Expiration><Date>2030-01-01T00:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>"
    )
    rules = lifecycle.parse_config(body)
    assert rules[0]["legacy_prefix"] is True and rules[0]["prefix"] == "old/"
    assert b"<Prefix>old/</Prefix>" in lifecycle.to_xml(rules)
    assert b"2030-01-01T00:00:00.000Z" in lifecycle.to_xml(rules)
    with pytest.raises(S3Error) as exc:
        lifecycle.parse_config(body.replace(b"T00:00:00Z", b"T05:00:00Z"))
    assert exc.value.code == "InvalidArgument"
    with pytest.raises(S3Error) as exc:
        lifecycle.parse_config(
            b"<LifecycleConfiguration><Rule><ID>x</ID><Filter/><Status>Enabled</Status></Rule></LifecycleConfiguration>"
        )
    assert exc.value.code == "InvalidRequest"
    # Rounded up to the next midnight UTC.
    assert lifecycle.due_ns(1, 1) == 2 * DAY_NS
    assert lifecycle.due_ns(0, 1) == DAY_NS
    assert Engine.seconds_until_hour(3, now=0.0) == 3 * 3600
    assert Engine.seconds_until_hour(3, now=4 * 3600.0) == 23 * 3600


# ----------------------------------------------------------------------------- versioning


def _versions(client, **kwargs):
    result = client.list_object_versions(Bucket="backups", **kwargs)
    return result.get("Versions", []), result.get("DeleteMarkers", [])


def test_unversioned_bucket_lists_null_versions(s3: Harness) -> None:
    client = s3.client()
    assert "Status" not in client.get_bucket_versioning(Bucket="backups")
    client.put_object(Bucket="backups", Key="a", Body=b"1")
    client.put_object(Bucket="backups", Key="a", Body=b"2")
    put = client.put_object(Bucket="backups", Key="b", Body=b"3")
    assert "VersionId" not in put
    versions, markers = _versions(client)
    assert [(v["Key"], v["VersionId"], v["IsLatest"]) for v in versions] == [
        ("a", "null", True),
        ("b", "null", True),
    ]
    assert markers == []
    got = client.get_object(Bucket="backups", Key="a", VersionId="null")
    assert got["Body"].read() == b"2"
    linked = client.list_object_versions(Bucket="files")
    assert linked.get("Versions", []) == []


def test_versioning_lifecycle_of_versions_and_markers(s3: Harness) -> None:
    client = s3.client()
    client.put_object(Bucket="backups", Key="doc", Body=b"pre-versioning")
    client.put_bucket_versioning(Bucket="backups", VersioningConfiguration={"Status": "Enabled"})
    assert client.get_bucket_versioning(Bucket="backups")["Status"] == "Enabled"
    v1 = client.put_object(Bucket="backups", Key="doc", Body=b"one")["VersionId"]
    v2 = client.put_object(Bucket="backups", Key="doc", Body=b"two")["VersionId"]
    assert v1 != v2 and len(v1) == 32 and v1 != "null"
    got = client.get_object(Bucket="backups", Key="doc")
    assert got["Body"].read() == b"two" and got["VersionId"] == v2
    assert client.get_object(Bucket="backups", Key="doc", VersionId=v1)["Body"].read() == b"one"
    old = client.get_object(Bucket="backups", Key="doc", VersionId="null")
    assert old["Body"].read() == b"pre-versioning"
    assert client.head_object(Bucket="backups", Key="doc", VersionId=v1)["ContentLength"] == 3

    versions, markers = _versions(client)
    assert [(v["VersionId"], v["IsLatest"]) for v in versions] == [
        (v2, True),
        (v1, False),
        ("null", False),
    ]
    # Quota/usage counts every version.
    assert s3.engine.bucket("backups").usage() == (1, 3 + 3 + len(b"pre-versioning"))

    deleted = client.delete_object(Bucket="backups", Key="doc")
    assert deleted["DeleteMarker"] is True
    marker_id = deleted["VersionId"]
    with pytest.raises(ClientError) as exc:
        client.get_object(Bucket="backups", Key="doc")
    assert _code(exc) == "NoSuchKey"
    assert exc.value.response["ResponseMetadata"]["HTTPHeaders"]["x-amz-delete-marker"] == "true"
    with pytest.raises(ClientError) as exc:
        client.get_object(Bucket="backups", Key="doc", VersionId=marker_id)
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 405
    assert "Contents" not in client.list_objects_v2(Bucket="backups")
    versions, markers = _versions(client)
    assert [(m["VersionId"], m["IsLatest"]) for m in markers] == [(marker_id, True)]
    assert all(not v["IsLatest"] for v in versions)

    # Removing the delete marker restores the previous version.
    removed = client.delete_object(Bucket="backups", Key="doc", VersionId=marker_id)
    assert removed["DeleteMarker"] is True and removed["VersionId"] == marker_id
    assert client.get_object(Bucket="backups", Key="doc")["Body"].read() == b"two"
    # Permanently deleting the current version promotes the next one.
    client.delete_object(Bucket="backups", Key="doc", VersionId=v2)
    assert client.get_object(Bucket="backups", Key="doc")["Body"].read() == b"one"
    with pytest.raises(ClientError) as exc:
        client.get_object(Bucket="backups", Key="doc", VersionId=v2)
    assert _code(exc) == "NoSuchVersion"

    # Copy from an old version; tags on a specific version.
    client.copy_object(
        Bucket="backups",
        Key="restored",
        CopySource={"Bucket": "backups", "Key": "doc", "VersionId": "null"},
    )
    assert client.get_object(Bucket="backups", Key="restored")["Body"].read() == b"pre-versioning"
    client.put_object_tagging(
        Bucket="backups",
        Key="doc",
        VersionId="null",
        Tagging={"TagSet": [{"Key": "v", "Value": "0"}]},
    )
    assert _tags(client.get_object_tagging(Bucket="backups", Key="doc", VersionId="null")) == {
        "v": "0"
    }
    assert client.get_object_tagging(Bucket="backups", Key="doc")["TagSet"] == []

    # Batch delete with versions.
    result = client.delete_objects(
        Bucket="backups",
        Delete={"Objects": [{"Key": "doc", "VersionId": v1}, {"Key": "restored"}]},
    )
    by_key = {item["Key"]: item for item in result["Deleted"]}
    assert by_key["doc"]["VersionId"] == v1
    assert by_key["restored"]["DeleteMarker"] is True
    assert client.get_object(Bucket="backups", Key="doc")["Body"].read() == b"pre-versioning"

    # Data files of noncurrent versions survive GC/orphan sweeps.
    bucket = s3.engine.bucket("backups")
    future = time.time_ns() + 8 * 86400 * 1_000_000_000
    bucket.gc(future)
    assert bucket.orphan_sweep(min_age_seconds=0) == 0
    restored_versions = [
        v for v in _versions(client, Prefix="restored")[0] if v["Key"] == "restored"
    ]
    assert len(restored_versions) == 1
    data = client.get_object(
        Bucket="backups", Key="restored", VersionId=restored_versions[0]["VersionId"]
    )["Body"].read()
    assert data == b"pre-versioning"


def test_versioning_suspended_and_null_version(s3: Harness) -> None:
    client = s3.client()
    client.put_bucket_versioning(Bucket="backups", VersioningConfiguration={"Status": "Enabled"})
    v1 = client.put_object(Bucket="backups", Key="k", Body=b"v1")["VersionId"]
    client.put_bucket_versioning(Bucket="backups", VersioningConfiguration={"Status": "Suspended"})
    assert client.get_bucket_versioning(Bucket="backups")["Status"] == "Suspended"
    assert client.put_object(Bucket="backups", Key="k", Body=b"n1")["VersionId"] == "null"
    assert client.put_object(Bucket="backups", Key="k", Body=b"n2")["VersionId"] == "null"
    versions, _ = _versions(client)
    assert [(v["VersionId"], v["IsLatest"]) for v in versions] == [("null", True), (v1, False)]
    deleted = client.delete_object(Bucket="backups", Key="k")
    assert deleted["VersionId"] == "null" and deleted["DeleteMarker"] is True
    versions, markers = _versions(client)
    assert [v["VersionId"] for v in versions] == [v1]
    assert [m["VersionId"] for m in markers] == ["null"]


def test_versioning_rules(s3: Harness) -> None:
    client = s3.client()
    with pytest.raises(ClientError) as exc:
        client.put_bucket_versioning(Bucket="files", VersioningConfiguration={"Status": "Enabled"})
    assert _code(exc) == "InvalidBucketState"
    with pytest.raises(ClientError) as exc:
        client.put_bucket_versioning(
            Bucket="backups",
            VersioningConfiguration={"Status": "Enabled", "MFADelete": "Enabled"},
        )
    assert _code(exc) == "NotImplemented"
    # Deleting a version needs s3:DeleteObjectVersion, reading one s3:GetObjectVersion.
    client.put_bucket_versioning(Bucket="backups", VersioningConfiguration={"Status": "Enabled"})
    vid = client.put_object(Bucket="backups", Key="x", Body=b"1")["VersionId"]
    writer = s3.client(TAGGER_AK, TAGGER_SECRET)
    assert writer.get_object(Bucket="backups", Key="x")["Body"].read() == b"1"
    with pytest.raises(ClientError) as exc:
        writer.get_object(Bucket="backups", Key="x", VersionId=vid)
    assert _code(exc) == "AccessDenied"
    with pytest.raises(ClientError) as exc:
        writer.delete_object(Bucket="backups", Key="x", VersionId=vid)
    assert _code(exc) == "AccessDenied"
    # A plain delete is allowed and only adds a marker; the data stays.
    writer.delete_object(Bucket="backups", Key="x")
    assert client.get_object(Bucket="backups", Key="x", VersionId=vid)["Body"].read() == b"1"
    # The bucket is not empty while versions exist.
    base = f"http://127.0.0.1:{s3.admin_port}"
    headers = {"X-MRK-Admin-Token": s3.engine.admin_token}
    assert httpx.delete(f"{base}/admin/buckets/backups?force=0", headers=headers).status_code == 409


def test_list_object_versions_paging_and_delimiter(s3: Harness) -> None:
    client = s3.client()
    client.put_bucket_versioning(Bucket="backups", VersioningConfiguration={"Status": "Enabled"})
    for key in ("a", "b", "dir/1", "dir/2"):
        for body in (b"1", b"2"):
            client.put_object(Bucket="backups", Key=key, Body=body)
    seen = []
    kwargs: dict[str, str | int] = {"MaxKeys": 3}
    while True:
        page = client.list_object_versions(Bucket="backups", **kwargs)
        seen.extend((v["Key"], v["VersionId"]) for v in page.get("Versions", []))
        if not page["IsTruncated"]:
            break
        kwargs = {
            "MaxKeys": 3,
            "KeyMarker": page["NextKeyMarker"],
            "VersionIdMarker": page["NextVersionIdMarker"],
        }
    assert len(seen) == 8 and len(set(seen)) == 8
    assert [key for key, _ in seen] == ["a", "a", "b", "b", "dir/1", "dir/1", "dir/2", "dir/2"]
    rolled = client.list_object_versions(Bucket="backups", Delimiter="/")
    assert [p["Prefix"] for p in rolled["CommonPrefixes"]] == ["dir/"]
    assert {v["Key"] for v in rolled["Versions"]} == {"a", "b"}


def test_lifecycle_noncurrent_expiration_and_markers(s3: Harness) -> None:
    client = s3.client()
    client.put_bucket_versioning(Bucket="backups", VersioningConfiguration={"Status": "Enabled"})
    for body in (b"1", b"22", b"333", b"4444"):
        client.put_object(Bucket="backups", Key="v", Body=body)
    client.put_object(Bucket="backups", Key="gone", Body=b"x")
    gone = client.put_object(Bucket="backups", Key="gone", Body=b"y")["VersionId"]
    client.delete_object(Bucket="backups", Key="gone")
    # Leave only the delete marker of "gone" (plus one noncurrent version, removed below).
    client.delete_object(Bucket="backups", Key="gone", VersionId=gone)
    client.put_bucket_lifecycle_configuration(
        Bucket="backups",
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "nc",
                    "Status": "Enabled",
                    "Filter": {},
                    "NoncurrentVersionExpiration": {
                        "NoncurrentDays": 1,
                        "NewerNoncurrentVersions": 1,
                    },
                },
                {
                    "ID": "markers",
                    "Status": "Enabled",
                    "Filter": {},
                    "Expiration": {"ExpiredObjectDeleteMarker": True},
                },
            ]
        },
    )
    bucket = s3.engine.bucket("backups")
    later = time.time_ns() + 3 * DAY_NS
    preview = lifecycle.run_bucket(bucket, later, dry_run=True)
    # v: 3 noncurrent, the newest one is kept -> "1" and "22" expire. gone: its one
    # noncurrent version "x" is the newest noncurrent (kept); the marker is not alone.
    assert preview["versions"] == 2 and preview["version_bytes"] == 1 + 2
    assert preview["markers"] == 0
    client.delete_objects(
        Bucket="backups",
        Delete={
            "Objects": [
                {"Key": "gone", "VersionId": v["VersionId"]}
                for v in _versions(client, Prefix="gone")[0]
            ]
        },
    )
    report = s3.engine.lifecycle_once(later)["backups"]
    assert report["versions"] == 2 and report["markers"] == 1
    versions, markers = _versions(client)
    assert [(v["Key"], v["IsLatest"]) for v in versions] == [("v", True), ("v", False)]
    assert markers == []
    assert client.get_object(Bucket="backups", Key="v")["Body"].read() == b"4444"
    assert bucket.usage() == (1, 4 + 3)


def test_index_schema_upgrade_keeps_old_data(tmp_path) -> None:
    import sqlite3

    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE objects (key TEXT PRIMARY KEY, size INTEGER NOT NULL, etag TEXT NOT NULL,"
        " last_modified_ns INTEGER NOT NULL, meta TEXT NOT NULL, layout TEXT NOT NULL,"
        " mtime_ns INTEGER, inode TEXT, dev TEXT) WITHOUT ROWID;"
        "INSERT INTO objects VALUES ('k', 1, 'e', 5, '{}', '[]', NULL, NULL, NULL);"
    )
    conn.commit()
    conn.close()
    index = BucketIndex(path)
    try:
        assert index.get("k") == ObjectRecord("k", 1, "e", 5, {}, [])
        assert [v.version_id for v in index.versions_for("k")] == ["null"]
        assert index.get_setting("versioning") is None
    finally:
        index.close()
