# ruff: noqa: E501, S105, S106, S311, S324 - fixed test credentials (AWS doc examples),
# MD5 only to compare S3 ETags, seeded RNG for the listing model, long test vectors.
"""Unit tests for the native S3 engine: SigV4, aws-chunked, checksums, policy, listing."""

from __future__ import annotations

import asyncio
import hashlib
import os
import zlib
from datetime import UTC, datetime, timedelta

import pytest
from mrk_control_plane import s3sigv4 as sig
from mrk_control_plane.s3engine import checksums
from mrk_control_plane.s3engine.chunked import AwsChunkedDecoder
from mrk_control_plane.s3engine.errors import S3Error
from mrk_control_plane.s3engine.listing import Entry, list_page
from mrk_control_plane.s3engine.policy import ALLOW, DENY, IMPLICIT, RequestContext, evaluate
from mrk_control_plane.s3engine.xmlio import parse_xml

# AWS documentation example credentials (sig-v4-header-based-auth / sigv4-streaming).
AK = "AKIAIOSFODNN7EXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATE = "20130524T000000Z"
NOW = datetime(2013, 5, 24, tzinfo=UTC)
SCOPE = "20130524/us-east-1/s3/aws4_request"
KEY = sig.derive_signing_key(SECRET, "20130524", "us-east-1")


def _sign(method: str, path: str, query: str, headers: dict[str, str], payload: str) -> str:
    normalized = {name: sig.normalize_header_value(value) for name, value in headers.items()}
    canonical = sig.canonical_request(
        method,
        sig.canonical_uri(path),
        sig.canonical_query(query),
        normalized,
        sorted(normalized),
        payload,
    )
    return sig.signature(KEY, sig.string_to_sign(DATE, SCOPE, canonical))


def _lookup(akid: str) -> str | None:
    return SECRET if akid == AK else None


# ----------------------------------------------------------------------------- AWS vectors


def test_aws_get_object_range_vector() -> None:
    headers = {
        "host": "examplebucket.s3.amazonaws.com",
        "range": "bytes=0-9",
        "x-amz-content-sha256": sig.EMPTY_SHA256,
        "x-amz-date": DATE,
    }
    assert _sign("GET", "/test.txt", "", headers, sig.EMPTY_SHA256) == (
        "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    )


def test_aws_put_object_vector() -> None:
    payload = hashlib.sha256(b"Welcome to Amazon S3.").hexdigest()
    headers = {
        "host": "examplebucket.s3.amazonaws.com",
        "date": "Fri, 24 May 2013 00:00:00 GMT",
        "x-amz-date": DATE,
        "x-amz-storage-class": "REDUCED_REDUNDANCY",
        "x-amz-content-sha256": payload,
    }
    assert _sign("PUT", "/test%24file.text", "", headers, payload) == (
        "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
    )


def test_aws_lifecycle_and_list_vectors() -> None:
    base = {
        "host": "examplebucket.s3.amazonaws.com",
        "x-amz-date": DATE,
        "x-amz-content-sha256": sig.EMPTY_SHA256,
    }
    assert _sign("GET", "/", "lifecycle", base, sig.EMPTY_SHA256) == (
        "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
    )
    assert _sign("GET", "/", "max-keys=2&prefix=J", base, sig.EMPTY_SHA256) == (
        "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
    )


def test_aws_presigned_vector_and_verification() -> None:
    url = sig.presign_url(
        "GET",
        "https://examplebucket.s3.amazonaws.com/test.txt",
        access_key_id=AK,
        secret_access_key=SECRET,
        region="us-east-1",
        expires=86400,
        now=NOW,
    )
    assert url.endswith(
        "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    )
    query = url.split("?", 1)[1]
    verified = sig.verify_request(
        "GET",
        "/test.txt",
        query,
        [("host", "examplebucket.s3.amazonaws.com")],
        _lookup,
        now=NOW + timedelta(hours=1),
    )
    assert verified is not None and verified.auth_type == "query"
    with pytest.raises(sig.SigV4Error) as expired:
        sig.verify_request(
            "GET",
            "/test.txt",
            query,
            [("host", "examplebucket.s3.amazonaws.com")],
            _lookup,
            now=NOW + timedelta(days=2),
        )
    assert expired.value.code == "AccessDenied" and "expired" in expired.value.message
    with pytest.raises(sig.SigV4Error) as tampered:
        sig.verify_request(
            "GET",
            "/test2.txt",
            query,
            [("host", "examplebucket.s3.amazonaws.com")],
            _lookup,
            now=NOW + timedelta(hours=1),
        )
    assert tampered.value.code == "SignatureDoesNotMatch"


def test_aws_streaming_chunk_signature_vectors() -> None:
    headers = {
        "host": "s3.amazonaws.com",
        "x-amz-date": DATE,
        "x-amz-storage-class": "REDUCED_REDUNDANCY",
        "x-amz-content-sha256": sig.STREAMING_SIGNED,
        "content-encoding": "aws-chunked",
        "x-amz-decoded-content-length": "66560",
        "content-length": "66824",
    }
    seed = _sign("PUT", "/examplebucket/chunkObject.txt", "", headers, sig.STREAMING_SIGNED)
    assert seed == "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
    first = sig.chunk_signature(KEY, DATE, SCOPE, seed, hashlib.sha256(b"a" * 65536).hexdigest())
    assert first == "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"
    second = sig.chunk_signature(KEY, DATE, SCOPE, first, hashlib.sha256(b"a" * 1024).hexdigest())
    assert second == "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497"
    final = sig.chunk_signature(KEY, DATE, SCOPE, second, sig.EMPTY_SHA256)
    assert final == "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9"


# ----------------------------------------------------------------------------- canonicalization


def test_canonical_uri_does_not_double_encode_or_normalize() -> None:
    assert sig.canonical_uri("/b/a%2Fb/c") == "/b/a%2Fb/c"
    assert sig.canonical_uri("/b/%252F") == "/b/%252F"
    assert sig.canonical_uri("/b/a b+c") == "/b/a%20b%2Bc"
    assert sig.canonical_uri("/b//x/./../y") == "/b//x/./../y"
    assert sig.canonical_uri("/b/%e2%82%ac~") == "/b/%E2%82%AC~"


def test_canonical_query_sorting_and_empty_values() -> None:
    assert sig.canonical_query("uploads") == "uploads="
    assert sig.canonical_query("b=2&a=1&a=0") == "a=0&a=1&b=2"
    assert sig.canonical_query("prefix=a+b&x=%7e") == "prefix=a%2Bb&x=~"


def test_header_folding_and_duplicates() -> None:
    headers = sig.header_map([("X-Amz-Meta-A", "  one   two "), ("x-amz-meta-a", "three")])
    assert headers["x-amz-meta-a"] == "one two,three"


# ----------------------------------------------------------------------------- botocore interop


def _botocore_request(
    method: str, url: str, body: bytes = b"", headers: dict[str, str] | None = None
):
    botocore = pytest.importorskip("botocore")
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    del botocore
    request = AWSRequest(method=method, url=url, data=body, headers=headers or {})
    S3SigV4Auth(Credentials(AK, SECRET), "s3", "us-east-1").add_auth(request)
    return request


@pytest.mark.parametrize(
    "path",
    [
        "/bucket/simple.txt",
        "/bucket/dir/with%20space/%E2%82%AC.txt",
        "/bucket/a%2Bb%3Dc%21%40.bin",
        "/bucket",
    ],
)
def test_verifier_accepts_botocore_signatures(path: str) -> None:
    request = _botocore_request(
        "PUT", f"http://127.0.0.1:9000{path}?uploads", b"hello", {"x-amz-meta-k": "v"}
    )
    headers = [(name.lower(), value) for name, value in request.headers.items()]
    headers.append(("host", "127.0.0.1:9000"))
    verified = sig.verify_request("PUT", path, "uploads", headers, _lookup)
    assert verified is not None and verified.access_key_id == AK


def test_signer_matches_botocore() -> None:
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    now = datetime.now(UTC).replace(microsecond=0)
    ours = sig.sign_request(
        "GET",
        "http://127.0.0.1:9000/bucket/key%20x?list-type=2&prefix=a",
        {"x-amz-meta-z": "1"},
        access_key_id=AK,
        secret_access_key=SECRET,
        region="us-east-1",
        payload_hash=sig.EMPTY_SHA256,
        now=now,
    )
    request = AWSRequest(
        method="GET",
        url="http://127.0.0.1:9000/bucket/key%20x?list-type=2&prefix=a",
        headers={
            "x-amz-meta-z": "1",
            "x-amz-date": ours["x-amz-date"],
            "x-amz-content-sha256": sig.EMPTY_SHA256,
        },
    )
    auth = S3SigV4Auth(Credentials(AK, SECRET), "s3", "us-east-1")
    auth._modify_request_before_signing = lambda req: None  # keep our date/payload headers
    request.context["timestamp"] = ours["x-amz-date"]
    canonical = auth.canonical_request(request)
    expected = auth.signature(auth.string_to_sign(request, canonical), request)
    assert ours["authorization"].endswith(f"Signature={expected}")


def test_unsigned_amz_header_and_skew_rejected() -> None:
    signed = sig.sign_request(
        "GET", "http://h/b/k", {}, access_key_id=AK, secret_access_key=SECRET, region="us-east-1"
    )
    headers = list(signed.items()) + [("x-amz-copy-source", "/other/secret")]
    with pytest.raises(sig.SigV4Error) as unsigned:
        sig.verify_request("GET", "/b/k", "", headers, _lookup)
    assert unsigned.value.code == "AccessDenied"
    old = sig.sign_request(
        "GET",
        "http://h/b/k",
        {},
        access_key_id=AK,
        secret_access_key=SECRET,
        region="us-east-1",
        now=datetime.now(UTC) - timedelta(minutes=20),
    )
    with pytest.raises(sig.SigV4Error) as skew:
        sig.verify_request("GET", "/b/k", "", list(old.items()), _lookup)
    assert skew.value.code == "RequestTimeTooSkewed"


def test_sigv2_and_unknown_keys_rejected() -> None:
    with pytest.raises(sig.SigV4Error) as v2:
        sig.verify_request(
            "GET", "/b", "", [("authorization", "AWS AK:sig"), ("host", "h")], _lookup
        )
    assert v2.value.code == "InvalidRequest"
    signed = sig.sign_request(
        "GET", "http://h/b", {}, access_key_id="NOPE", secret_access_key="x", region="r"
    )
    with pytest.raises(sig.SigV4Error) as unknown:
        sig.verify_request("GET", "/b", "", list(signed.items()), _lookup)
    assert unknown.value.code == "InvalidAccessKeyId"
    with pytest.raises(sig.SigV4Error) as region:
        signed = sig.sign_request(
            "GET", "http://h/b", {}, access_key_id=AK, secret_access_key=SECRET, region="eu-x"
        )
        sig.verify_request("GET", "/b", "", list(signed.items()), _lookup, region="us-east-1")
    assert region.value.code == "AuthorizationHeaderMalformed"


# ----------------------------------------------------------------------------- aws-chunked


async def _aiter(pieces):
    for piece in pieces:
        yield piece


def _decode(body: bytes, *, mode: str, verified=None, trailers=frozenset(), length=None, split=7):
    async def run():
        pieces = [body[i : i + split] for i in range(0, len(body), split)]
        decoder = AwsChunkedDecoder(
            _aiter(pieces),
            mode=mode,
            verified=verified,
            declared_trailers=set(trailers),
            decoded_length=length,
            max_chunk_bytes=1 << 24,
        )
        out = bytearray()
        async for piece in decoder:
            out += piece
        return bytes(out), decoder.trailers

    return asyncio.run(run())


def _signed_context(payload_mode: str) -> sig.VerifiedRequest:
    headers = sig.sign_request(
        "PUT",
        "http://h/b/k",
        {"content-encoding": "aws-chunked"},
        access_key_id=AK,
        secret_access_key=SECRET,
        region="us-east-1",
        payload_hash=payload_mode,
    )
    verified = sig.verify_request("PUT", "/b/k", "", list(headers.items()), _lookup)
    assert verified is not None
    return verified


@pytest.mark.parametrize("split", [1, 3, 64, 100000])
def test_signed_chunked_roundtrip_at_every_split(split: int) -> None:
    verified = _signed_context(sig.STREAMING_SIGNED)
    signer = sig.ChunkedPayloadSigner(
        verified.signing_key, verified.amz_date, verified.credential.scope, verified.signature
    )
    data = os.urandom(300)
    body = signer.chunk(data[:200]) + signer.chunk(data[200:]) + signer.final()
    out, _ = _decode(body, mode=sig.STREAMING_SIGNED, verified=verified, length=300, split=split)
    assert out == data


def test_signed_chunk_tampering_detected() -> None:
    verified = _signed_context(sig.STREAMING_SIGNED)
    signer = sig.ChunkedPayloadSigner(
        verified.signing_key, verified.amz_date, verified.credential.scope, verified.signature
    )
    body = bytearray(signer.chunk(b"hello world") + signer.final())
    body[body.index(b"hello")] = ord("j")
    with pytest.raises(S3Error) as exc:
        _decode(bytes(body), mode=sig.STREAMING_SIGNED, verified=verified)
    assert exc.value.code == "SignatureDoesNotMatch"


def test_signed_trailer_roundtrip_and_tamper() -> None:
    verified = _signed_context(sig.STREAMING_SIGNED_TRAILER)
    signer = sig.ChunkedPayloadSigner(
        verified.signing_key, verified.amz_date, verified.credential.scope, verified.signature
    )
    data = b"payload-with-trailer"
    crc = checksums.compute("CRC32C", data)
    body = signer.chunk(data) + signer.final([("x-amz-checksum-crc32c", crc)])
    out, trailers = _decode(
        body,
        mode=sig.STREAMING_SIGNED_TRAILER,
        verified=verified,
        trailers={"x-amz-checksum-crc32c"},
    )
    assert out == data and trailers == {"x-amz-checksum-crc32c": crc}
    forged = body.replace(crc.encode(), checksums.compute("CRC32C", b"x").encode())
    with pytest.raises(S3Error) as exc:
        _decode(
            forged,
            mode=sig.STREAMING_SIGNED_TRAILER,
            verified=verified,
            trailers={"x-amz-checksum-crc32c"},
        )
    assert exc.value.code == "SignatureDoesNotMatch"


def test_unsigned_trailer_like_botocore() -> None:
    data = b"x" * 1000
    crc = checksums.compute("CRC32", data)
    body = b"3e8\r\n" + data + b"\r\n" + b"0\r\nx-amz-checksum-crc32:" + crc.encode() + b"\r\n\r\n"
    out, trailers = _decode(
        body, mode=sig.STREAMING_UNSIGNED_TRAILER, trailers={"x-amz-checksum-crc32"}, length=1000
    )
    assert out == data and trailers["x-amz-checksum-crc32"] == crc
    with pytest.raises(S3Error) as short:
        _decode(
            body,
            mode=sig.STREAMING_UNSIGNED_TRAILER,
            trailers={"x-amz-checksum-crc32"},
            length=1001,
        )
    assert short.value.code == "IncompleteBody"
    with pytest.raises(S3Error) as undeclared:
        _decode(body, mode=sig.STREAMING_UNSIGNED_TRAILER, trailers=set(), length=1000)
    assert undeclared.value.code == "InvalidArgument"
    with pytest.raises(S3Error):
        _decode(b"zz\r\n", mode=sig.STREAMING_UNSIGNED_TRAILER)


# ----------------------------------------------------------------------------- checksums


def test_crc_check_values_and_fallback() -> None:
    assert checksums.new_hasher("CRC32C").__class__.__name__ == "_Crc"
    assert checksums.py_crc32c(b"123456789") == 0xE3069283
    assert checksums.py_crc64nvme(b"123456789") == 0xAE8B14860A799888
    data = os.urandom(4097)
    for name, py in (("CRC32C", checksums.py_crc32c), ("CRC64NVME", checksums.py_crc64nvme)):
        hasher = checksums.new_hasher(name)
        hasher.update(data[:1000])
        hasher.update(data[1000:])
        assert hasher.value == py(data)
    assert checksums.compute("CRC32", data) == checksums.b64(zlib.crc32(data).to_bytes(4, "big"))


@pytest.mark.parametrize("name", ["CRC32", "CRC32C", "CRC64NVME"])
def test_crc_combine_matches_direct(name: str) -> None:
    parts = [os.urandom(n) for n in (1, 5000, 70000, 3)]
    digests = []
    for part in parts:
        hasher = checksums.new_hasher(name)
        hasher.update(part)
        digests.append((hasher.digest(), len(part)))
    whole = checksums.new_hasher(name)
    whole.update(b"".join(parts))
    assert checksums.combine_full_object(name, digests) == whole.digest()


# ----------------------------------------------------------------------------- policy


def test_policy_allow_deny_wildcards_and_conditions() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:Get*", "s3:PutObject"],
                "Resource": "arn:aws:s3:::backups/dokploy/*",
            },
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:mrk:s3:::backups",
                "Condition": {"StringLike": {"s3:prefix": ["dokploy/*", "dokploy/"]}},
            },
            {
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::backups/dokploy/secret*",
            },
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::home/${aws:username}/*",
            },
        ],
    }
    ctx = RequestContext(username="alice")
    assert evaluate([policy], "s3:GetObject", "arn:aws:s3:::backups/dokploy/a.sql", ctx) == ALLOW
    assert evaluate([policy], "S3:getobject", "arn:aws:s3:::backups/dokploy/a.sql", ctx) == ALLOW
    assert (
        evaluate([policy], "s3:DeleteObject", "arn:aws:s3:::backups/dokploy/a.sql", ctx) == IMPLICIT
    )
    assert (
        evaluate([policy], "s3:GetObject", "arn:aws:s3:::backups/dokploy/secret.txt", ctx) == DENY
    )
    assert evaluate([policy], "s3:GetObject", "arn:aws:s3:::backups/other/a", ctx) == IMPLICIT
    listing = RequestContext(values={"s3:prefix": "dokploy/2026"})
    assert evaluate([policy], "s3:ListBucket", "arn:aws:s3:::backups", listing) == ALLOW
    assert (
        evaluate(
            [policy],
            "s3:ListBucket",
            "arn:aws:s3:::backups",
            RequestContext(values={"s3:prefix": "x"}),
        )
        == IMPLICIT
    )
    assert evaluate([policy], "s3:GetObject", "arn:aws:s3:::home/alice/f", ctx) == ALLOW
    assert evaluate([policy], "s3:GetObject", "arn:aws:s3:::home/bob/f", ctx) == IMPLICIT


def test_policy_unknown_operator_fails_closed() -> None:
    allow = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {"Weird": {"a": "b"}},
            }
        ]
    }
    deny = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {"Weird": {"a": "b"}},
            }
        ]
    }
    full = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    assert evaluate([allow], "s3:GetObject", "arn:aws:s3:::b/k", RequestContext()) == IMPLICIT
    assert evaluate([full, deny], "s3:GetObject", "arn:aws:s3:::b/k", RequestContext()) == DENY
    ip = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {"NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            }
        ]
    }
    assert evaluate([full, ip], "s3:GetObject", "x", RequestContext(source_ip="10.1.2.3")) == ALLOW
    assert evaluate([full, ip], "s3:GetObject", "x", RequestContext(source_ip="8.8.8.8")) == DENY


# ----------------------------------------------------------------------------- listing & xml


def _model(keys, prefix, delimiter, marker, max_keys):
    contents, prefixes = [], []
    for key in sorted(keys):
        if not key.startswith(prefix) or key <= marker:
            continue
        if delimiter and delimiter in key[len(prefix) :]:
            common = key[: key.index(delimiter, len(prefix)) + len(delimiter)]
            if common <= marker or common in prefixes:
                continue
            prefixes.append(common)
        else:
            contents.append(key)
    merged = sorted([(k, "k") for k in contents] + [(p, "p") for p in prefixes])
    return merged[:max_keys], len(merged) > max_keys


def test_listing_matches_reference_model_with_paging() -> None:
    import random

    rng = random.Random(7)
    alphabet = ["a", "b", "/", "-", ".", "é", "z"]
    keys = sorted(
        {"".join(rng.choice(alphabet) for _ in range(rng.randint(1, 6))) for _ in range(400)}
    )

    def source(start: str, inclusive: bool):
        for key in keys:
            if key > start or (inclusive and key == start):
                yield Entry(key)

    for prefix in ["", "a", "a/", "b-"]:
        for delimiter in ["", "/", "-"]:
            for max_keys in [1, 3, 1000]:
                marker = ""
                collected = []
                for _ in range(2000):
                    page = list_page(
                        source, prefix=prefix, delimiter=delimiter, marker=marker, max_keys=max_keys
                    )
                    collected += [(e.key, "k") for e in page.contents] + [
                        (p, "p") for p in page.prefixes
                    ]
                    if not page.truncated:
                        break
                    marker = page.next_marker
                expected, _ = _model(keys, prefix, delimiter, "", 10**9)
                assert sorted(collected) == expected, (prefix, delimiter, max_keys)


def test_xml_parser_rejects_entities() -> None:
    with pytest.raises(S3Error):
        parse_xml(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><Delete>&a;</Delete>')
    root = parse_xml(
        b'<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Object><Key>k</Key></Object></Delete>'
    )
    assert root.tag == "Delete"
