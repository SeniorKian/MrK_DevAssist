"""Minimal S3 client for server backup destinations (AWS Signature Version 4).

Only what backups need: PutObject, multipart upload (create / part / complete /
abort), ListObjectsV2 (one page), GetObject (streamed) and DeleteObject. Works
with AWS, MinIO, ArvanCloud, Liara and our own engine (path-style). Requests
are sent through a caller-provided ``send`` callable so external endpoints go
through ``outbound.py`` (proxy + destination policy) and the local engine
through a plain loopback client. Secrets never appear in errors or logs.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import time
import xml.etree.ElementTree as ET  # noqa: S405 - bounded responses, no entity resolution
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import parse_qsl, quote, urlsplit

import httpx

try:  # shared signer (also used by the S3 engine and panel)
    from .. import s3sigv4 as _shared
except ImportError:  # pragma: no cover
    _shared = None  # type: ignore[assignment]

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
MIN_PART_BYTES = 5 * 1024 * 1024
DEFAULT_PART_BYTES = 8 * 1024 * 1024
MAX_PARTS = 10_000
_MAX_XML_BYTES = 2 * 1024 * 1024
_NS = re.compile(r"^\{[^}]*\}")

Sender = Callable[..., Awaitable[httpx.Response]]


class S3Error(Exception):
    def __init__(self, code: str, status_code: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def _encode(value: str, safe: str = "-_.~") -> str:
    return quote(value, safe=safe)


def encode_key(key: str) -> str:
    return _encode(key, safe="-_.~/")


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret_key: str, date: str, region: str, service: str = "s3") -> bytes:
    k_date = _hmac(("AWS4" + secret_key).encode("utf-8"), date)
    return _hmac(_hmac(_hmac(k_date, region), service), "aws4_request")


def canonical_query(query: str) -> str:
    pairs = parse_qsl(query, keep_blank_values=True)
    return "&".join(f"{_encode(k)}={_encode(v)}" for k, v in sorted(pairs))


def sign_request_fallback(
    method: str,
    url: str,
    headers: dict[str, str],
    payload_sha256: str,
    access_key_id: str,
    secret_access_key: str,
    region: str,
    *,
    service: str = "s3",
    now: float | None = None,
) -> dict[str, str]:
    """Return ``headers`` plus Host, x-amz-date, x-amz-content-sha256 and Authorization."""
    parsed = urlsplit(url)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now if now is not None else time.time()))
    date = stamp[:8]
    host = (parsed.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port and parsed.port != default_port:
        host = f"{host}:{parsed.port}"
    signed = {key.lower(): " ".join(str(value).split()) for key, value in headers.items()}
    signed["host"] = host
    signed["x-amz-date"] = stamp
    signed["x-amz-content-sha256"] = payload_sha256
    names = sorted(signed)
    canonical = "\n".join(
        [
            method.upper(),
            parsed.path or "/",
            canonical_query(parsed.query),
            "".join(f"{name}:{signed[name]}\n" for name in names),
            ";".join(names),
            payload_sha256,
        ]
    )
    scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()]
    )
    signature = hmac.new(
        signing_key(secret_access_key, date, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    result = dict(headers)
    result["Host"] = host
    result["x-amz-date"] = stamp
    result["x-amz-content-sha256"] = payload_sha256
    result["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, "
        f"SignedHeaders={';'.join(names)}, Signature={signature}"
    )
    return result


def sign_request(
    method: str,
    url: str,
    headers: dict[str, str],
    payload_sha256: str,
    access_key_id: str,
    secret_access_key: str,
    region: str,
    *,
    service: str = "s3",
    now: float | None = None,
) -> dict[str, str]:
    """Sign with the shared ``s3sigv4`` module when present, else the local signer."""
    if _shared is None:  # pragma: no cover - the shared signer ships with Gate 18
        return sign_request_fallback(
            method, url, headers, payload_sha256, access_key_id, secret_access_key, region,
            service=service, now=now,
        )
    return _shared.sign_request(
        method,
        url,
        headers,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        region=region,
        payload_hash=payload_sha256,
        now=None if now is None else datetime.fromtimestamp(now, UTC),
        service=service,
    )


@dataclass(frozen=True, slots=True)
class S3Target:
    endpoint: str  # scheme://host[:port], no path
    bucket: str
    region: str
    access_key_id: str
    secret_access_key: str = field(repr=False)
    path_style: bool = True

    def url(self, key: str = "", query: str = "") -> str:
        parsed = urlsplit(self.endpoint)
        path = "/" + encode_key(key) if key else "/"
        if self.path_style:
            base = f"{parsed.scheme}://{parsed.netloc}/{self.bucket}"
            full = base + (path if key else "/")
        else:
            full = f"{parsed.scheme}://{self.bucket}.{parsed.netloc}{path}"
        return full + (f"?{query}" if query else "")


def _xml(body: bytes) -> ET.Element | None:
    if not body or len(body) > _MAX_XML_BYTES or b"<!ENTITY" in body or b"<!DOCTYPE" in body:
        return None
    try:
        return ET.fromstring(body)  # noqa: S314 - see import note
    except ET.ParseError:
        return None


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in element.iter() if _NS.sub("", child.tag) == name]


def _text(element: ET.Element, name: str) -> str | None:
    found = _children(element, name)
    return found[0].text if found and found[0].text is not None else None


def error_code_for(status: int, body: bytes) -> str:
    root = _xml(body)
    code = _text(root, "Code") if root is not None else None
    if status in (401, 403) or code in {
        "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch",
    }:
        return "s3_auth_failed"
    if code == "NoSuchBucket":
        return "s3_bucket_not_found"
    if code == "NoSuchKey" or status == 404:
        return "s3_object_not_found"
    if code == "RequestTimeTooSkewed":
        return "s3_clock_skew"
    return f"s3_http_{status}"


class S3Client:
    def __init__(self, target: S3Target, send: Sender, *, retries: int = 2) -> None:
        self.target = target
        self.send = send
        self.retries = retries

    async def _request(
        self,
        method: str,
        key: str = "",
        query: str = "",
        content: bytes = b"",
        *,
        headers: dict[str, str] | None = None,
        stream: bool = False,
        ok: tuple[int, ...] = (200,),
    ) -> httpx.Response:
        url = self.target.url(key, query)
        payload_hash = hashlib.sha256(content).hexdigest() if content else EMPTY_SHA256
        attempt = 0
        while True:
            signed = sign_request(
                method,
                url,
                dict(headers or {}),
                payload_hash,
                self.target.access_key_id,
                self.target.secret_access_key,
                self.target.region,
            )
            # httpx (or outbound's IP pinning) sets the same Host from the URL.
            signed = {k: v for k, v in signed.items() if k.lower() != "host"}
            try:
                response = await self.send(
                    method, url, headers=signed, content=content or None, stream=True
                )
            except httpx.TransportError:
                if attempt >= self.retries or method == "GET" and stream:
                    raise
                attempt += 1
                await asyncio.sleep(0.5 * attempt)
                continue
            if response.status_code in ok:
                if not stream:
                    await response.aread()
                    await response.aclose()
                return response
            body = b""
            try:
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) > _MAX_XML_BYTES:
                        break
            finally:
                await response.aclose()
            if response.status_code >= 500 and attempt < self.retries:
                attempt += 1
                await asyncio.sleep(0.5 * attempt)
                continue
            raise S3Error(error_code_for(response.status_code, body), response.status_code)

    async def put_object(self, key: str, data: bytes, content_type: str) -> str:
        response = await self._request(
            "PUT", key, content=data, headers={"Content-Type": content_type}
        )
        return response.headers.get("ETag", "").strip('"')

    async def create_multipart(self, key: str, content_type: str) -> str:
        response = await self._request(
            "POST", key, "uploads=", headers={"Content-Type": content_type}
        )
        root = _xml(response.content)
        upload_id = _text(root, "UploadId") if root is not None else None
        if not upload_id:
            raise S3Error("s3_invalid_response")
        return upload_id

    async def upload_part(self, key: str, upload_id: str, number: int, data: bytes) -> str:
        query = f"partNumber={number}&uploadId={_encode(upload_id)}"
        response = await self._request("PUT", key, query, data)
        etag = response.headers.get("ETag")
        if not etag:
            raise S3Error("s3_invalid_response")
        return etag

    async def complete_multipart(
        self, key: str, upload_id: str, parts: list[tuple[int, str]]
    ) -> None:
        body = "<CompleteMultipartUpload>" + "".join(
            f"<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
            for number, etag in parts
        ) + "</CompleteMultipartUpload>"
        response = await self._request(
            "POST",
            key,
            f"uploadId={_encode(upload_id)}",
            body.encode("utf-8"),
            headers={"Content-Type": "application/xml"},
        )
        # S3 may answer 200 with an <Error> body for a failed completion.
        root = _xml(response.content)
        if root is not None and _NS.sub("", root.tag) == "Error":
            raise S3Error(error_code_for(500, response.content), 200)

    async def abort_multipart(self, key: str, upload_id: str) -> None:
        await self._request("DELETE", key, f"uploadId={_encode(upload_id)}", ok=(200, 204, 404))

    async def list_objects(self, prefix: str = "", max_keys: int = 1000) -> list[dict[str, object]]:
        query = f"list-type=2&max-keys={max_keys}&prefix={_encode(prefix)}"
        response = await self._request("GET", "", query)
        root = _xml(response.content)
        if root is None:
            raise S3Error("s3_invalid_response")
        items: list[dict[str, object]] = []
        for content in _children(root, "Contents"):
            key = _text(content, "Key")
            size = _text(content, "Size")
            if key is not None:
                items.append({"key": key, "size": int(size) if size and size.isdigit() else 0})
        return items

    async def delete_object(self, key: str) -> None:
        await self._request("DELETE", key, ok=(200, 204, 404))

    async def get_object(self, key: str) -> httpx.Response:
        """Streamed response; the caller must ``aclose`` it."""
        return await self._request("GET", key, stream=True)


class MultipartUpload:
    """Upload a stream of unknown length: one PUT if small, multipart otherwise.

    At most ``part_size`` + one write's worth of bytes is buffered.
    """

    def __init__(
        self,
        client: S3Client,
        key: str,
        part_size: int = DEFAULT_PART_BYTES,
        content_type: str = "application/octet-stream",
    ) -> None:
        self.client = client
        self.key = key
        self.part_size = part_size
        self.content_type = content_type
        self.buffer = bytearray()
        self.upload_id: str | None = None
        self.parts: list[tuple[int, str]] = []
        self.size = 0

    async def _flush_part(self, data: bytes) -> None:
        if self.upload_id is None:
            self.upload_id = await self.client.create_multipart(self.key, self.content_type)
        number = len(self.parts) + 1
        if number > MAX_PARTS:
            raise S3Error("s3_too_many_parts")
        self.parts.append((number, await self.client.upload_part(
            self.key, self.upload_id, number, data
        )))

    async def write(self, data: bytes) -> None:
        self.buffer.extend(data)
        self.size += len(data)
        while len(self.buffer) >= self.part_size:
            part = bytes(self.buffer[: self.part_size])
            del self.buffer[: self.part_size]
            await self._flush_part(part)

    async def finish(self) -> None:
        if self.upload_id is None:
            await self.client.put_object(self.key, bytes(self.buffer), self.content_type)
        else:
            if self.buffer:
                await self._flush_part(bytes(self.buffer))
            await self.client.complete_multipart(self.key, self.upload_id, self.parts)
        self.buffer.clear()

    async def abort(self) -> None:
        if self.upload_id is not None:
            try:
                await self.client.abort_multipart(self.key, self.upload_id)
            except (S3Error, httpx.HTTPError):
                pass
