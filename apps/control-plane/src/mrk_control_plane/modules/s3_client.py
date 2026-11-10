"""Loopback clients for the S3 engine: SigV4-signed S3 calls and the internal admin API.

The control plane talks to ``s3-engine`` as the hidden ``__mrk_panel__`` identity. The
signer is self-contained (AWS Signature Version 4, header and query/presigned forms) so the
module does not depend on the engine package being importable in the control plane.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import xml.etree.ElementTree as ET  # noqa: S405 - responses come from our own loopback engine
from collections.abc import AsyncIterator, Callable, Iterable
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

ALGORITHM = "AWS4-HMAC-SHA256"
UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
DEFAULT_ENGINE_URL = "http://127.0.0.1:9000"
DEFAULT_ADMIN_URL = "http://127.0.0.1:9001"
ADMIN_TOKEN_HEADER = "X-MRK-Admin-Token"  # noqa: S105 - header name, not a secret
_MAX_ERROR_BODY = 64 * 1024
_MAX_XML_BODY = 16 * 1024 * 1024

# Tests replace this with a factory returning e.g. httpx.MockTransport(fake_engine).
TRANSPORT_FACTORY: Callable[[], httpx.AsyncBaseTransport] | None = None


# docs/44: the engine may run in its own container (image mrk-s3). The add-service
# wizard saves its addresses here; environment variables still win.
REMOTE_FILE = "s3-engine.json"
_REMOTE_PATH: Path | None = None


def configure_remote(data_dir: Path) -> None:
    global _REMOTE_PATH
    _REMOTE_PATH = data_dir / "control-plane" / REMOTE_FILE


def validate_engine_url(value: str) -> str:
    text = value.strip().rstrip("/")
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("S3 engine URL must be http(s)://host:port")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path:
        raise ValueError("S3 engine URL must not contain credentials, a path or a query")
    if any(ch.isspace() for ch in text):
        raise ValueError("S3 engine URL must not contain spaces")
    return text


def remote_config() -> dict[str, str] | None:
    """``{"engine_url", "admin_url"}`` of a separate engine, or None (bundled engine)."""
    if _REMOTE_PATH is None:
        return None
    try:
        payload = json.loads(_REMOTE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    try:
        return {
            "engine_url": validate_engine_url(str(payload["engine_url"])),
            "admin_url": validate_engine_url(str(payload["admin_url"])),
        }
    except (KeyError, ValueError):
        return None


def is_remote() -> bool:
    return remote_config() is not None


def save_remote(engine: str, admin: str) -> dict[str, str]:
    if _REMOTE_PATH is None:
        raise RuntimeError("remote S3 engine path is not configured")
    payload = {"engine_url": validate_engine_url(engine), "admin_url": validate_engine_url(admin)}
    _REMOTE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = _REMOTE_PATH.with_name(f".{REMOTE_FILE}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, _REMOTE_PATH)
    return payload


def engine_url() -> str:
    remote = remote_config()
    fallback = remote["engine_url"] if remote else DEFAULT_ENGINE_URL
    return (os.getenv("MRK_S3_ENGINE_URL", "").strip() or fallback).rstrip("/")


def admin_url() -> str:
    remote = remote_config()
    fallback = remote["admin_url"] if remote else DEFAULT_ADMIN_URL
    return (os.getenv("MRK_S3_ADMIN_URL", "").strip() or fallback).rstrip("/")


def new_client(timeout: httpx.Timeout | float = 30.0) -> httpx.AsyncClient:
    transport = TRANSPORT_FACTORY() if TRANSPORT_FACTORY is not None else None
    # Loopback only: never inherit HTTP(S)_PROXY from the environment.
    return httpx.AsyncClient(transport=transport, timeout=timeout, trust_env=False)


class EngineError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


def unreachable(exc: Exception | None = None) -> EngineError:
    detail = f" ({type(exc).__name__})" if exc is not None else ""
    return EngineError("engine_unreachable", 503, f"the S3 engine is not reachable{detail}")


# ---------------------------------------------------------------- SigV4


def uri_encode(value: str, *, keep_slash: bool = False) -> str:
    """RFC 3986 encoding as SigV4 requires (unreserved: A-Z a-z 0-9 - _ . ~)."""
    return quote(value, safe="/" if keep_slash else "")


def object_path(bucket: str, key: str | None = None) -> str:
    path = "/" + uri_encode(bucket)
    if key is not None:
        path += "/" + uri_encode(key, keep_slash=True)
    return path


def canonical_query(params: Iterable[tuple[str, str]]) -> str:
    encoded = sorted((uri_encode(name), uri_encode(value)) for name, value in params)
    return "&".join(f"{name}={value}" for name, value in encoded)


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret: str, date: str, region: str, service: str = "s3") -> bytes:
    key = _hmac(("AWS4" + secret).encode("utf-8"), date)
    key = _hmac(key, region)
    key = _hmac(key, service)
    return _hmac(key, "aws4_request")


def host_header(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    default = {"http": 80, "https": 443}.get(parts.scheme)
    if parts.port is not None and parts.port != default:
        host = f"{host}:{parts.port}"
    return host


def _signature(
    *,
    method: str,
    path: str,
    query: str,
    headers: dict[str, str],
    payload_hash: str,
    secret: str,
    region: str,
    amz_date: str,
) -> tuple[str, str, str]:
    """Return (signed_headers, signature, credential_scope)."""
    canonical_headers = {
        name.lower(): " ".join(value.strip().split()) for name, value in headers.items()
    }
    names = sorted(canonical_headers)
    signed_headers = ";".join(names)
    canonical_request = "\n".join(
        [
            method,
            path,
            query,
            "".join(f"{name}:{canonical_headers[name]}\n" for name in names),
            signed_headers,
            payload_hash,
        ]
    )
    date = amz_date[:8]
    scope = f"{date}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(
        [ALGORITHM, amz_date, scope, hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()]
    )
    signature = hmac.new(
        signing_key(secret, date, region), string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return signed_headers, signature, scope


def sign_headers(
    *,
    method: str,
    endpoint: str,
    path: str,
    params: list[tuple[str, str]],
    access_key: str,
    secret: str,
    region: str,
    payload_hash: str = UNSIGNED_PAYLOAD,
    extra_headers: dict[str, str] | None = None,
    now: dt.datetime | None = None,
) -> tuple[str, dict[str, str]]:
    """Sign a request with an Authorization header. Returns (url, headers to send)."""
    moment = (now or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)
    amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
    query = canonical_query(params)
    url = f"{endpoint}{path}" + (f"?{query}" if query else "")
    headers = dict(extra_headers or {})
    headers["x-amz-date"] = amz_date
    headers["x-amz-content-sha256"] = payload_hash
    to_sign = {"host": host_header(endpoint)}
    for name, value in headers.items():
        lower = name.lower()
        if lower.startswith("x-amz-") or lower in {"content-md5", "content-type"}:
            to_sign[lower] = value
    signed, signature, scope = _signature(
        method=method,
        path=path,
        query=query,
        headers=to_sign,
        payload_hash=payload_hash,
        secret=secret,
        region=region,
        amz_date=amz_date,
    )
    headers["Authorization"] = (
        f"{ALGORITHM} Credential={access_key}/{scope}, SignedHeaders={signed}, "
        f"Signature={signature}"
    )
    return url, headers


def presign_url(
    *,
    method: str,
    endpoint: str,
    bucket: str,
    key: str,
    access_key: str,
    secret: str,
    region: str,
    expires_seconds: int,
    now: dt.datetime | None = None,
) -> str:
    """Query-string SigV4 (presigned URL), path-style, signing only ``host``."""
    moment = (now or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)
    amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
    scope = f"{amz_date[:8]}/{region}/s3/aws4_request"
    path = object_path(bucket, key)
    params = [
        ("X-Amz-Algorithm", ALGORITHM),
        ("X-Amz-Credential", f"{access_key}/{scope}"),
        ("X-Amz-Date", amz_date),
        ("X-Amz-Expires", str(expires_seconds)),
        ("X-Amz-SignedHeaders", "host"),
    ]
    query = canonical_query(params)
    _signed, signature, _scope = _signature(
        method=method,
        path=path,
        query=query,
        headers={"host": host_header(endpoint)},
        payload_hash=UNSIGNED_PAYLOAD,
        secret=secret,
        region=region,
        amz_date=amz_date,
    )
    return f"{endpoint}{path}?{query}&X-Amz-Signature={signature}"


# ---------------------------------------------------------------- XML helpers


def _strip(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_xml(body: bytes) -> ET.Element:
    if len(body) > _MAX_XML_BODY:
        raise EngineError("engine_error", 502, "S3 engine response is too large")
    if b"<!DOCTYPE" in body or b"<!ENTITY" in body:
        raise EngineError("engine_error", 502, "S3 engine response is not allowed XML")
    try:
        root = ET.fromstring(body)  # noqa: S314 - loopback engine, DTDs rejected above
    except ET.ParseError:
        raise EngineError("engine_error", 502, "S3 engine returned malformed XML") from None
    for element in root.iter():
        element.tag = _strip(element.tag)
    return root


def _text(element: ET.Element, name: str) -> str | None:
    child = element.find(name)
    return None if child is None else (child.text or "")


_ERROR_MAP: dict[str, tuple[str, int]] = {
    "NoSuchKey": ("object_not_found", 404),
    "NoSuchBucket": ("bucket_not_found_in_engine", 404),
    "NoSuchUpload": ("upload_not_found", 404),
    "AccessDenied": ("engine_access_denied", 403),
    "EntityTooLarge": ("object_too_large", 413),
    "QuotaExceeded": ("quota_exceeded", 409),
    "InvalidArgument": ("invalid_key", 422),
    "KeyTooLongError": ("invalid_key", 422),
    "InvalidObjectName": ("invalid_key", 422),
    "BucketNotEmpty": ("bucket_not_empty", 409),
    "PreconditionFailed": ("precondition_failed", 412),
    "InvalidRange": ("invalid_range", 416),
    "SignatureDoesNotMatch": ("engine_auth_failed", 502),
    "InvalidAccessKeyId": ("engine_auth_failed", 502),
}


def error_from_response(status_code: int, body: bytes) -> EngineError:
    code = message = None
    if body:
        try:
            root = parse_xml(body[:_MAX_ERROR_BODY])
            code = _text(root, "Code")
            message = _text(root, "Message")
        except EngineError:
            pass
    if code in _ERROR_MAP:
        mapped, status = _ERROR_MAP[code]
        return EngineError(mapped, status, message or code or "S3 engine error")
    if status_code == 404:
        return EngineError("object_not_found", 404, message or "object not found")
    return EngineError(
        "engine_error", 502, f"S3 engine error {status_code}" + (f": {code}" if code else "")
    )


# ---------------------------------------------------------------- S3 client


class EngineS3:
    """Minimal async S3 client for the panel identity (path-style, loopback)."""

    def __init__(
        self,
        *,
        access_key: str,
        secret: str,
        region: str,
        endpoint: str | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> None:
        self.endpoint = (endpoint or engine_url()).rstrip("/")
        self.access_key = access_key
        self._secret = secret
        self.region = region
        self.client = new_client(timeout or httpx.Timeout(30.0, read=300.0, write=300.0))

    async def aclose(self) -> None:
        await self.client.aclose()

    async def __aenter__(self) -> EngineS3:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def send(
        self,
        method: str,
        bucket: str,
        key: str | None = None,
        *,
        params: list[tuple[str, str]] | None = None,
        headers: dict[str, str] | None = None,
        content: bytes | AsyncIterator[bytes] | None = None,
        payload_hash: str | None = None,
        stream: bool = False,
    ) -> httpx.Response:
        if payload_hash is None:
            if isinstance(content, bytes):
                payload_hash = hashlib.sha256(content).hexdigest()
            elif content is None:
                payload_hash = EMPTY_SHA256
            else:
                payload_hash = UNSIGNED_PAYLOAD
        url, signed = sign_headers(
            method=method,
            endpoint=self.endpoint,
            path=object_path(bucket, key),
            params=params or [],
            access_key=self.access_key,
            secret=self._secret,
            region=self.region,
            payload_hash=payload_hash,
            extra_headers=headers,
        )
        request = self.client.build_request(method, url, headers=signed, content=content)
        try:
            response = await self.client.send(request, stream=stream)
        except httpx.HTTPError as exc:
            raise unreachable(exc) from None
        if response.status_code >= 300 and not (stream and response.status_code == 304):
            body = b""
            try:
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) >= _MAX_ERROR_BODY:
                        break
            finally:
                await response.aclose()
            raise error_from_response(response.status_code, body)
        return response

    async def call(
        self, method: str, bucket: str, key: str | None = None, **kwargs: Any
    ) -> httpx.Response:
        response = await self.send(method, bucket, key, **kwargs)
        await response.aread()
        return response

    def presign_get(self, endpoint: str, bucket: str, key: str, expires_seconds: int) -> str:
        return presign_url(
            method="GET",
            endpoint=endpoint,
            bucket=bucket,
            key=key,
            access_key=self.access_key,
            secret=self._secret,
            region=self.region,
            expires_seconds=expires_seconds,
        )

    async def list_objects(
        self,
        bucket: str,
        *,
        prefix: str = "",
        delimiter: str = "",
        continuation: str = "",
        limit: int = 1000,
    ) -> dict[str, Any]:
        params = [("list-type", "2"), ("max-keys", str(limit)), ("encoding-type", "url")]
        if prefix:
            params.append(("prefix", prefix))
        if delimiter:
            params.append(("delimiter", delimiter))
        if continuation:
            params.append(("continuation-token", continuation))
        response = await self.call("GET", bucket, params=params)
        root = parse_xml(response.content)
        url_encoded = (_text(root, "EncodingType") or "").lower() == "url"

        def decode(value: str | None) -> str:
            from urllib.parse import unquote

            return unquote(value or "") if url_encoded else (value or "")

        objects = []
        for item in root.findall("Contents"):
            size_text = _text(item, "Size") or "0"
            objects.append(
                {
                    "key": decode(_text(item, "Key")),
                    "size": int(size_text) if size_text.isdigit() else 0,
                    "etag": (_text(item, "ETag") or "").strip('"'),
                    "last_modified": _text(item, "LastModified"),
                    "content_type": _text(item, "ContentType"),
                }
            )
        prefixes = [decode(_text(item, "Prefix")) for item in root.findall("CommonPrefixes")]
        truncated = (_text(root, "IsTruncated") or "").lower() == "true"
        return {
            "prefixes": prefixes,
            "objects": objects,
            "next_continuation": (_text(root, "NextContinuationToken") or None)
            if truncated
            else None,
        }

    async def head(self, bucket: str, key: str) -> httpx.Response:
        return await self.call("HEAD", bucket, key)

    async def delete(self, bucket: str, key: str) -> None:
        await self.call("DELETE", bucket, key)

    async def copy(self, bucket: str, source: str, destination: str) -> None:
        response = await self.call(
            "PUT",
            bucket,
            destination,
            headers={"x-amz-copy-source": object_path(bucket, source)},
        )
        # CopyObject may answer 200 with an <Error> document.
        if response.content and b"<Error" in response.content[:512]:
            raise error_from_response(500, response.content)

    async def create_multipart(self, bucket: str, key: str, content_type: str | None) -> str:
        headers = {"Content-Type": content_type} if content_type else None
        response = await self.call("POST", bucket, key, params=[("uploads", "")], headers=headers)
        upload_id = _text(parse_xml(response.content), "UploadId")
        if not upload_id:
            raise EngineError("engine_error", 502, "S3 engine did not return an UploadId")
        return upload_id

    async def upload_part(
        self,
        bucket: str,
        key: str,
        upload_id: str,
        number: int,
        content: bytes | AsyncIterator[bytes],
        length: int,
    ) -> str:
        response = await self.call(
            "PUT",
            bucket,
            key,
            params=[("partNumber", str(number)), ("uploadId", upload_id)],
            headers={"Content-Length": str(length)},
            content=content,
            payload_hash=UNSIGNED_PAYLOAD,
        )
        return response.headers.get("etag", "")

    async def complete_multipart(
        self, bucket: str, key: str, upload_id: str, parts: list[tuple[int, str]]
    ) -> str:
        body = (
            "<CompleteMultipartUpload>"
            + "".join(
                f"<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
                for number, etag in parts
            )
            + "</CompleteMultipartUpload>"
        )
        response = await self.call(
            "POST",
            bucket,
            key,
            params=[("uploadId", upload_id)],
            headers={"Content-Type": "application/xml"},
            content=body.encode("utf-8"),
        )
        root = parse_xml(response.content)
        if root.tag == "Error":
            raise error_from_response(500, response.content)
        return (_text(root, "ETag") or "").strip('"')

    async def abort_multipart(self, bucket: str, key: str, upload_id: str) -> None:
        try:
            await self.call("DELETE", bucket, key, params=[("uploadId", upload_id)])
        except EngineError:
            pass


# ---------------------------------------------------------------- admin API


class EngineAdmin:
    """Internal management API on 127.0.0.1:9001 (shared token file, docs/31 §2)."""

    def __init__(self, token_path: Path, base_url: str | None = None) -> None:
        self.token_path = token_path
        self._base_url = base_url.rstrip("/") if base_url else None

    @property
    def base_url(self) -> str:
        # Resolved per call: the wizard may move the engine to its own container.
        return self._base_url or admin_url()

    def _token(self) -> str:
        try:
            return self.token_path.read_text(encoding="utf-8").strip()
        except OSError:
            raise EngineError(
                "engine_unreachable", 503, "S3 engine admin token is missing"
            ) from None

    async def request(self, method: str, path: str, *, timeout: float = 5.0) -> httpx.Response:
        headers = {ADMIN_TOKEN_HEADER: self._token(), "Accept": "application/json"}
        async with new_client(timeout) as client:
            try:
                response = await client.request(method, f"{self.base_url}{path}", headers=headers)
            except httpx.HTTPError as exc:
                raise unreachable(exc) from None
        return response

    async def json(self, method: str, path: str, *, timeout: float = 5.0) -> Any:
        response = await self.request(method, path, timeout=timeout)
        if response.status_code >= 400:
            raise EngineError(
                "engine_error" if response.status_code != 404 else "bucket_not_found_in_engine",
                502 if response.status_code != 404 else 404,
                f"S3 engine admin API answered {response.status_code}",
            )
        try:
            return response.json()
        except ValueError:
            raise EngineError(
                "engine_error", 502, "S3 engine admin API returned invalid JSON"
            ) from None

    async def health(self) -> bool:
        try:
            response = await self.request("GET", "/admin/health", timeout=2.0)
        except EngineError:
            return False
        return response.status_code == 200

    async def bucket_stats(self, bucket: str) -> dict[str, int] | None:
        try:
            payload = await self.json("GET", f"/admin/buckets/{uri_encode(bucket)}/stats")
        except EngineError:
            return None
        if not isinstance(payload, dict):
            return None
        objects, size = payload.get("objects"), payload.get("bytes")
        if not isinstance(objects, int) or not isinstance(size, int):
            return None
        return {"objects": objects, "bytes": size}

    async def ensure_bucket(self, bucket: str) -> bool:
        try:
            response = await self.request("POST", f"/admin/buckets/{uri_encode(bucket)}/ensure")
        except EngineError:
            return False
        return response.status_code < 300

    async def lifecycle(self, bucket: str) -> dict[str, Any]:
        """Lifecycle rules, versioning state and the last worker run of one bucket."""
        payload = await self.json("GET", f"/admin/buckets/{uri_encode(bucket)}/lifecycle")
        if not isinstance(payload, dict):
            raise EngineError("engine_error", 502, "S3 engine admin API returned invalid JSON")
        return payload

    async def lifecycle_preview(self, bucket: str) -> dict[str, Any]:
        """Dry run: what the lifecycle worker would delete now (nothing is deleted)."""
        payload = await self.json(
            "POST", f"/admin/buckets/{uri_encode(bucket)}/lifecycle/preview", timeout=120.0
        )
        if not isinstance(payload, dict):
            raise EngineError("engine_error", 502, "S3 engine admin API returned invalid JSON")
        return payload

    async def delete_bucket(self, bucket: str, *, force: bool) -> None:
        response = await self.request(
            "DELETE",
            f"/admin/buckets/{uri_encode(bucket)}?force={1 if force else 0}",
            timeout=120.0,
        )
        if response.status_code == 409:
            raise EngineError("bucket_not_empty", 409, "bucket is not empty; delete with force")
        if response.status_code >= 400 and response.status_code != 404:
            raise EngineError(
                "engine_error", 502, f"S3 engine admin API answered {response.status_code}"
            )
