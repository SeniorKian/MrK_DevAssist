"""S3 REST protocol: routing, auth, policy checks and operations (docs/30 §1, §2).

A raw ASGI application (no framework routing): bucket/key/subresources are parsed
from ``scope["raw_path"]`` so SigV4 canonicalization sees exactly what we route on.
The request body is only read after authentication, which makes uvicorn answer
``Expect: 100-continue`` at the right moment.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, unquote, unquote_to_bytes

from .. import s3sigv4
from . import checksums, lifecycle, tagging
from .chunked import AwsChunkedDecoder
from .errors import S3Error
from .index import PartRecord, VersionRecord, prefix_upper_bound
from .linked import LinkedBucket
from .listing import list_page, resume_point
from .policy import ALLOW, DENY, RequestContext, evaluate, resource_arn
from .snapshot import Identity, Snapshot
from .storage import (
    EMPTY_MD5,
    BaseBucket,
    BodyHasher,
    ManagedBucket,
    ObjectInfo,
    PendingWrite,
    multipart_etag,
    open_segments,
    stream_fds,
    write_stream,
)
from .xmlio import (
    XmlWriter,
    child_text,
    children,
    error_xml,
    has_invalid_xml_chars,
    http_date,
    iso8601,
    parse_xml,
)

if TYPE_CHECKING:
    from .engine import Engine

LOGGER = logging.getLogger("mrk.s3.api")
OWNER_ID = hashlib.sha256(b"mrk-s3-owner").hexdigest()
STORAGE_CLASSES = frozenset(
    {
        "STANDARD",
        "REDUCED_REDUNDANCY",
        "STANDARD_IA",
        "ONEZONE_IA",
        "INTELLIGENT_TIERING",
        "GLACIER",
        "DEEP_ARCHIVE",
        "GLACIER_IR",
        "EXPRESS_ONEZONE",
    }
)
ACCEPTED_ACLS = frozenset({"private", "bucket-owner-full-control", "bucket-owner-read"})
CONTENT_HEADERS = {
    "content-type": "content_type",
    "content-disposition": "content_disposition",
    "content-language": "content_language",
    "cache-control": "cache_control",
    "expires": "expires",
}
RESPONSE_OVERRIDES = {
    "response-content-type": "Content-Type",
    "response-content-language": "Content-Language",
    "response-expires": "Expires",
    "response-cache-control": "Cache-Control",
    "response-content-disposition": "Content-Disposition",
    "response-content-encoding": "Content-Encoding",
}
MAX_COPY_SOURCE = 5 * 1024**3
# Internal metadata that never travels with a copy (the index assigns new values).
COPY_EXCLUDED_META = frozenset({"parts_count", "version_id", "vseq"})
KEEPALIVE_SECONDS = 10.0


# --------------------------------------------------------------------------- request/response


@dataclass(slots=True)
class Response:
    status: int = 200
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes | AsyncIterator[bytes] = b""
    content_length: int | None = None

    def header(self, name: str, value: str | int | None) -> Response:
        if value is not None:
            self.headers.append((name, str(value)))
        return self


def website_page(bucket: str, head: bool) -> Response:
    """The page shown for a public bucket's root when it has no index.html."""
    safe = "".join(char for char in bucket if char.isalnum() or char in "-._")
    body = (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{safe}</title><style>body{{font:16px/1.6 system-ui,sans-serif;"
        "max-width:36rem;margin:12vh auto;padding:0 1rem;color:#222}"
        "@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}}"
        "code{background:rgba(127,127,127,.15);padding:.1em .35em;border-radius:4px}"
        "</style></head><body>"
        f"<h1>{safe}</h1><p>This is a public file space. Files open with their full address, "
        "for example <code>/path/to/file.png</code>; the list of files is not public.</p>"
        "<p dir=\"rtl\" lang=\"fa\">این یک فضای فایل عمومی است. هر فایل با نشانی کامل خودش "
        "باز می‌شود؛ فهرست فایل‌ها عمومی نیست.</p></body></html>"
    ).encode()
    response = Response(200, [("Content-Type", "text/html; charset=utf-8"),
                              ("Cache-Control", "public, max-age=300")],
                        b"" if head else body)
    if head:
        response.header("Content-Length", len(body))
    return response


def xml_response(body: bytes, status: int = 200) -> Response:
    return Response(status, [("Content-Type", "application/xml")], body)


class Request:
    def __init__(
        self, scope: dict[str, Any], receive: Callable[[], Awaitable[dict[str, Any]]]
    ) -> None:
        self.scope = scope
        self._receive = receive
        self.method: str = scope["method"].upper()
        raw_path = scope.get("raw_path") or scope.get("path", "/").encode("utf-8")
        self.raw_path: str = raw_path.decode("latin-1") if isinstance(raw_path, bytes) else raw_path
        if "?" in self.raw_path:
            self.raw_path = self.raw_path.split("?", 1)[0]
        self.raw_query: str = scope.get("query_string", b"").decode("latin-1")
        self.header_list: list[tuple[str, str]] = [
            (name.decode("latin-1").lower(), value.decode("latin-1"))
            for name, value in scope.get("headers", [])
        ]
        self.headers: dict[str, str] = s3sigv4.header_map(self.header_list)
        self.query_pairs = s3sigv4.parse_query(self.raw_query)
        self.query: dict[str, str] = {}
        for name, value in self.query_pairs:
            self.query.setdefault(name, value)
        self.bucket: str | None = None
        self.key: str | None = None
        # True when the Host is a custom domain of one bucket (path = key).
        self.bucket_host = False
        self.body_started = False
        self.disconnected = False

    def header(self, name: str) -> str | None:
        return self.headers.get(name)

    @property
    def header_bytes(self) -> int:
        return sum(len(name) + len(value) + 4 for name, value in self.header_list)

    async def raw_body(self, idle_timeout: float) -> AsyncIterator[bytes]:
        self.body_started = True
        while True:
            try:
                message = await asyncio.wait_for(self._receive(), timeout=idle_timeout)
            except TimeoutError as exc:
                raise S3Error("RequestTimeout") from exc
            if message["type"] == "http.disconnect":
                self.disconnected = True
                raise S3Error("IncompleteBody", "The client disconnected.")
            body = message.get("body", b"")
            if body:
                yield body
            if not message.get("more_body", False):
                return

    async def read_all(self, limit: int, idle_timeout: float) -> bytes:
        data = bytearray()
        async for piece in self.raw_body(idle_timeout):
            data += piece
            if len(data) > limit:
                raise S3Error("MalformedXML", "The request body is too large.")
        return bytes(data)


@dataclass(slots=True)
class Principal:
    identity: Identity | None
    verified: s3sigv4.VerifiedRequest | None

    @property
    def anonymous(self) -> bool:
        return self.identity is None


# --------------------------------------------------------------------------- helpers


def quote_etag(etag: str) -> str:
    return f'"{etag}"'


def strip_etag(value: str) -> str:
    value = value.strip()
    if value.startswith("W/"):
        value = value[2:]
    return value.strip('"').lower()


def _etag_matches(header: str, etag: str) -> bool:
    for item in header.split(","):
        item = item.strip()
        if item == "*" or strip_etag(item) == etag.lower():
            return True
    return False


def _parse_http_date(value: str) -> float | None:
    try:
        return parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, IndexError):
        return None


def _parse_int(
    value: str | None, name: str, *, minimum: int = 0, default: int | None = None
) -> int | None:
    if value is None or value == "":
        return default
    try:
        number = int(value)
    except ValueError as exc:
        raise S3Error(
            "InvalidArgument",
            f"Provided {name} not an integer or within integer range",
            ArgumentName=name,
            ArgumentValue=value,
        ) from exc
    if number < minimum:
        raise S3Error(
            "InvalidArgument",
            f"Argument {name} must be an integer >= {minimum}",
            ArgumentName=name,
            ArgumentValue=value,
        )
    return number


def encode_key(value: str, encoding: str | None) -> str:
    return quote(value, safe="/") if encoding == "url" else value


def evaluate_conditions(
    headers: dict[str, str], info: ObjectInfo, *, copy_source: bool = False
) -> int | None:
    """RFC 7232 order as S3 applies it. Returns 304/412 or ``None`` to proceed."""
    prefix = "x-amz-copy-source-" if copy_source else ""
    if_match = headers.get(prefix + "if-match")
    if_unmodified = headers.get(prefix + "if-unmodified-since")
    if_none_match = headers.get(prefix + "if-none-match")
    if_modified = headers.get(prefix + "if-modified-since")
    modified = info.last_modified_ns / 1e9
    if if_match is not None:
        if not _etag_matches(if_match, info.etag):
            return 412
    elif if_unmodified is not None:
        stamp = _parse_http_date(if_unmodified)
        if stamp is not None and int(modified) > stamp:
            return 412
    if if_none_match is not None:
        if _etag_matches(if_none_match, info.etag):
            return 412 if copy_source else 304
    elif if_modified is not None:
        stamp = _parse_http_date(if_modified)
        if stamp is not None and int(modified) <= stamp:
            return 412 if copy_source else 304
    return None


def parse_range(value: str | None, size: int) -> tuple[int, int] | None:
    """Single byte range -> (start, end) inclusive; multi/invalid ranges are ignored (full body)."""
    if not value:
        return None
    value = value.strip()
    if not value.startswith("bytes=") or "," in value:
        return None
    spec = value[6:].strip()
    first, sep, last = spec.partition("-")
    if not sep:
        return None
    try:
        if first == "":
            length = int(last)
            if length <= 0:
                raise S3Error("InvalidRange", headers={"Content-Range": f"bytes */{size}"})
            if size == 0:
                raise S3Error("InvalidRange", headers={"Content-Range": f"bytes */{size}"})
            return max(0, size - length), size - 1
        start = int(first)
        end = int(last) if last else size - 1
    except ValueError:
        return None
    if start < 0 or (last and end < start):
        return None
    if start >= size:
        raise S3Error(
            "InvalidRange",
            headers={"Content-Range": f"bytes */{size}"},
            ActualObjectSize=str(size),
            RangeRequested=value,
        )
    return start, min(end, size - 1)


# --------------------------------------------------------------------------- application


class S3Api:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.settings = engine.settings

    # ASGI entry -------------------------------------------------------------------
    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        request = Request(scope, receive)
        request_id = secrets.token_hex(8).upper()
        host_id = base64.b64encode(secrets.token_bytes(24)).decode("ascii")
        started = time.monotonic()
        try:
            response = await self.dispatch(request)
        except S3Error as exc:
            response = self.error_response(exc, request, request_id, host_id)
        except Exception:
            LOGGER.exception(
                "S3 request failed", extra={"method": request.method, "bucket": request.bucket}
            )
            response = self.error_response(S3Error("InternalError"), request, request_id, host_id)
        response.headers.extend(
            [("x-amz-request-id", request_id), ("x-amz-id-2", host_id), ("Server", "MRK")]
        )
        await self._send(send, request, response)
        # 503 = module disabled/unmounted: expected, so not logged as a warning.
        failed = response.status >= 500 and response.status != 503
        if LOGGER.isEnabledFor(logging.DEBUG) or failed:
            level = logging.WARNING if failed else logging.DEBUG
            LOGGER.log(
                level,
                "s3 request",
                extra={
                    "method": request.method,
                    "bucket": request.bucket,
                    "status": response.status,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                },
            )

    async def _send(self, send: Any, request: Request, response: Response) -> None:
        body = response.body
        headers = list(response.headers)
        names = {name.lower() for name, _ in headers}
        if isinstance(body, bytes):
            if "content-length" not in names:
                headers.append(
                    (
                        "Content-Length",
                        str(
                            response.content_length
                            if response.content_length is not None
                            else len(body)
                        ),
                    )
                )
        elif response.content_length is not None and "content-length" not in names:
            headers.append(("Content-Length", str(response.content_length)))
        await send(
            {
                "type": "http.response.start",
                "status": response.status,
                "headers": [
                    (n.encode("latin-1"), v.encode("latin-1", "replace")) for n, v in headers
                ],
            }
        )
        if request.method == "HEAD":
            if not isinstance(body, bytes):
                await body.aclose()  # type: ignore[attr-defined]
            await send({"type": "http.response.body", "body": b""})
            return
        if isinstance(body, bytes):
            await send({"type": "http.response.body", "body": body})
            return
        try:
            async for chunk in body:
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
        except S3Error:
            LOGGER.warning("S3 response stream aborted", extra={"bucket": request.bucket})
            raise
        finally:
            await body.aclose()  # type: ignore[attr-defined]
        await send({"type": "http.response.body", "body": b""})

    def error_response(
        self, exc: S3Error, request: Request, request_id: str, host_id: str
    ) -> Response:
        details = dict(exc.details)
        if (
            request.bucket
            and "BucketName" not in details
            and exc.code in {"NoSuchBucket", "NoSuchKey", "NoSuchUpload"}
        ):
            details["BucketName"] = request.bucket
        if exc.code == "NoSuchKey" and request.key is not None:
            details.setdefault("Key", request.key)
        details.setdefault("Resource", unquote(request.raw_path))
        if exc.code in {"AccessDenied", "SignatureDoesNotMatch", "InvalidAccessKeyId"}:
            LOGGER.info(
                "S3 auth/permission failure", extra={"code": exc.code, "bucket": request.bucket}
            )
        response = xml_response(
            error_xml(exc.code, exc.message, request_id, host_id, details), exc.status
        )
        for name, value in exc.headers.items():
            response.header(name, value)
        if exc.status == 503:
            response.header("Retry-After", "5")
        if request.body_started is False and request.method in {"PUT", "POST"}:
            response.header("Connection", "close")
        return response

    # Dispatch ----------------------------------------------------------------------
    @property
    def snapshot(self) -> Snapshot:
        snapshot = self.engine.snapshots.current
        if snapshot is None or not snapshot.enabled:
            raise S3Error("ServiceUnavailable", "The S3 service is disabled.", 503)
        return snapshot

    def resolve(self, request: Request, snapshot: Snapshot) -> None:
        host = (request.header("host") or "").strip().lower()
        if host.startswith("["):
            host = host.split("]", 1)[0] + "]"
        elif ":" in host:
            host = host.rsplit(":", 1)[0]
        path = request.raw_path or "/"
        suffix = next(
            (
                item
                for item in (snapshot.virtual_host_suffix, *snapshot.extra_suffixes)
                if item and host.endswith("." + item)
            ),
            "",
        )
        if not suffix and host in snapshot.bucket_hosts:
            # docs/43: a verified custom domain of one bucket (path = key).
            request.bucket = snapshot.bucket_hosts[host]
            request.bucket_host = True
            remainder = path[1:] if path.startswith("/") else path
            request.key = (
                unquote_to_bytes(remainder).decode("utf-8", "replace") if remainder else None
            )
            return
        if suffix:
            request.bucket = host[: -(len(suffix) + 1)]
            remainder = path[1:] if path.startswith("/") else path
            request.key = (
                unquote_to_bytes(remainder).decode("utf-8", "replace") if remainder else None
            )
            return
        if path in {"", "/"}:
            return
        trimmed = path[1:]
        bucket_raw, sep, key_raw = trimmed.partition("/")
        request.bucket = unquote(bucket_raw)
        if sep and key_raw:
            request.key = unquote_to_bytes(key_raw).decode("utf-8", "replace")

    def authenticate(self, request: Request, snapshot: Snapshot) -> Principal:
        try:
            verified = s3sigv4.verify_request(
                request.method,
                request.raw_path,
                request.raw_query,
                request.header_list,
                self.engine.snapshots.secret_for,
                max_skew_seconds=self.settings.clock_skew_seconds,
                region=None if self.settings.accept_any_region else snapshot.region,
                require_content_sha256=self.settings.require_content_sha256,
                debug=self.settings.debug_signatures,
            )
        except s3sigv4.SigV4Error as exc:
            raise S3Error(exc.code, exc.message, exc.status, **exc.details) from exc
        if verified is None:
            return Principal(None, None)
        entry = snapshot.keys.get(verified.access_key_id)
        if entry is None or not entry[0].enabled or not entry[1].enabled:
            raise S3Error("InvalidAccessKeyId", AWSAccessKeyId=verified.access_key_id)
        self.engine.note_key_used(verified.access_key_id)
        return Principal(entry[0], verified)

    def context(
        self, request: Request, principal: Principal, extra: dict[str, str] | None = None
    ) -> RequestContext:
        client = request.scope.get("client") or ("", 0)
        source_ip = client[0] if client else ""
        secure = request.scope.get("scheme") == "https"
        trusted = self.engine.trusted_proxies
        if source_ip in trusted:
            forwarded = request.header("x-forwarded-for")
            if forwarded:
                source_ip = forwarded.split(",")[-1].strip()
            proto = request.header("x-forwarded-proto")
            if proto:
                secure = proto.split(",")[0].strip().lower() == "https"
        return RequestContext(
            username=principal.identity.name if principal.identity else "",
            source_ip=source_ip,
            secure_transport=secure,
            auth_type="REST-QUERY-STRING"
            if principal.verified and principal.verified.auth_type == "query"
            else "REST-HEADER",
            user_agent=request.header("user-agent") or "",
            referer=request.header("referer") or "",
            content_sha256=request.header("x-amz-content-sha256") or "",
            values=extra or {},
        )

    def allowed(
        self,
        principal: Principal,
        request: Request,
        action: str,
        bucket: str | None,
        key: str | None = None,
        *,
        extra: dict[str, str] | None = None,
    ) -> bool:
        snapshot = self.snapshot
        if principal.identity is None:
            config = snapshot.buckets.get(bucket or "")
            if config is None or not config.public_read:
                return False
            if action == "s3:GetObject":
                return True
            if action in {"s3:GetBucketLocation"}:
                return True
            return action == "s3:ListBucket" and config.public_list
        identity = principal.identity
        resource = resource_arn(bucket, key)
        decision = evaluate(
            [identity.policy] if identity.policy else [],
            action,
            resource,
            self.context(request, principal, extra),
        )
        if decision == DENY:
            return False
        if identity.system:
            return True
        return decision == ALLOW

    def require(
        self,
        principal: Principal,
        request: Request,
        action: str,
        bucket: str | None,
        key: str | None = None,
        *,
        extra: dict[str, str] | None = None,
    ) -> None:
        if not self.allowed(principal, request, action, bucket, key, extra=extra):
            raise S3Error("AccessDenied")

    def bucket_for(self, name: str) -> BaseBucket:
        bucket = self.engine.bucket(name)
        if bucket is None:
            raise S3Error("NoSuchBucket", BucketName=name)
        return bucket

    async def dispatch(self, request: Request) -> Response:
        snapshot = self.snapshot
        if request.header_bytes > self.settings.max_header_bytes:
            raise S3Error("RequestHeaderSectionTooLarge")
        self.resolve(request, snapshot)
        principal = self.authenticate(request, snapshot)
        if request.bucket is None:
            if request.method in {"GET", "HEAD"}:
                return self.list_buckets(request, principal, snapshot)
            raise S3Error("MethodNotAllowed")
        if (
            request.key is not None
            and len(request.key.encode("utf-8")) > self.settings.max_key_bytes
        ):
            raise S3Error("KeyTooLongError", MaxSizeAllowed=str(self.settings.max_key_bytes))
        if request.key is None:
            site = await self.website_root(request, principal, snapshot)
            if site is not None:
                return site
            return await self.bucket_operation(request, principal)
        try:
            return await self.object_operation(request, principal)
        except S3Error as exc:
            stripped = self.bucket_prefixed_key(request, exc)
            if stripped is None:
                raise
            # A link made for path-style addressing (/<bucket>/<key>) opened on the
            # bucket's own domain: the key without the repeated bucket name.
            request.key = stripped
            return await self.object_operation(request, principal)

    # Public buckets in a browser ----------------------------------------------------
    @staticmethod
    def bucket_prefixed_key(request: Request, exc: S3Error) -> str | None:
        """The key without a leading ``<bucket>/`` on a bucket domain, for a read that
        found nothing under the full key; None when it does not apply."""
        if not request.bucket_host or request.method not in {"GET", "HEAD"}:
            return None
        if exc.code not in {"NoSuchKey", "AccessDenied"} or request.bucket is None:
            return None
        if any(name in request.query for name in ("versionId", "uploadId", "tagging", "acl",
                                                  "attributes", "retention", "legal-hold")):
            return None
        key = request.key or ""
        prefix = request.bucket + "/"
        if not key.startswith(prefix) or len(key) == len(prefix):
            return None
        return key[len(prefix):]

    async def website_root(
        self, request: Request, principal: Principal, snapshot: Snapshot
    ) -> Response | None:
        """A browser opening a public bucket's root: its index.html, or a short page.

        Only for anonymous GET/HEAD without query parameters from a client that asks for
        HTML, on a bucket that is public to read but not to list. S3 clients (which list
        with XML) and everything else keep the S3 behaviour.
        """
        if not principal.anonymous or request.method not in {"GET", "HEAD"} or request.query:
            return None
        if "text/html" not in (request.header("accept") or "").lower():
            return None
        name = request.bucket or ""
        config = snapshot.buckets.get(name)
        if config is None or not config.public_read or config.public_list:
            return None
        request.key = "index.html"
        try:
            return await self.object_operation(request, principal)
        except S3Error as exc:
            if exc.code not in {"NoSuchKey", "AccessDenied"}:
                raise
        finally:
            request.key = None
        return website_page(name, request.method == "HEAD")

    # Service -----------------------------------------------------------------------
    def list_buckets(self, request: Request, principal: Principal, snapshot: Snapshot) -> Response:
        if principal.anonymous:
            raise S3Error("AccessDenied")
        list_all = self.allowed(principal, request, "s3:ListAllMyBuckets", None)
        writer = XmlWriter().open("ListAllMyBucketsResult", xmlns=True)
        identity = principal.identity
        assert identity is not None
        writer.open("Owner").elem("ID", identity.canonical_id).elem(
            "DisplayName", identity.name
        ).close("Owner")
        writer.open("Buckets")
        for name in sorted(snapshot.buckets):
            config = snapshot.buckets[name]
            if not list_all and not self.allowed(principal, request, "s3:ListBucket", name):
                continue
            created = config.created_at_ns or 0
            writer.open("Bucket").elem("Name", name).elem("CreationDate", iso8601(created)).close(
                "Bucket"
            )
        writer.close("Buckets").close("ListAllMyBucketsResult")
        return xml_response(writer.to_bytes())

    # Buckets -----------------------------------------------------------------------
    async def bucket_operation(self, request: Request, principal: Principal) -> Response:
        name = request.bucket
        assert name is not None
        query = request.query
        method = request.method
        exists = self.engine.bucket(name) is not None
        if method == "PUT" and not any(
            item in query
            for item in (
                "versioning",
                "acl",
                "policy",
                "cors",
                "lifecycle",
                "tagging",
                "website",
                "encryption",
            )
        ):
            if exists and self.allowed(principal, request, "s3:ListBucket", name):
                raise S3Error("BucketAlreadyOwnedByYou", BucketName=name)
            raise S3Error(
                "AccessDenied", "Buckets are created in the DevAssist panel, not via the S3 API."
            )
        if method == "DELETE" and not any(
            item in query for item in ("tagging", "lifecycle", "policy", "cors", "website")
        ):
            if not exists:
                raise S3Error("NoSuchBucket", BucketName=name)
            raise S3Error(
                "AccessDenied", "Buckets are deleted in the DevAssist panel, not via the S3 API."
            )
        bucket = self.bucket_for(name)
        if method == "HEAD":
            self.require(principal, request, "s3:ListBucket", name)
            return (
                Response(200)
                .header("x-amz-bucket-region", self.snapshot.region)
                .header("Content-Type", "application/xml")
            )
        if method == "GET":
            return await self.bucket_get(request, principal, bucket)
        if method == "POST" and "delete" in query:
            return await self.delete_objects(request, principal, bucket)
        if method == "PUT":
            return await self.bucket_put(request, principal, bucket)
        if method == "DELETE":
            return await self.bucket_delete(request, principal, bucket)
        if method == "POST":
            raise S3Error("NotImplemented", "This bucket operation is not implemented.")
        raise S3Error("MethodNotAllowed")

    async def bucket_get(
        self, request: Request, principal: Principal, bucket: BaseBucket
    ) -> Response:
        query = request.query
        name = bucket.name
        if "location" in query:
            self.require(principal, request, "s3:GetBucketLocation", name)
            region = self.snapshot.region
            writer = XmlWriter()
            if region == "us-east-1":
                writer.empty("LocationConstraint", xmlns=True)
            else:
                writer.open("LocationConstraint", xmlns=True).raw(region).close(
                    "LocationConstraint"
                )
            return xml_response(writer.to_bytes())
        if "versioning" in query:
            self.require(principal, request, "s3:GetBucketVersioning", name)
            state = bucket.versioning
            if not state:
                return xml_response(
                    XmlWriter().empty("VersioningConfiguration", xmlns=True).to_bytes()
                )
            body = (
                XmlWriter()
                .open("VersioningConfiguration", xmlns=True)
                .elem("Status", state)
                .close("VersioningConfiguration")
            )
            return xml_response(body.to_bytes())
        if "versions" in query:
            return await self.list_versions(request, principal, bucket)
        if "tagging" in query:
            self.require(principal, request, "s3:GetBucketTagging", name)
            stored = await asyncio.to_thread(bucket.index.get_setting, "tagging")
            if stored is None:
                raise S3Error("NoSuchTagSet", BucketName=name)
            return xml_response(tagging.to_xml([(pair[0], pair[1]) for pair in json.loads(stored)]))
        if "lifecycle" in query:
            self.require(principal, request, "s3:GetLifecycleConfiguration", name)
            rules = await asyncio.to_thread(lifecycle.load_rules, bucket)
            if not rules:
                raise S3Error("NoSuchLifecycleConfiguration", BucketName=name)
            return xml_response(lifecycle.to_xml(rules))
        if "acl" in query:
            self.require(principal, request, "s3:GetBucketAcl", name)
            return xml_response(self._acl_xml())
        if "uploads" in query:
            self.require(principal, request, "s3:ListBucketMultipartUploads", name)
            return await self.list_uploads(request, bucket)
        if "encryption" in query:
            self.require(principal, request, "s3:GetEncryptionConfiguration", name)
            raise S3Error("ServerSideEncryptionConfigurationNotFoundError", BucketName=name)
        missing = {
            "policy": "NoSuchBucketPolicy",
            "cors": "NoSuchCORSConfiguration",
            "website": "NoSuchWebsiteConfiguration",
        }
        for item, code in missing.items():
            if item in query:
                self.require(principal, request, "s3:ListBucket", name)
                raise S3Error(code, BucketName=name)
        if "requestPayment" in query:
            self.require(principal, request, "s3:ListBucket", name)
            body = (
                XmlWriter()
                .open("RequestPaymentConfiguration", xmlns=True)
                .elem("Payer", "BucketOwner")
                .close("RequestPaymentConfiguration")
            )
            return xml_response(body.to_bytes())
        if "accelerate" in query:
            self.require(principal, request, "s3:ListBucket", name)
            return xml_response(XmlWriter().empty("AccelerateConfiguration", xmlns=True).to_bytes())
        if "ownershipControls" in query:
            self.require(principal, request, "s3:ListBucket", name)
            body = (
                XmlWriter()
                .open("OwnershipControls", xmlns=True)
                .open("Rule")
                .elem("ObjectOwnership", "BucketOwnerEnforced")
                .close("Rule")
                .close("OwnershipControls")
            )
            return xml_response(body.to_bytes())
        unsupported = {
            "object-lock",
            "replication",
            "logging",
            "notification",
            "analytics",
            "inventory",
            "metrics",
            "intelligent-tiering",
            "publicAccessBlock",
            "policyStatus",
        }
        if unsupported & set(query):
            raise S3Error("NotImplemented", "This bucket subresource is not implemented.")
        return await self.list_objects(request, principal, bucket)

    async def bucket_put(
        self, request: Request, principal: Principal, bucket: BaseBucket
    ) -> Response:
        query = request.query
        name = bucket.name
        if "tagging" in query:
            self.require(principal, request, "s3:PutBucketTagging", name)
            body = await self.read_body_verified(request, principal, require_digest=False)
            tags = tagging.parse_xml_tags(body, tagging.MAX_BUCKET_TAGS)
            await asyncio.to_thread(
                bucket.index.set_setting,
                "tagging",
                json.dumps([list(pair) for pair in tags], separators=(",", ":")),
            )
            return Response(204)
        if "lifecycle" in query:
            self.require(principal, request, "s3:PutLifecycleConfiguration", name)
            if bucket.config.read_only:
                raise S3Error("InvalidBucketState", "Read-only linked buckets have no lifecycle.")
            body = await self.read_body_verified(request, principal, require_digest=False)
            rules = lifecycle.parse_config(body)
            await asyncio.to_thread(lifecycle.save_rules, bucket, rules)
            return Response(200)
        if "versioning" in query:
            self.require(principal, request, "s3:PutBucketVersioning", name)
            body = await self.read_body_verified(request, principal, require_digest=False)
            root = parse_xml(body)
            if root.tag != "VersioningConfiguration":
                raise S3Error("MalformedXML")
            mfa = (child_text(root, "MfaDelete") or child_text(root, "MFADelete") or "").strip()
            if mfa == "Enabled" or request.header("x-amz-mfa"):
                raise S3Error("NotImplemented", "MFA Delete is not supported.")
            if mfa not in {"", "Disabled"}:
                raise S3Error("IllegalVersioningConfigurationException")
            status = child_text(root, "Status")
            if status is None:
                return Response(200)
            status = status.strip()
            if status not in {"Enabled", "Suspended"}:
                raise S3Error("IllegalVersioningConfigurationException")
            if not isinstance(bucket, ManagedBucket):
                raise S3Error(
                    "InvalidBucketState",
                    "Versioning is not available for linked-folder buckets.",
                )
            await asyncio.to_thread(bucket.index.set_setting, "versioning", status)
            return Response(200)
        raise S3Error("NotImplemented", "This bucket operation is not implemented.")

    async def bucket_delete(
        self, request: Request, principal: Principal, bucket: BaseBucket
    ) -> Response:
        query = request.query
        name = bucket.name
        if "tagging" in query:
            self.require(principal, request, "s3:PutBucketTagging", name)
            await asyncio.to_thread(bucket.index.set_setting, "tagging", None)
            return Response(204)
        if "lifecycle" in query:
            self.require(principal, request, "s3:PutLifecycleConfiguration", name)
            await asyncio.to_thread(lifecycle.save_rules, bucket, None)
            return Response(204)
        raise S3Error("NotImplemented", "This bucket operation is not implemented.")

    def _collect_versions(
        self,
        bucket: BaseBucket,
        prefix: str,
        delimiter: str,
        key_marker: str,
        vid_marker: str,
        max_keys: int,
    ) -> tuple[list[VersionRecord], list[str], bool, str | None, str | None]:
        """One ListObjectVersions page: ``(versions, prefixes, truncated, next markers)``."""
        items: list[VersionRecord] = []
        prefixes: list[str] = []
        if max_keys <= 0:
            return items, prefixes, False, None, None
        if isinstance(bucket, LinkedBucket):
            page = list_page(
                bucket.iter_entries(prefix, delimiter),
                prefix=prefix,
                delimiter=delimiter,
                marker=key_marker,
                max_keys=max_keys,
            )
            for entry in page.contents:
                info = bucket.entry_info(entry)
                items.append(
                    VersionRecord(
                        key=info.key,
                        version_id="null",
                        seq=0,
                        size=info.size,
                        etag=info.etag,
                        last_modified_ns=info.last_modified_ns,
                        meta=info.meta,
                        layout=[],
                        delete_marker=False,
                        is_latest=True,
                    )
                )
            return items, list(page.prefixes), page.truncated, page.next_marker, None
        index = bucket.index
        if vid_marker:
            start, inclusive = key_marker, True
        else:
            start, inclusive = resume_point(prefix, delimiter, key_marker)
            inclusive = inclusive and bool(key_marker)
        count = 0
        last_key: str | None = None
        last_vid: str | None = None
        while True:
            keys = index.version_keys(start, inclusive=inclusive, prefix=prefix, limit=500)
            if not keys:
                return items, prefixes, False, None, None
            jump: str | None = None
            for key in keys:
                if delimiter:
                    position = key.find(delimiter, len(prefix))
                    if position >= 0:
                        common = key[: position + len(delimiter)]
                        if count >= max_keys:
                            return items, prefixes, True, last_key, last_vid
                        prefixes.append(common)
                        count += 1
                        last_key, last_vid = common, None
                        upper = prefix_upper_bound(common)
                        if upper is None:
                            return items, prefixes, False, None, None
                        jump = upper
                        break
                versions = index.versions_for(key)
                if key == key_marker and vid_marker:
                    ids = [version.version_id for version in versions]
                    if vid_marker not in ids:
                        raise S3Error(
                            "InvalidArgument",
                            "Invalid version id specified",
                            ArgumentName="version-id-marker",
                        )
                    versions = versions[ids.index(vid_marker) + 1 :]
                for version in versions:
                    if count >= max_keys:
                        return items, prefixes, True, last_key, last_vid
                    items.append(version)
                    count += 1
                    last_key, last_vid = key, version.version_id
            if jump is not None:
                start, inclusive = jump, True
            else:
                start, inclusive = keys[-1], False

    async def list_versions(
        self, request: Request, principal: Principal, bucket: BaseBucket
    ) -> Response:
        query = request.query
        prefix = query.get("prefix", "")
        delimiter = query.get("delimiter", "")
        encoding = query.get("encoding-type")
        if encoding is not None and encoding != "url":
            raise S3Error(
                "InvalidArgument",
                "Invalid Encoding Method specified in Request",
                ArgumentName="encoding-type",
            )
        key_marker = query.get("key-marker", "")
        vid_marker = query.get("version-id-marker", "")
        if vid_marker and not key_marker:
            raise S3Error(
                "InvalidArgument",
                "A version-id marker cannot be specified without a key marker.",
                ArgumentName="version-id-marker",
            )
        max_keys = _parse_int(query.get("max-keys"), "max-keys", default=1000) or 0
        max_keys = min(max_keys, self.settings.max_keys_per_list)
        self.require(
            principal,
            request,
            "s3:ListBucketVersions",
            bucket.name,
            extra={"s3:prefix": prefix, "s3:delimiter": delimiter, "s3:max-keys": str(max_keys)},
        )
        items, prefixes, truncated, next_key, next_vid = await asyncio.to_thread(
            self._collect_versions, bucket, prefix, delimiter, key_marker, vid_marker, max_keys
        )
        enc = encoding
        writer = XmlWriter().open("ListVersionsResult", xmlns=True)
        writer.elem("Name", bucket.name).elem("Prefix", encode_key(prefix, enc))
        writer.elem("KeyMarker", encode_key(key_marker, enc)).elem("VersionIdMarker", vid_marker)
        if truncated and next_key is not None:
            writer.elem("NextKeyMarker", encode_key(next_key, enc))
            if next_vid is not None:
                writer.elem("NextVersionIdMarker", next_vid)
        writer.elem("MaxKeys", max_keys)
        if delimiter:
            writer.elem("Delimiter", encode_key(delimiter, enc))
        if enc:
            writer.elem("EncodingType", enc)
        writer.elem("IsTruncated", truncated)
        for version in items:
            tag = "DeleteMarker" if version.delete_marker else "Version"
            writer.open(tag).elem("Key", encode_key(version.key, enc))
            writer.elem("VersionId", version.version_id).elem("IsLatest", version.is_latest)
            writer.elem("LastModified", iso8601(version.last_modified_ns))
            if not version.delete_marker:
                writer.elem("ETag", quote_etag(version.etag)).elem("Size", version.size)
                writer.elem("StorageClass", version.meta.get("storage_class", "STANDARD"))
            writer.open("Owner").elem("ID", OWNER_ID).elem("DisplayName", "mrk").close("Owner")
            writer.close(tag)
        for common in prefixes:
            writer.open("CommonPrefixes").elem("Prefix", encode_key(common, enc)).close(
                "CommonPrefixes"
            )
        writer.close("ListVersionsResult")
        return xml_response(writer.to_bytes())

    def _acl_xml(self) -> bytes:
        writer = XmlWriter().open("AccessControlPolicy", xmlns=True)
        writer.open("Owner").elem("ID", OWNER_ID).elem("DisplayName", "mrk").close("Owner")
        writer.open("AccessControlList").raw(
            '<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">'  # noqa: E501
        )
        writer.elem("ID", OWNER_ID).elem("DisplayName", "mrk").raw("</Grantee>")
        writer.elem("Permission", "FULL_CONTROL").raw("</Grant>").close("AccessControlList").close(
            "AccessControlPolicy"
        )
        return writer.to_bytes()

    # Listing -----------------------------------------------------------------------
    def _token_key(self) -> bytes:
        return self.engine.token_key

    def make_token(self, bucket: str, marker: str) -> str:
        payload = json.dumps({"b": bucket, "k": marker}, separators=(",", ":")).encode("utf-8")
        mac = hmac.new(self._token_key(), payload, hashlib.sha256).digest()[:16]
        return base64.urlsafe_b64encode(mac + payload).decode("ascii").rstrip("=")

    def read_token(self, bucket: str, token: str) -> str:
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
            mac, payload = raw[:16], raw[16:]
            expected = hmac.new(self._token_key(), payload, hashlib.sha256).digest()[:16]
            if not hmac.compare_digest(mac, expected):
                raise ValueError
            data = json.loads(payload)
            if data.get("b") != bucket or not isinstance(data.get("k"), str):
                raise ValueError
            return data["k"]
        except (ValueError, binascii.Error, json.JSONDecodeError) as exc:
            raise S3Error(
                "InvalidArgument",
                "The continuation token provided is incorrect",
                ArgumentName="continuation-token",
            ) from exc

    def entry_info(self, bucket: BaseBucket, entry: Any) -> ObjectInfo:
        if isinstance(bucket, LinkedBucket):
            return bucket.entry_info(entry)
        return entry.payload

    async def list_objects(
        self, request: Request, principal: Principal, bucket: BaseBucket
    ) -> Response:
        query = request.query
        v2 = query.get("list-type") == "2"
        prefix = query.get("prefix", "")
        delimiter = query.get("delimiter", "")
        encoding = query.get("encoding-type")
        if encoding is not None and encoding != "url":
            raise S3Error(
                "InvalidArgument",
                "Invalid Encoding Method specified in Request",
                ArgumentName="encoding-type",
            )
        max_keys = _parse_int(query.get("max-keys"), "max-keys", default=1000) or 0
        max_keys = min(max_keys, self.settings.max_keys_per_list)
        self.require(
            principal,
            request,
            "s3:ListBucket",
            bucket.name,
            extra={"s3:prefix": prefix, "s3:delimiter": delimiter, "s3:max-keys": str(max_keys)},
        )
        if v2:
            token = query.get("continuation-token")
            start_after = query.get("start-after", "")
            marker = self.read_token(bucket.name, token) if token else start_after
        else:
            marker = query.get("marker", "")
        source = bucket.iter_entries(prefix, delimiter)

        def run() -> tuple[Any, list[ObjectInfo]]:
            page = list_page(
                source, prefix=prefix, delimiter=delimiter, marker=marker, max_keys=max_keys
            )
            return page, [self.entry_info(bucket, entry) for entry in page.contents]

        page, infos = await asyncio.to_thread(run)
        enc = encoding
        writer = XmlWriter().open("ListBucketResult", xmlns=True)
        writer.elem("Name", bucket.name).elem("Prefix", encode_key(prefix, enc))
        if v2:
            if query.get("continuation-token"):
                writer.elem("ContinuationToken", query["continuation-token"])
            if query.get("start-after"):
                writer.elem("StartAfter", encode_key(query["start-after"], enc))
            writer.elem("KeyCount", len(infos) + len(page.prefixes))
        else:
            writer.elem("Marker", encode_key(marker, enc))
        writer.elem("MaxKeys", max_keys)
        if delimiter:
            writer.elem("Delimiter", encode_key(delimiter, enc))
        if enc:
            writer.elem("EncodingType", enc)
        writer.elem("IsTruncated", page.truncated)
        if page.truncated and page.next_marker is not None:
            if v2:
                writer.elem("NextContinuationToken", self.make_token(bucket.name, page.next_marker))
            else:
                writer.elem("NextMarker", encode_key(page.next_marker, enc))
        fetch_owner = (not v2) or query.get("fetch-owner") == "true"
        for info in infos:
            writer.open("Contents").elem("Key", encode_key(info.key, enc))
            writer.elem("LastModified", iso8601(info.last_modified_ns)).elem(
                "ETag", quote_etag(info.etag)
            )
            algorithm = info.meta.get("checksum_algorithm")
            if algorithm:
                writer.elem("ChecksumAlgorithm", algorithm)
                writer.elem("ChecksumType", info.meta.get("checksum_type", "FULL_OBJECT"))
            writer.elem("Size", info.size)
            if fetch_owner:
                writer.open("Owner").elem("ID", OWNER_ID).elem("DisplayName", "mrk").close("Owner")
            writer.elem("StorageClass", info.meta.get("storage_class", "STANDARD")).close(
                "Contents"
            )
        for common in page.prefixes:
            writer.open("CommonPrefixes").elem("Prefix", encode_key(common, enc)).close(
                "CommonPrefixes"
            )
        writer.close("ListBucketResult")
        return xml_response(writer.to_bytes())

    async def list_uploads(self, request: Request, bucket: BaseBucket) -> Response:
        query = request.query
        prefix = query.get("prefix", "")
        delimiter = query.get("delimiter", "")
        key_marker = query.get("key-marker", "")
        id_marker = query.get("upload-id-marker", "")
        encoding = query.get("encoding-type")
        max_uploads = min(
            _parse_int(query.get("max-uploads"), "max-uploads", default=1000) or 0, 1000
        )
        uploads = await asyncio.to_thread(bucket.index.list_uploads)
        items = []
        prefixes: list[str] = []
        truncated = False
        last_key = last_id = None
        for upload in uploads:
            if not upload.key.startswith(prefix):
                continue
            if key_marker:
                if upload.key < key_marker or (
                    upload.key == key_marker and (not id_marker or upload.upload_id <= id_marker)
                ):
                    continue
            if delimiter:
                index = upload.key.find(delimiter, len(prefix))
                if index >= 0:
                    common = upload.key[: index + len(delimiter)]
                    if common in prefixes:
                        continue
                    if len(items) + len(prefixes) >= max_uploads:
                        truncated = True
                        break
                    prefixes.append(common)
                    continue
            if len(items) + len(prefixes) >= max_uploads:
                truncated = True
                break
            items.append(upload)
            last_key, last_id = upload.key, upload.upload_id
        writer = XmlWriter().open("ListMultipartUploadsResult", xmlns=True)
        writer.elem("Bucket", bucket.name).elem("KeyMarker", encode_key(key_marker, encoding)).elem(
            "UploadIdMarker", id_marker
        )
        if truncated:
            writer.elem("NextKeyMarker", encode_key(last_key or "", encoding)).elem(
                "NextUploadIdMarker", last_id or ""
            )
        if prefix:
            writer.elem("Prefix", encode_key(prefix, encoding))
        if delimiter:
            writer.elem("Delimiter", encode_key(delimiter, encoding))
        if encoding:
            writer.elem("EncodingType", encoding)
        writer.elem("MaxUploads", max_uploads).elem("IsTruncated", truncated)
        for upload in items:
            writer.open("Upload").elem("Key", encode_key(upload.key, encoding)).elem(
                "UploadId", upload.upload_id
            )
            writer.open("Initiator").elem("ID", upload.initiator).elem(
                "DisplayName", upload.initiator
            ).close("Initiator")
            writer.open("Owner").elem("ID", OWNER_ID).elem("DisplayName", "mrk").close("Owner")
            writer.elem("StorageClass", upload.meta.get("storage_class", "STANDARD"))
            writer.elem("Initiated", iso8601(upload.initiated_ns)).close("Upload")
        for common in prefixes:
            writer.open("CommonPrefixes").elem("Prefix", encode_key(common, encoding)).close(
                "CommonPrefixes"
            )
        writer.close("ListMultipartUploadsResult")
        return xml_response(writer.to_bytes())

    # DeleteObjects -----------------------------------------------------------------
    async def delete_objects(
        self, request: Request, principal: Principal, bucket: BaseBucket
    ) -> Response:
        body = await self.read_body_verified(request, principal)
        root = parse_xml(body)
        if root.tag != "Delete":
            raise S3Error("MalformedXML")
        quiet = (child_text(root, "Quiet") or "").strip().lower() == "true"
        objects = list(children(root, "Object"))
        if not objects or len(objects) > self.settings.max_delete_objects:
            raise S3Error("MalformedXML")
        # (key, requested version, resulting version id, delete marker?)
        deleted: list[tuple[str, str | None, str | None, bool]] = []
        errors: list[tuple[str, str, str]] = []
        for item in objects:
            key = child_text(item, "Key")
            if key is None:
                raise S3Error("MalformedXML")
            version = child_text(item, "VersionId") or None
            if version not in (None, "null") and not isinstance(bucket, ManagedBucket):
                errors.append((key, "NoSuchVersion", "The specified version does not exist."))
                continue
            action = "s3:DeleteObject" if version is None else "s3:DeleteObjectVersion"
            if not self.allowed(principal, request, action, bucket.name, key):
                errors.append((key, "AccessDenied", "Access Denied"))
                continue
            try:
                if isinstance(bucket, ManagedBucket):
                    vid, marker = await asyncio.to_thread(bucket.delete_detail, key, version)
                    deleted.append((key, version, vid, marker))
                else:
                    await asyncio.to_thread(bucket.delete, key)
                    deleted.append((key, version, None, False))
            except S3Error as exc:
                errors.append((key, exc.code, exc.message))
        writer = XmlWriter().open("DeleteResult", xmlns=True)
        if not quiet:
            for key, version, vid, marker in deleted:
                writer.open("Deleted").elem("Key", key)
                if version is not None:
                    writer.elem("VersionId", version)
                if marker:
                    writer.elem("DeleteMarker", True).elem("DeleteMarkerVersionId", vid)
                writer.close("Deleted")
        for key, code, message in errors:
            writer.open("Error").elem("Key", key).elem("Code", code).elem("Message", message).close(
                "Error"
            )
        writer.close("DeleteResult")
        return xml_response(writer.to_bytes())

    async def read_body_verified(
        self, request: Request, principal: Principal, *, require_digest: bool = True
    ) -> bytes:
        """Read a small (XML) body, verifying Content-MD5 / checksum / payload hash."""
        source = self.body_source(request, principal)
        data = bytearray()
        async for piece in source.iterate():
            data += piece
            if len(data) > self.settings.max_xml_body_bytes:
                raise S3Error("MalformedXML", "The request body is too large.")
        body = bytes(data)
        hasher = BodyHasher(source.algorithms, sha256=source.sha256_expected is not None)
        hasher.update(body)
        source.verify(hasher, body_md5=hasher.md5.digest())
        if require_digest and not request.header("content-md5") and not source.algorithms:
            raise S3Error("InvalidRequest", "Missing required header for this request: Content-MD5")
        return body

    # Objects -----------------------------------------------------------------------
    async def object_operation(self, request: Request, principal: Principal) -> Response:
        name = request.bucket
        key = request.key
        assert name is not None and key is not None
        bucket = self.bucket_for(name)
        query = request.query
        method = request.method
        if method in {"GET", "HEAD"}:
            if "uploadId" in query and method == "GET":
                self.require(principal, request, "s3:ListMultipartUploadParts", name, key)
                return await self.list_parts(request, bucket, key)
            if "acl" in query:
                self.require(principal, request, "s3:GetObjectAcl", name, key)
                return xml_response(self._acl_xml())
            if "tagging" in query and method == "GET":
                self.require(principal, request, "s3:GetObjectTagging", name, key)
                info = await self.tagging_target(bucket, key, query.get("versionId"))
                response = xml_response(
                    tagging.to_xml(tagging.decode(info.meta.get("tagging"), strict=False))
                )
                return self.version_header(response, bucket, info, query.get("versionId"))
            if {"attributes", "torrent", "retention", "legal-hold"} & set(query):
                raise S3Error("NotImplemented", "This object subresource is not implemented.")
            return await self.get_object(request, principal, bucket, key)
        if method == "PUT":
            if "tagging" in query:
                self.require(principal, request, "s3:PutObjectTagging", name, key)
                body = await self.read_body_verified(request, principal, require_digest=False)
                tags = tagging.parse_xml_tags(body, tagging.MAX_OBJECT_TAGS)
                info = await self.set_tags(bucket, key, query.get("versionId"), tags)
                return self.version_header(Response(200), bucket, info, query.get("versionId"))
            if {"acl", "retention", "legal-hold"} & set(query):
                raise S3Error("NotImplemented", "This object subresource is not implemented.")
            self.require(principal, request, "s3:PutObject", name, key)
            if "uploadId" in query or "partNumber" in query:
                if "x-amz-copy-source" in request.headers:
                    return await self.upload_part_copy(request, principal, bucket, key)
                return await self.upload_part(request, principal, bucket, key)
            if "x-amz-copy-source" in request.headers:
                return await self.copy_object(request, principal, bucket, key)
            return await self.put_object(request, principal, bucket, key)
        if method == "DELETE":
            if "uploadId" in query:
                self.require(principal, request, "s3:AbortMultipartUpload", name, key)
                bucket.get_upload(query["uploadId"], key)
                await asyncio.to_thread(bucket.abort_upload, query["uploadId"])
                return Response(204)
            if "tagging" in query:
                self.require(principal, request, "s3:DeleteObjectTagging", name, key)
                info = await self.set_tags(bucket, key, query.get("versionId"), [])
                return self.version_header(Response(204), bucket, info, query.get("versionId"))
            version = query.get("versionId")
            action = "s3:DeleteObject" if version is None else "s3:DeleteObjectVersion"
            self.require(principal, request, action, name, key)
            response = Response(204)
            if isinstance(bucket, ManagedBucket):
                vid, marker = await asyncio.to_thread(bucket.delete_detail, key, version)
                if vid is not None and (version is not None or bucket.versioning):
                    response.header("x-amz-version-id", vid)
                if marker:
                    response.header("x-amz-delete-marker", "true")
                return response
            if version not in (None, "null"):
                raise S3Error("NoSuchVersion", Key=key, VersionId=version)
            await asyncio.to_thread(bucket.delete, key)
            return response
        if method == "POST":
            if "uploads" in query:
                self.require(principal, request, "s3:PutObject", name, key)
                return self.create_upload(request, principal, bucket, key)
            if "uploadId" in query:
                self.require(principal, request, "s3:PutObject", name, key)
                return await self.complete_upload(request, principal, bucket, key)
            raise S3Error("NotImplemented", "This object operation is not implemented.")
        raise S3Error("MethodNotAllowed")

    # Versions and tags -------------------------------------------------------------
    def version_header(
        self,
        response: Response,
        bucket: BaseBucket,
        info: ObjectInfo | None,
        requested: str | None = None,
    ) -> Response:
        if info is not None and (requested is not None or bucket.versioning):
            response.header("x-amz-version-id", info.version_id)
        return response

    def resolve_version(self, bucket: BaseBucket, key: str, version: str) -> ObjectInfo:
        """The object info for ``?versionId=``; delete markers answer 405 like AWS."""
        if isinstance(bucket, ManagedBucket):
            record = bucket.head_version(key, version)
            if record is None:
                raise S3Error("NoSuchVersion", Key=key, VersionId=version)
            if record.delete_marker:
                raise S3Error(
                    "MethodNotAllowed",
                    headers={
                        "x-amz-delete-marker": "true",
                        "x-amz-version-id": record.version_id,
                        "Last-Modified": http_date(record.last_modified_ns),
                        "Allow": "DELETE",
                    },
                )
            return bucket.version_info(record)
        info = bucket.head(key)
        if version != "null" or info is None:
            raise S3Error("NoSuchVersion", Key=key, VersionId=version)
        return info

    def missing_key(self, bucket: BaseBucket, key: str) -> S3Error:
        """``NoSuchKey``, flagged when the latest version is a delete marker."""
        headers: dict[str, str] = {}
        if isinstance(bucket, ManagedBucket) and bucket.versioning:
            marker = bucket.index.latest_marker(key)
            if marker is not None:
                headers = {"x-amz-delete-marker": "true", "x-amz-version-id": marker.version_id}
        return S3Error("NoSuchKey", headers=headers, Key=key)

    async def tagging_target(self, bucket: BaseBucket, key: str, version: str | None) -> ObjectInfo:
        if version is not None:
            return await asyncio.to_thread(self.resolve_version, bucket, key, version)
        info = await asyncio.to_thread(bucket.head, key)
        if info is None or info.is_dir and isinstance(bucket, LinkedBucket):
            raise await asyncio.to_thread(self.missing_key, bucket, key)
        return info

    async def set_tags(
        self, bucket: BaseBucket, key: str, version: str | None, tags: tagging.Tags
    ) -> ObjectInfo:
        bucket.check_writable()
        async with bucket.lock_for(key):
            info = await self.tagging_target(bucket, key, version)
            meta = dict(info.meta)
            if tags:
                meta["tagging"] = tagging.encode(tags)
            else:
                meta.pop("tagging", None)
            stored = await asyncio.to_thread(
                bucket.set_object_meta, key, meta, info.version_id if version is not None else None
            )
        if not stored:
            raise S3Error("NoSuchKey", Key=key)
        info.meta = meta
        return info

    # Common object headers ----------------------------------------------------------
    def object_headers(self, response: Response, info: ObjectInfo) -> None:
        meta = info.meta
        response.header("ETag", quote_etag(info.etag))
        response.header("Last-Modified", http_date(info.last_modified_ns))
        response.header("Accept-Ranges", "bytes")
        response.header("Content-Type", meta.get("content_type") or "binary/octet-stream")
        response.header("X-Content-Type-Options", "nosniff")
        for header, field_name in CONTENT_HEADERS.items():
            if header == "content-type":
                continue
            value = meta.get(field_name)
            if value:
                response.header(header.title(), value)
        if meta.get("content_encoding"):
            response.header("Content-Encoding", meta["content_encoding"])
        storage_class = meta.get("storage_class")
        if storage_class and storage_class != "STANDARD":
            response.header("x-amz-storage-class", storage_class)
        for name, value in (meta.get("user") or {}).items():
            response.header(f"x-amz-meta-{name}", value)
        if meta.get("tagging"):
            response.header(
                "x-amz-tagging-count", len(tagging.decode(meta["tagging"], strict=False))
            )

    def checksum_headers(self, response: Response, info: ObjectInfo) -> None:
        for algorithm, value in (info.meta.get("checksums") or {}).items():
            response.header(checksums.HEADER_FOR[algorithm], value)
        if info.meta.get("checksums"):
            response.header("x-amz-checksum-type", info.meta.get("checksum_type", "FULL_OBJECT"))

    async def get_object(
        self, request: Request, principal: Principal, bucket: BaseBucket, key: str
    ) -> Response:
        version = request.query.get("versionId")
        action = "s3:GetObject" if version is None else "s3:GetObjectVersion"
        if not self.allowed(principal, request, action, bucket.name, key):
            raise S3Error("AccessDenied")
        if version is not None:
            info = await asyncio.to_thread(self.resolve_version, bucket, key, version)
        else:
            found = await asyncio.to_thread(bucket.head, key)
            if found is None:
                if not self.allowed(principal, request, "s3:ListBucket", bucket.name):
                    raise S3Error("AccessDenied")
                raise await asyncio.to_thread(self.missing_key, bucket, key)
            info = found
        status = evaluate_conditions(request.headers, info)
        if status == 304:
            response = Response(304)
            response.header("ETag", quote_etag(info.etag)).header(
                "Last-Modified", http_date(info.last_modified_ns)
            )
            return response
        if status == 412:
            raise S3Error("PreconditionFailed", Condition="If-Match")
        size = info.size
        byte_range: tuple[int, int] | None = None
        part_number = _parse_int(request.query.get("partNumber"), "partNumber", minimum=1)
        response = Response(200)
        if part_number is not None:
            segments = (
                [seg[1] for seg in info.segments] if info.segments and info.parts_count else [size]
            )
            if part_number > len(segments):
                raise S3Error(
                    "InvalidPartNumber", "The requested partnumber is not satisfiable", 416
                )
            start = sum(segments[: part_number - 1])
            byte_range = (
                (start, start + segments[part_number - 1] - 1)
                if segments[part_number - 1]
                else None
            )
            response.header("x-amz-mp-parts-count", len(segments) if info.parts_count else None)
        else:
            byte_range = parse_range(request.header("range"), size)
        self.object_headers(response, info)
        self.version_header(response, bucket, info, version)
        if principal.identity is not None:
            for param, header in RESPONSE_OVERRIDES.items():
                if param in request.query:
                    response.headers = [
                        (n, v) for n, v in response.headers if n.lower() != header.lower()
                    ]
                    response.header(header, request.query[param])
        if byte_range is not None and (byte_range != (0, size - 1) or request.header("range")):
            start, end = byte_range
            response.status = 206
            response.header("Content-Range", f"bytes {start}-{end}/{size}")
        else:
            start, end = 0, size - 1
            if (request.header("x-amz-checksum-mode") or "").upper() == "ENABLED":
                self.checksum_headers(response, info)
        length = max(0, end - start + 1)
        response.content_length = length
        if request.method == "HEAD" or length == 0:
            response.body = b""
            return response
        opened = await asyncio.to_thread(self._open, bucket, info)
        stream = stream_fds(opened, start, end)
        if (
            isinstance(bucket, LinkedBucket)
            and not info.validated
            and start == 0
            and end == size - 1
        ):
            stream = self._hash_while_streaming(bucket, info, stream)
        response.body = stream
        return response

    def _open(self, bucket: BaseBucket, info: ObjectInfo) -> list[tuple[int, int]]:
        if isinstance(bucket, LinkedBucket):
            return bucket.open_object(info)
        try:
            return open_segments(info.segments)
        except FileNotFoundError as exc:
            raise S3Error("InternalError", "The object data is missing.") from exc

    async def _hash_while_streaming(
        self, bucket: LinkedBucket, info: ObjectInfo, stream: AsyncIterator[bytes]
    ) -> AsyncIterator[bytes]:
        digest = hashlib.md5(usedforsecurity=False)
        total = 0
        try:
            async for chunk in stream:
                digest.update(chunk)
                total += len(chunk)
                yield chunk
        finally:
            await stream.aclose()  # type: ignore[attr-defined]
        if total == info.size:
            current = await asyncio.to_thread(bucket.head, info.key)
            if current is not None and current.etag == info.etag and current.size == info.size:
                parts_stat = await asyncio.to_thread(self._stat_linked, bucket, info.key)
                if parts_stat is not None:
                    await asyncio.to_thread(
                        bucket.store_md5, info.key, parts_stat, digest.hexdigest()
                    )

    @staticmethod
    def _stat_linked(bucket: LinkedBucket, key: str) -> os.stat_result | None:
        from .linked import key_parts

        parts, _ = key_parts(key)
        try:
            with bucket.safe.open_dir(parts[:-1]) as handle:
                return bucket.safe.lstat(handle, parts[-1])
        except OSError:
            return None

    # Write path --------------------------------------------------------------------
    def body_source(self, request: Request, principal: Principal) -> BodySource:
        return BodySource(self, request, principal)

    def collect_meta(self, request: Request) -> dict[str, Any]:
        headers = request.headers
        meta: dict[str, Any] = {}
        for header, field_name in CONTENT_HEADERS.items():
            value = request.header(header)
            if value:
                meta[field_name] = value
        encoding = [
            item.strip()
            for item in (headers.get("content-encoding") or "").split(",")
            if item.strip()
        ]
        encoding = [item for item in encoding if item.lower() != "aws-chunked"]
        if encoding:
            meta["content_encoding"] = ",".join(encoding)
        meta.setdefault("content_type", "binary/octet-stream")
        user: dict[str, str] = {}
        total = 0
        for name, value in request.header_list:
            if name.startswith("x-amz-meta-"):
                short = name[len("x-amz-meta-") :]
                if short in user:
                    user[short] = f"{user[short]},{value.strip()}"
                else:
                    user[short] = value.strip()
                total += len(short) + len(value)
        if total > self.settings.max_user_metadata_bytes:
            raise S3Error(
                "MetadataTooLarge", MaxMetadataSize=str(self.settings.max_user_metadata_bytes)
            )
        if user:
            meta["user"] = user
        storage_class = headers.get("x-amz-storage-class")
        if storage_class:
            if storage_class not in STORAGE_CLASSES:
                raise S3Error("InvalidStorageClass", StorageClassRequested=storage_class)
            meta["storage_class"] = storage_class
        if headers.get("x-amz-tagging"):
            stored = tagging.from_header(headers["x-amz-tagging"])
            if stored:
                meta["tagging"] = stored
        self.check_unsupported_headers(request)
        return meta

    def check_unsupported_headers(self, request: Request) -> None:
        headers = request.headers
        acl = headers.get("x-amz-acl")
        if acl and acl not in ACCEPTED_ACLS:
            raise S3Error(
                "NotImplemented",
                "Canned ACLs other than private are not supported; use the bucket's public setting.",  # noqa: E501
            )
        if any(name.startswith("x-amz-grant-") for name in headers):
            raise S3Error("NotImplemented", "ACL grants are not supported.")
        if headers.get("x-amz-server-side-encryption") or headers.get(
            "x-amz-server-side-encryption-customer-algorithm"
        ):
            raise S3Error("NotImplemented", "Server-side encryption is not implemented.")
        if headers.get("x-amz-object-lock-mode") or headers.get("x-amz-object-lock-legal-hold"):
            raise S3Error("NotImplemented", "Object lock is not implemented.")

    def check_quota(
        self, bucket: BaseBucket, adding: int, replacing: int = 0, *, new_object: bool = False
    ) -> int | None:
        """Raise when ``adding`` bytes do not fit; return the remaining budget (None = unlimited).

        Checks the bucket's own quota and, for a «my space» bucket, the byte/object quota
        its workspace shares across all its buckets (docs/43 §3).
        """
        remaining: int | None = None
        quota = bucket.config.quota_bytes
        if quota is not None:
            _objects, used = bucket.usage()
            used += bucket.index.uploads_bytes() if isinstance(bucket, ManagedBucket) else 0
            remaining = quota - used + replacing
            if adding > remaining:
                raise S3Error(
                    "QuotaExceeded", f"The bucket quota of {quota} bytes would be exceeded."
                )
        group = self.snapshot.groups.get(bucket.config.name)
        if group is not None and (group.max_bytes is not None or group.max_objects is not None):
            objects = used_bytes = 0
            for name in group.buckets:
                member = self.engine.bucket(name)
                if member is None:
                    continue
                count, size = member.usage()
                objects += count
                used_bytes += size
                if isinstance(member, ManagedBucket):
                    used_bytes += member.index.uploads_bytes()
            if group.max_objects is not None and new_object and objects + 1 > group.max_objects:
                raise S3Error(
                    "QuotaExceeded",
                    f"The workspace file limit of {group.max_objects} would be exceeded.",
                )
            if group.max_bytes is not None:
                left = group.max_bytes - used_bytes + replacing
                if adding > left:
                    raise S3Error(
                        "QuotaExceeded",
                        f"The workspace quota of {group.max_bytes} bytes would be exceeded.",
                    )
                remaining = left if remaining is None else min(remaining, left)
        return None if remaining is None else max(0, remaining)

    def check_disk(self, bucket: BaseBucket) -> None:
        path = bucket.storage_path()
        try:
            usage = shutil.disk_usage(path if path.exists() else self.settings.data_root)
        except OSError:
            return
        if usage.total and usage.used * 100 / usage.total >= self.settings.disk_block_percent:
            raise S3Error("InsufficientStorage", "The storage volume is above its fill watermark.")

    async def put_object(
        self, request: Request, principal: Principal, bucket: BaseBucket, key: str
    ) -> Response:
        bucket.check_writable()
        if has_invalid_xml_chars(key):
            raise S3Error(
                "InvalidArgument",
                "Object keys must not contain characters XML cannot represent.",
                ArgumentName="key",
            )
        meta = self.collect_meta(request)
        source = self.body_source(request, principal)
        declared = source.declared_length
        limit = min(self.settings.max_single_put_bytes, self.snapshot.max_object_bytes)
        if declared is not None and declared > limit:
            raise S3Error("EntityTooLarge", MaxSizeAllowed=str(limit), ProposedSize=str(declared))
        existing = await asyncio.to_thread(bucket.head, key)
        await self.check_conditional_write(request, existing)
        remaining = self.check_quota(
            bucket, declared or 0, existing.size if existing else 0, new_object=existing is None
        )
        self.check_disk(bucket)
        if key.endswith("/") and isinstance(bucket, LinkedBucket):
            if declared not in (0, None):
                raise S3Error("InvalidArgument", "Folder keys in a linked folder must be empty.")
            async for piece in source.iterate():
                if piece:
                    raise S3Error(
                        "InvalidArgument", "Folder keys in a linked folder must be empty."
                    )
            source.verify(
                BodyHasher(source.algorithms, sha256=source.sha256_expected is not None),
                body_md5=hashlib.md5(b"", usedforsecurity=False).digest(),
            )
            info = await asyncio.to_thread(bucket.make_dir_marker, key)
            return Response(200).header("ETag", quote_etag(EMPTY_MD5))
        pending = await asyncio.to_thread(bucket.new_temp, key)
        try:
            hasher = BodyHasher(source.algorithms, sha256=source.sha256_expected is not None)
            await write_stream(
                source.iterate(), pending, hasher, size_limit=limit, quota_limit=remaining
            )
            source.verify(hasher, body_md5=hasher.md5.digest())
            values = hasher.checksum_values()
            if values:
                meta["checksums"] = values
                meta["checksum_algorithm"] = next(iter(values))
                meta["checksum_type"] = "FULL_OBJECT"
            etag = hasher.md5.hexdigest()
            async with bucket.lock_for(key):
                current = await asyncio.to_thread(bucket.head, key)
                await self.check_conditional_write(request, current)
                info = await asyncio.to_thread(bucket.commit_object, pending, key, etag, meta)
        except BaseException:
            await asyncio.to_thread(self._discard, bucket, pending)
            raise
        response = Response(200).header("ETag", quote_etag(info.etag))
        self.version_header(response, bucket, info)
        for algorithm, value in values.items():
            response.header(checksums.HEADER_FOR[algorithm], value)
        if values:
            response.header("x-amz-checksum-type", "FULL_OBJECT")
        return response

    @staticmethod
    def _discard(bucket: BaseBucket, pending: PendingWrite) -> None:
        if isinstance(bucket, LinkedBucket) and "handle" in pending.extra:
            bucket.discard(pending)
        else:
            pending.abort()

    async def check_conditional_write(self, request: Request, existing: ObjectInfo | None) -> None:
        if_none = request.header("if-none-match")
        if if_none is not None:
            if if_none.strip() != "*":
                raise S3Error("NotImplemented", "If-None-Match only supports '*' on writes.")
            if existing is not None:
                raise S3Error("PreconditionFailed", Condition="If-None-Match")
        if_match = request.header("if-match")
        if if_match is not None:
            if existing is None:
                raise S3Error("NoSuchKey", Key=request.key)
            if not _etag_matches(if_match, existing.etag):
                raise S3Error("PreconditionFailed", Condition="If-Match")

    # Copy --------------------------------------------------------------------------
    def parse_copy_source(self, request: Request) -> tuple[str, str, str | None]:
        raw = request.header("x-amz-copy-source") or ""
        raw, _, query = raw.partition("?")
        version: str | None = None
        if query:
            for name, value in s3sigv4.parse_query(query):
                if name == "versionId":
                    version = value
        decoded = unquote(raw)
        if decoded.startswith("/"):
            decoded = decoded[1:]
        bucket, sep, key = decoded.partition("/")
        if not sep or not bucket or not key:
            raise S3Error(
                "InvalidArgument",
                "Copy Source must mention the source bucket and key: sourcebucket/sourcekey",
                ArgumentName="x-amz-copy-source",
            )
        return bucket, key, version

    async def copy_source_info(
        self, request: Request, principal: Principal
    ) -> tuple[BaseBucket, ObjectInfo]:
        source_bucket_name, source_key, version = self.parse_copy_source(request)
        action = "s3:GetObject" if version is None else "s3:GetObjectVersion"
        self.require(principal, request, action, source_bucket_name, source_key)
        source_bucket = self.bucket_for(source_bucket_name)
        if version is not None:
            try:
                info = await asyncio.to_thread(
                    self.resolve_version, source_bucket, source_key, version
                )
            except S3Error as exc:
                if exc.code == "MethodNotAllowed":
                    raise S3Error(
                        "InvalidRequest",
                        "The source of a copy request may not specifically refer to a delete marker by version id.",  # noqa: E501
                    ) from exc
                raise
            info.meta = dict(info.meta, copy_source_version=version)
        else:
            found = await asyncio.to_thread(source_bucket.head, source_key)
            if found is None:
                raise S3Error("NoSuchKey", Key=source_key)
            info = found
        status = evaluate_conditions(request.headers, info, copy_source=True)
        if status is not None:
            raise S3Error("PreconditionFailed", Condition="x-amz-copy-source-If-Match")
        return source_bucket, info

    async def copy_object(
        self, request: Request, principal: Principal, bucket: BaseBucket, key: str
    ) -> Response:
        bucket.check_writable()
        if has_invalid_xml_chars(key):
            raise S3Error(
                "InvalidArgument",
                "Object keys must not contain characters XML cannot represent.",
                ArgumentName="key",
            )
        source_bucket, info = await self.copy_source_info(request, principal)
        directive = (request.header("x-amz-metadata-directive") or "COPY").upper()
        if directive not in {"COPY", "REPLACE"}:
            raise S3Error(
                "InvalidArgument",
                "Unknown metadata directive.",
                ArgumentName="x-amz-metadata-directive",
            )
        source_version = info.meta.get("copy_source_version")
        same = source_bucket.name == bucket.name and info.key == key
        if (
            same
            and source_version is None
            and directive == "COPY"
            and not request.header("x-amz-storage-class")
            and (request.header("x-amz-tagging-directive") or "COPY").upper() != "REPLACE"
        ):
            raise S3Error(
                "InvalidRequest",
                "This copy request is illegal because it is trying to copy an object to itself without changing "  # noqa: E501
                "the object's metadata, storage class, website redirect location or encryption attributes.",  # noqa: E501
            )
        if info.size > MAX_COPY_SOURCE:
            raise S3Error(
                "InvalidRequest",
                f"The specified copy source is larger than the maximum allowable size for a copy source: {MAX_COPY_SOURCE}",  # noqa: E501
            )
        if directive == "REPLACE":
            meta = self.collect_meta(request)
        else:
            self.check_unsupported_headers(request)
            meta = {k: v for k, v in info.meta.items() if k not in COPY_EXCLUDED_META}
            if request.header("x-amz-storage-class"):
                meta["storage_class"] = request.header("x-amz-storage-class")
        meta.pop("copy_source_version", None)
        tag_directive = (request.header("x-amz-tagging-directive") or "COPY").upper()
        if tag_directive not in {"COPY", "REPLACE"}:
            raise S3Error(
                "InvalidArgument",
                "Unknown tagging directive.",
                ArgumentName="x-amz-tagging-directive",
            )
        new_tags = (
            tagging.from_header(request.header("x-amz-tagging") or "")
            if tag_directive == "REPLACE"
            else info.meta.get("tagging")
        )
        if new_tags:
            meta["tagging"] = new_tags
        else:
            meta.pop("tagging", None)
        existing = await asyncio.to_thread(bucket.head, key)
        self.check_quota(
            bucket, info.size, existing.size if existing else 0, new_object=existing is None
        )
        self.check_disk(bucket)
        if info.is_dir and isinstance(bucket, LinkedBucket):
            result = await asyncio.to_thread(bucket.make_dir_marker, key)
        elif (
            isinstance(bucket, ManagedBucket)
            and isinstance(source_bucket, ManagedBucket)
            and not same
            and not info.parts_count
        ):
            meta["checksums"] = (
                info.meta.get("checksums")
                if directive == "COPY" or "checksums" not in meta
                else meta["checksums"]
            )
            if not meta.get("checksums"):
                meta.pop("checksums", None)
            else:
                meta["checksum_algorithm"] = info.meta.get("checksum_algorithm")
                meta["checksum_type"] = info.meta.get("checksum_type", "FULL_OBJECT")
            result = await asyncio.to_thread(bucket.link_copy, info, key, meta)
            if result is None:
                result = await self._stream_copy(bucket, source_bucket, info, key, meta, request)
        else:
            result = await self._stream_copy(bucket, source_bucket, info, key, meta, request)
        writer = XmlWriter().open("CopyObjectResult", xmlns=True)
        writer.elem("LastModified", iso8601(result.last_modified_ns)).elem(
            "ETag", quote_etag(result.etag)
        )
        for algorithm, value in (result.meta.get("checksums") or {}).items():
            writer.elem(f"Checksum{algorithm}", value)
        writer.close("CopyObjectResult")
        response = xml_response(writer.to_bytes())
        self.version_header(response, bucket, result)
        if source_version is not None:
            response.header("x-amz-copy-source-version-id", source_version)
        elif source_bucket.versioning:
            response.header("x-amz-copy-source-version-id", info.version_id)
        return response

    async def _stream_copy(
        self,
        bucket: BaseBucket,
        source_bucket: BaseBucket,
        info: ObjectInfo,
        key: str,
        meta: dict[str, Any],
        request: Request,
    ) -> ObjectInfo:
        algorithms = set((info.meta.get("checksums") or {}).keys())
        if info.parts_count:
            algorithms = set()
        requested = checksums.normalize_algorithm(request.header("x-amz-checksum-algorithm"))
        if requested:
            algorithms = {requested}
        meta.pop("parts_count", None)
        pending = await asyncio.to_thread(bucket.new_temp, key)
        try:
            hasher = BodyHasher(algorithms)
            if info.size:
                opened = await asyncio.to_thread(self._open, source_bucket, info)
                await write_stream(stream_fds(opened, 0, info.size - 1), pending, hasher)
            values = hasher.checksum_values()
            meta.pop("checksums", None)
            meta.pop("checksum_algorithm", None)
            meta.pop("checksum_type", None)
            if values:
                meta["checksums"] = values
                meta["checksum_algorithm"] = next(iter(values))
                meta["checksum_type"] = "FULL_OBJECT"
            async with bucket.lock_for(key):
                return await asyncio.to_thread(
                    bucket.commit_object, pending, key, hasher.md5.hexdigest(), meta
                )
        except BaseException:
            await asyncio.to_thread(self._discard, bucket, pending)
            raise

    # Multipart ---------------------------------------------------------------------
    def create_upload(
        self, request: Request, principal: Principal, bucket: BaseBucket, key: str
    ) -> Response:
        bucket.check_writable()
        if has_invalid_xml_chars(key):
            raise S3Error(
                "InvalidArgument",
                "Object keys must not contain characters XML cannot represent.",
                ArgumentName="key",
            )
        if isinstance(bucket, LinkedBucket):
            from .linked import key_parts

            parts, is_dir = key_parts(key)
            if is_dir:
                raise S3Error("InvalidArgument", "Folder keys cannot carry data.")
        meta = self.collect_meta(request)
        algorithm_header = request.header("x-amz-checksum-algorithm")
        algorithm = checksums.normalize_algorithm(algorithm_header)
        if algorithm_header and algorithm is None:
            raise S3Error("InvalidRequest", "Checksum algorithm is not supported.")
        checksum_type = (request.header("x-amz-checksum-type") or "").upper()
        if algorithm:
            if not checksum_type:
                checksum_type = "FULL_OBJECT" if algorithm == "CRC64NVME" else "COMPOSITE"
            if checksum_type not in {"COMPOSITE", "FULL_OBJECT"}:
                raise S3Error("InvalidRequest", "Value for x-amz-checksum-type is invalid.")
            if checksum_type == "FULL_OBJECT" and algorithm not in checksums.CRC_WIDTH:
                raise S3Error(
                    "InvalidRequest", "The FULL_OBJECT checksum type requires a CRC algorithm."
                )
            if checksum_type == "COMPOSITE" and algorithm == "CRC64NVME":
                raise S3Error(
                    "InvalidRequest", "CRC64NVME only supports the FULL_OBJECT checksum type."
                )
            meta["checksum_algorithm"] = algorithm
            meta["checksum_type"] = checksum_type
        initiator = principal.identity.canonical_id if principal.identity else "anonymous"
        upload = bucket.create_upload(key, meta, initiator)
        writer = XmlWriter().open("InitiateMultipartUploadResult", xmlns=True)
        writer.elem("Bucket", bucket.name).elem("Key", key).elem("UploadId", upload.upload_id)
        writer.close("InitiateMultipartUploadResult")
        response = xml_response(writer.to_bytes())
        if algorithm:
            response.header("x-amz-checksum-algorithm", algorithm).header(
                "x-amz-checksum-type", checksum_type
            )
        return response

    def _part_number(self, request: Request) -> int:
        number = _parse_int(request.query.get("partNumber"), "partNumber", minimum=1)
        if number is None or number > self.settings.multipart_max_parts:
            raise S3Error(
                "InvalidArgument",
                "Part number must be an integer between 1 and 10000, inclusive",
                ArgumentName="partNumber",
            )
        return number

    async def upload_part(
        self, request: Request, principal: Principal, bucket: BaseBucket, key: str
    ) -> Response:
        bucket.check_writable()
        upload_id = request.query.get("uploadId") or ""
        number = self._part_number(request)
        upload = bucket.get_upload(upload_id, key)
        source = self.body_source(request, principal)
        upload_algorithm = upload.meta.get("checksum_algorithm")
        if upload_algorithm:
            source.algorithms.add(upload_algorithm)
        declared = source.declared_length
        if declared is not None and declared > self.settings.max_part_bytes:
            raise S3Error("EntityTooLarge", MaxSizeAllowed=str(self.settings.max_part_bytes))
        remaining = self.check_quota(bucket, declared or 0)
        self.check_disk(bucket)
        pending = await asyncio.to_thread(bucket.part_temp, upload_id)
        try:
            hasher = BodyHasher(source.algorithms, sha256=source.sha256_expected is not None)
            await write_stream(
                source.iterate(),
                pending,
                hasher,
                size_limit=self.settings.max_part_bytes,
                quota_limit=remaining,
            )
            source.verify(hasher, body_md5=hasher.md5.digest())
            values = hasher.checksum_values()
            part = await asyncio.to_thread(
                bucket.commit_part, pending, upload, number, hasher.md5.hexdigest(), values
            )
        except BaseException:
            pending.abort()
            raise
        response = Response(200).header("ETag", quote_etag(part.etag))
        for algorithm, value in values.items():
            response.header(checksums.HEADER_FOR[algorithm], value)
        return response

    async def upload_part_copy(
        self, request: Request, principal: Principal, bucket: BaseBucket, key: str
    ) -> Response:
        bucket.check_writable()
        upload_id = request.query.get("uploadId") or ""
        number = self._part_number(request)
        upload = bucket.get_upload(upload_id, key)
        source_bucket, info = await self.copy_source_info(request, principal)
        start, end = 0, info.size - 1
        range_header = request.header("x-amz-copy-source-range")
        if range_header:
            spec = range_header.strip()
            if not spec.startswith("bytes="):
                raise S3Error(
                    "InvalidArgument",
                    "The x-amz-copy-source-range value must be of the form bytes=first-last",
                    ArgumentName="x-amz-copy-source-range",
                )
            first, _, last = spec[6:].partition("-")
            try:
                start, end = int(first), int(last)
            except ValueError as exc:
                raise S3Error(
                    "InvalidArgument",
                    "The x-amz-copy-source-range value must be of the form bytes=first-last",
                    ArgumentName="x-amz-copy-source-range",
                ) from exc
            if start < 0 or end < start or end >= info.size:
                raise S3Error("InvalidRange", headers={"Content-Range": f"bytes */{info.size}"})
        length = max(0, end - start + 1)
        if length > self.settings.max_part_bytes:
            raise S3Error("EntityTooLarge")
        self.check_quota(bucket, length)
        algorithms = (
            {upload.meta["checksum_algorithm"]} if upload.meta.get("checksum_algorithm") else set()
        )
        pending = await asyncio.to_thread(bucket.part_temp, upload_id)
        try:
            hasher = BodyHasher(algorithms)
            if length:
                opened = await asyncio.to_thread(self._open, source_bucket, info)
                await write_stream(stream_fds(opened, start, end), pending, hasher)
            part = await asyncio.to_thread(
                bucket.commit_part,
                pending,
                upload,
                number,
                hasher.md5.hexdigest(),
                hasher.checksum_values(),
            )
        except BaseException:
            pending.abort()
            raise
        writer = XmlWriter().open("CopyPartResult", xmlns=True)
        writer.elem("LastModified", iso8601(part.last_modified_ns)).elem(
            "ETag", quote_etag(part.etag)
        )
        for algorithm, value in part.checksums.items():
            writer.elem(f"Checksum{algorithm}", value)
        writer.close("CopyPartResult")
        return xml_response(writer.to_bytes())

    async def list_parts(self, request: Request, bucket: BaseBucket, key: str) -> Response:
        upload = bucket.get_upload(request.query.get("uploadId") or "", key)
        max_parts = min(
            _parse_int(request.query.get("max-parts"), "max-parts", default=1000) or 0, 1000
        )
        marker = (
            _parse_int(request.query.get("part-number-marker"), "part-number-marker", default=0)
            or 0
        )
        parts = [
            p
            for p in await asyncio.to_thread(bucket.index.list_parts, upload.upload_id)
            if p.part_number > marker
        ]
        truncated = len(parts) > max_parts
        parts = parts[:max_parts]
        writer = XmlWriter().open("ListPartsResult", xmlns=True)
        writer.elem("Bucket", bucket.name).elem("Key", key).elem("UploadId", upload.upload_id)
        writer.open("Initiator").elem("ID", upload.initiator).elem(
            "DisplayName", upload.initiator
        ).close("Initiator")
        writer.open("Owner").elem("ID", OWNER_ID).elem("DisplayName", "mrk").close("Owner")
        writer.elem("StorageClass", upload.meta.get("storage_class", "STANDARD"))
        writer.elem("PartNumberMarker", marker)
        writer.elem("NextPartNumberMarker", parts[-1].part_number if parts else marker)
        writer.elem("MaxParts", max_parts).elem("IsTruncated", truncated)
        if upload.meta.get("checksum_algorithm"):
            writer.elem("ChecksumAlgorithm", upload.meta["checksum_algorithm"])
            writer.elem("ChecksumType", upload.meta.get("checksum_type"))
        for part in parts:
            writer.open("Part").elem("PartNumber", part.part_number).elem(
                "LastModified", iso8601(part.last_modified_ns)
            )
            writer.elem("ETag", quote_etag(part.etag)).elem("Size", part.size)
            for algorithm, value in part.checksums.items():
                writer.elem(f"Checksum{algorithm}", value)
            writer.close("Part")
        writer.close("ListPartsResult")
        return xml_response(writer.to_bytes())

    async def complete_upload(
        self, request: Request, principal: Principal, bucket: BaseBucket, key: str
    ) -> Response:
        bucket.check_writable()
        upload_id = request.query.get("uploadId") or ""
        upload = bucket.get_upload(upload_id, key)
        body = await self.read_body_verified(request, principal, require_digest=False)
        root = parse_xml(body)
        if root.tag != "CompleteMultipartUpload":
            raise S3Error("MalformedXML")
        requested: list[tuple[int, str, dict[str, str]]] = []
        for item in children(root, "Part"):
            number_text = child_text(item, "PartNumber")
            etag = child_text(item, "ETag")
            if number_text is None or etag is None:
                raise S3Error("MalformedXML")
            try:
                number = int(number_text)
            except ValueError as exc:
                raise S3Error("MalformedXML") from exc
            sums = {}
            for algorithm in checksums.ALGORITHMS:
                value = child_text(item, f"Checksum{algorithm}")
                if value:
                    sums[algorithm] = value.strip()
            requested.append((number, strip_etag(etag), sums))
        if not requested:
            raise S3Error("MalformedXML", "You must specify at least one part.")
        stored = {
            part.part_number: part
            for part in await asyncio.to_thread(bucket.index.list_parts, upload_id)
        }
        chosen: list[PartRecord] = []
        previous = 0
        for number, etag, sums in requested:
            if number <= previous:
                raise S3Error("InvalidPartOrder", UploadId=upload_id)
            previous = number
            part = stored.get(number)
            if part is None or part.etag.lower() != etag:
                raise S3Error("InvalidPart", UploadId=upload_id, PartNumber=str(number), ETag=etag)
            for algorithm, value in sums.items():
                if part.checksums.get(algorithm) and part.checksums[algorithm] != value:
                    raise S3Error(
                        "InvalidPart",
                        f"The checksum for part {number} does not match.",
                        UploadId=upload_id,
                    )
            chosen.append(part)
        minimum = self.settings.multipart_min_part_bytes
        for part in chosen[:-1]:
            if part.size < minimum:
                raise S3Error(
                    "EntityTooSmall",
                    ProposedSize=str(part.size),
                    MinSizeAllowed=str(minimum),
                    PartNumber=str(part.part_number),
                )
        total = sum(part.size for part in chosen)
        if total > self.snapshot.max_object_bytes:
            raise S3Error("EntityTooLarge", MaxSizeAllowed=str(self.snapshot.max_object_bytes))
        meta = dict(upload.meta)
        algorithm = meta.get("checksum_algorithm")
        result_checksum: str | None = None
        if algorithm:
            digests: list[bytes] = []
            for part in chosen:
                value = part.checksums.get(algorithm)
                raw = checksums.decode_value(algorithm, value) if value else None
                if raw is None:
                    raise S3Error(
                        "InvalidPart",
                        f"Part {part.part_number} has no {algorithm} checksum.",
                        UploadId=upload_id,
                    )
                digests.append(raw)
            if meta.get("checksum_type") == "FULL_OBJECT":
                full = checksums.combine_full_object(
                    algorithm, list(zip(digests, [p.size for p in chosen], strict=True))
                )
                result_checksum = checksums.b64(full)
            else:
                result_checksum = checksums.composite(algorithm, digests)
            provided = request.header(checksums.HEADER_FOR[algorithm])
            if provided and provided.strip() != result_checksum:
                raise S3Error(
                    "BadDigest",
                    f"The {algorithm} you specified did not match the calculated checksum.",
                )
            meta["checksums"] = {algorithm: result_checksum}
        meta["parts_count"] = len(chosen)
        etag = multipart_etag([part.etag for part in chosen])
        existing = await asyncio.to_thread(bucket.head, key)
        await self.check_conditional_write(request, existing)
        self.check_quota(bucket, 0, new_object=existing is None)

        async def assemble() -> ObjectInfo:
            async with bucket.lock_for(key):
                return await asyncio.to_thread(bucket.complete_upload, upload, chosen, etag, meta)

        location = (
            f"{self.snapshot.public_endpoint}/{bucket.name}/{quote(key, safe='/')}"
            if self.snapshot.public_endpoint
            else f"/{bucket.name}/{quote(key, safe='/')}"
        )

        def success_xml(info: ObjectInfo) -> bytes:
            writer = XmlWriter().open("CompleteMultipartUploadResult", xmlns=True)
            writer.elem("Location", location).elem("Bucket", bucket.name).elem("Key", key).elem(
                "ETag", quote_etag(info.etag)
            )
            if algorithm and result_checksum:
                writer.elem(f"Checksum{algorithm}", result_checksum).elem(
                    "ChecksumType", meta.get("checksum_type")
                )
            writer.close("CompleteMultipartUploadResult")
            return writer.to_bytes()

        task = asyncio.ensure_future(assemble())
        done, _ = await asyncio.wait({task}, timeout=KEEPALIVE_SECONDS)
        if done:
            info = task.result()
            return self.version_header(xml_response(success_xml(info)), bucket, info)

        async def body() -> AsyncIterator[bytes]:
            # Headers are already out: keep the connection alive, report failures in the body.
            first = True
            while not task.done():
                await asyncio.wait({task}, timeout=KEEPALIVE_SECONDS)
                if not task.done():
                    yield b'<?xml version="1.0" encoding="UTF-8"?>\n' if first else b" "
                    first = False
            try:
                text = success_xml(task.result())
            except S3Error as exc:
                text = error_xml(
                    exc.code, exc.message, secrets.token_hex(8).upper(), "", exc.details
                )
            except Exception:
                LOGGER.exception("multipart assembly failed", extra={"bucket": bucket.name})
                text = error_xml(
                    "InternalError",
                    "We encountered an internal error. Please try again.",
                    secrets.token_hex(8).upper(),
                    "",
                    {},
                )
            yield text.split(b"\n", 1)[1] if not first else text

        return Response(200, [("Content-Type", "application/xml")], body())


class BodySource:
    """Decodes the request body (plain or aws-chunked) and verifies digests afterwards."""

    def __init__(self, api: S3Api, request: Request, principal: Principal) -> None:
        self.api = api
        self.request = request
        self.principal = principal
        headers = request.headers
        verified = principal.verified
        self.payload_hash = (
            verified.payload_hash
            if verified
            else (headers.get("x-amz-content-sha256") or s3sigv4.UNSIGNED_PAYLOAD)
        )
        self.streaming = self.payload_hash in s3sigv4.STREAMING_MODES
        encodings = [
            item.strip().lower() for item in (headers.get("content-encoding") or "").split(",")
        ]
        if (
            self.streaming
            and "aws-chunked" not in encodings
            and headers.get("x-amz-decoded-content-length") is None
        ):
            raise S3Error(
                "InvalidArgument", "Streaming payloads need Content-Encoding: aws-chunked."
            )
        content_length = _parse_int(headers.get("content-length"), "Content-Length")
        decoded = _parse_int(
            headers.get("x-amz-decoded-content-length"), "x-amz-decoded-content-length"
        )
        if self.streaming:
            self.declared_length = decoded
        else:
            self.declared_length = content_length
            if (
                content_length is None
                and request.method == "PUT"
                and "chunked" not in (headers.get("transfer-encoding") or "").lower()
            ):
                raise S3Error("MissingContentLength")
        self.content_length = content_length
        self.sha256_expected = (
            self.payload_hash if len(self.payload_hash) == 64 and not self.streaming else None
        )
        self.algorithms: set[str] = set()
        self.expected: dict[str, str] = {}
        self.trailer_names: set[str] = set()
        for name, value in headers.items():
            algorithm = checksums.ALGORITHM_FOR_HEADER.get(name)
            if algorithm:
                self.algorithms.add(algorithm)
                self.expected[algorithm] = value.strip()
        trailer_header = headers.get("x-amz-trailer")
        if trailer_header:
            if not self.streaming or self.payload_hash == s3sigv4.STREAMING_SIGNED:
                raise S3Error("InvalidRequest", "x-amz-trailer requires a trailer streaming mode.")
            for name in trailer_header.split(","):
                name = name.strip().lower()
                if not name:
                    continue
                algorithm = checksums.ALGORITHM_FOR_HEADER.get(name)
                if algorithm is None:
                    raise S3Error("InvalidRequest", f"Unsupported trailer {name}.")
                self.trailer_names.add(name)
                self.algorithms.add(algorithm)
        sdk_algorithm = checksums.normalize_algorithm(headers.get("x-amz-sdk-checksum-algorithm"))
        if sdk_algorithm:
            self.algorithms.add(sdk_algorithm)
        if len(self.algorithms) > 1:
            raise S3Error(
                "InvalidRequest",
                "Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed.",  # noqa: E501
            )
        md5_header = headers.get("content-md5")
        self.content_md5: bytes | None = None
        if md5_header is not None:
            try:
                raw = base64.b64decode(md5_header.strip(), validate=True)
            except (ValueError, binascii.Error) as exc:
                raise S3Error("InvalidDigest") from exc
            if len(raw) != 16:
                raise S3Error("InvalidDigest")
            self.content_md5 = raw
        for algorithm, value in self.expected.items():
            if checksums.decode_value(algorithm, value) is None:
                raise S3Error(
                    "InvalidRequest",
                    f"Value for x-amz-checksum-{algorithm.lower()} header is invalid.",
                )
        self.decoder: AwsChunkedDecoder | None = None
        self.received = 0

    async def iterate(self) -> AsyncIterator[bytes]:
        raw = self.request.raw_body(self.api.settings.idle_body_timeout_seconds)
        if self.streaming:
            self.decoder = AwsChunkedDecoder(
                raw,
                mode=self.payload_hash,
                verified=self.principal.verified,
                declared_trailers=self.trailer_names,
                decoded_length=self.declared_length,
                max_chunk_bytes=self.api.settings.max_chunk_bytes,
            )
            async for piece in self.decoder:
                self.received += len(piece)
                yield piece
            return
        async for piece in raw:
            self.received += len(piece)
            if self.content_length is not None and self.received > self.content_length:
                raise S3Error("IncompleteBody", "More data than Content-Length.")
            yield piece
        if self.content_length is not None and self.received != self.content_length:
            raise S3Error("IncompleteBody")

    def verify(self, hasher: BodyHasher, *, body_md5: bytes) -> None:
        if self.content_md5 is not None and not hmac.compare_digest(self.content_md5, body_md5):
            raise S3Error(
                "BadDigest", "The Content-MD5 you specified did not match what we received."
            )
        if self.sha256_expected is not None:
            assert hasher.sha256 is not None
            if hasher.sha256.hexdigest() != self.sha256_expected:
                raise S3Error(
                    "XAmzContentSHA256Mismatch",
                    ClientComputedContentSHA256=self.sha256_expected,
                    S3ComputedContentSHA256=hasher.sha256.hexdigest(),
                )
        computed = hasher.checksum_values()
        expected = dict(self.expected)
        if self.decoder is not None:
            for name, value in self.decoder.trailers.items():
                algorithm = checksums.ALGORITHM_FOR_HEADER[name]
                if checksums.decode_value(algorithm, value) is None:
                    raise S3Error("InvalidRequest", f"Value for {name} trailing header is invalid.")
                expected[algorithm] = value
        for algorithm, value in expected.items():
            if computed.get(algorithm) != value:
                raise S3Error(
                    "BadDigest",
                    f"The {algorithm} you specified did not match the calculated checksum.",
                )


def now_iso() -> str:
    return datetime.now(UTC).isoformat()
