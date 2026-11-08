"""AWS Signature Version 4 for S3: canonicalization, signer, presigner, verifier.

Clean-room implementation of the public AWS SigV4 algorithm, shared by both sides:

* the native S3 engine (``mrk_control_plane.s3engine``) verifies requests with
  :func:`verify_request` and aws-chunked chunk/trailer signatures with
  :func:`chunk_signature` / :func:`trailer_signature`;
* the control plane (and any internal client) signs requests to the engine with
  :func:`sign_request` and builds share links with :func:`presign_url`.

Canonicalization follows the S3 rules exactly:

* the canonical URI is derived from the raw (still percent-encoded) request path,
  one segment at a time: decode once, then encode with the RFC 3986 unreserved
  set. ``/`` separators are kept, ``//``, ``.`` and ``..`` are *not* normalized,
  and a literal ``%2F`` inside a segment stays ``%2F`` (no double decoding);
* the canonical query sorts by encoded name, then encoded value; parameters
  without ``=`` become ``name=``; ``+`` in a raw query is a literal plus
  (``%2B``), never a space;
* header names are lower-cased, values trimmed with inner whitespace runs
  collapsed to one space, duplicates joined with ``,`` in received order.

Example (client side)::

    from mrk_control_plane import s3sigv4
    headers = s3sigv4.sign_request(
        "GET", "http://127.0.0.1:9000/backups/db.sql.gz", {},
        access_key_id=akid, secret_access_key=secret, region="us-east-1",
    )
    url = s3sigv4.presign_url(
        "GET", "https://s3.example.com/backups/db.sql.gz",
        access_key_id=akid, secret_access_key=secret, region="us-east-1", expires=3600,
    )

No SigV2 support, by design (docs/30 §2.5).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import unquote_to_bytes, urlsplit

ALGORITHM = "AWS4-HMAC-SHA256"
SERVICE = "s3"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"
STREAMING_SIGNED = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
STREAMING_SIGNED_TRAILER = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
STREAMING_UNSIGNED_TRAILER = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
STREAMING_MODES = frozenset(
    {STREAMING_SIGNED, STREAMING_SIGNED_TRAILER, STREAMING_UNSIGNED_TRAILER}
)
MAX_PRESIGN_EXPIRES = 604800
AMZ_DATE_FORMAT = "%Y%m%dT%H%M%SZ"

_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_WS = re.compile(r"\s+")
_ENCODE_TABLE = [chr(b) if b in _UNRESERVED else f"%{b:02X}" for b in range(256)]


class SigV4Error(Exception):
    """Authentication failure with the S3 error code and HTTP status to return."""

    def __init__(self, code: str, message: str, status: int = 403, **details: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details


@dataclass(frozen=True, slots=True)
class Credential:
    access_key_id: str
    date: str
    region: str
    service: str

    @property
    def scope(self) -> str:
        return f"{self.date}/{self.region}/{self.service}/aws4_request"


@dataclass(slots=True)
class VerifiedRequest:
    """Result of a successful SigV4 verification."""

    access_key_id: str
    credential: Credential
    amz_date: str
    signing_key: bytes = field(repr=False)
    signature: str = field(repr=False)
    payload_hash: str
    auth_type: str  # "header" | "query"
    signed_headers: tuple[str, ...]
    request_time: datetime


# --------------------------------------------------------------------------- encoding


def uri_encode(value: str | bytes, *, encode_slash: bool = True) -> str:
    """Percent-encode with the RFC 3986 unreserved set (upper-case hex), as AWS does."""
    data = value.encode("utf-8") if isinstance(value, str) else value
    if encode_slash:
        return "".join(_ENCODE_TABLE[b] for b in data)
    return "".join("/" if b == 0x2F else _ENCODE_TABLE[b] for b in data)


def canonical_uri(raw_path: str) -> str:
    """Canonical URI for S3 from the raw request path (no normalization)."""
    if not raw_path:
        return "/"
    return "/".join(uri_encode(unquote_to_bytes(segment)) for segment in raw_path.split("/"))


def parse_query(raw_query: str) -> list[tuple[str, str]]:
    """Split a raw query into decoded ``(name, value)`` pairs; ``+`` stays literal."""
    pairs: list[tuple[str, str]] = []
    if not raw_query:
        return pairs
    for item in raw_query.split("&"):
        if not item:
            continue
        name, _, value = item.partition("=")
        pairs.append(
            (
                unquote_to_bytes(name).decode("utf-8", "surrogateescape"),
                unquote_to_bytes(value).decode("utf-8", "surrogateescape"),
            )
        )
    return pairs


def _encode_param(value: str) -> str:
    return uri_encode(value.encode("utf-8", "surrogateescape"))


def canonical_query_from_params(
    params: Iterable[tuple[str, str]], *, exclude: Iterable[str] = ()
) -> str:
    excluded = set(exclude)
    encoded = sorted(
        (_encode_param(name), _encode_param(value))
        for name, value in params
        if name not in excluded
    )
    return "&".join(f"{name}={value}" for name, value in encoded)


def canonical_query(raw_query: str, *, exclude: Iterable[str] = ()) -> str:
    return canonical_query_from_params(parse_query(raw_query), exclude=exclude)


def normalize_header_value(value: str) -> str:
    return _WS.sub(" ", value.strip())


def header_map(headers: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Lower-case names, duplicates joined with ``,`` in received order (values normalized)."""
    merged: dict[str, list[str]] = {}
    for name, value in headers:
        merged.setdefault(name.lower(), []).append(normalize_header_value(value))
    return {name: ",".join(values) for name, values in merged.items()}


def canonical_headers(headers: Mapping[str, str], signed_headers: Iterable[str]) -> str:
    return "".join(f"{name}:{headers.get(name, '')}\n" for name in signed_headers)


def canonical_request(
    method: str,
    uri: str,
    query: str,
    headers: Mapping[str, str],
    signed_headers: Iterable[str],
    payload_hash: str,
) -> str:
    signed = list(signed_headers)
    return "\n".join(
        [
            method.upper(),
            uri,
            query,
            canonical_headers(headers, signed),
            ";".join(signed),
            payload_hash,
        ]
    )


def string_to_sign(amz_date: str, scope: str, canonical: str) -> str:
    digest = hashlib.sha256(canonical.encode("utf-8", "surrogateescape")).hexdigest()
    return f"{ALGORITHM}\n{amz_date}\n{scope}\n{digest}"


# --------------------------------------------------------------------------- keys


_KEY_CACHE: OrderedDict[tuple[str, str, str, str], bytes] = OrderedDict()
_KEY_CACHE_LOCK = threading.Lock()
_KEY_CACHE_SIZE = 256


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def derive_signing_key(secret: str, date: str, region: str, service: str = SERVICE) -> bytes:
    """``HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")``."""
    cache_key = (hashlib.sha256(secret.encode("utf-8")).hexdigest(), date, region, service)
    with _KEY_CACHE_LOCK:
        cached = _KEY_CACHE.get(cache_key)
        if cached is not None:
            _KEY_CACHE.move_to_end(cache_key)
            return cached
    key = _hmac(("AWS4" + secret).encode("utf-8"), date)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    with _KEY_CACHE_LOCK:
        _KEY_CACHE[cache_key] = key
        while len(_KEY_CACHE) > _KEY_CACHE_SIZE:
            _KEY_CACHE.popitem(last=False)
    return key


def signature(signing_key: bytes, message: str) -> str:
    return hmac.new(
        signing_key, message.encode("utf-8", "surrogateescape"), hashlib.sha256
    ).hexdigest()


def chunk_string_to_sign(
    amz_date: str, scope: str, previous_signature: str, chunk_sha256: str
) -> str:
    return "\n".join(
        [
            "AWS4-HMAC-SHA256-PAYLOAD",
            amz_date,
            scope,
            previous_signature,
            EMPTY_SHA256,
            chunk_sha256,
        ]
    )


def chunk_signature(
    signing_key: bytes, amz_date: str, scope: str, previous_signature: str, chunk_sha256: str
) -> str:
    return signature(
        signing_key, chunk_string_to_sign(amz_date, scope, previous_signature, chunk_sha256)
    )


def canonical_trailer(trailers: Iterable[tuple[str, str]]) -> bytes:
    return "".join(f"{name.lower()}:{value.strip()}\n" for name, value in trailers).encode("utf-8")


def trailer_signature(
    signing_key: bytes,
    amz_date: str,
    scope: str,
    previous_signature: str,
    trailers: Iterable[tuple[str, str]],
) -> str:
    digest = hashlib.sha256(canonical_trailer(trailers)).hexdigest()
    message = "\n".join(["AWS4-HMAC-SHA256-TRAILER", amz_date, scope, previous_signature, digest])
    return signature(signing_key, message)


# --------------------------------------------------------------------------- dates


def format_amz_date(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(AMZ_DATE_FORMAT)


def parse_amz_date(value: str) -> datetime:
    return datetime.strptime(value, AMZ_DATE_FORMAT).replace(tzinfo=UTC)


def _now(now: datetime | None) -> datetime:
    return (now or datetime.now(UTC)).astimezone(UTC)


# --------------------------------------------------------------------------- client side


def _host_for(parts) -> str:
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port and not (
        (parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    return host


def sign_request(
    method: str,
    url: str,
    headers: Mapping[str, str] | None = None,
    *,
    access_key_id: str,
    secret_access_key: str,
    region: str,
    payload_hash: str = UNSIGNED_PAYLOAD,
    now: datetime | None = None,
    service: str = SERVICE,
) -> dict[str, str]:
    """Return ``headers`` plus host, x-amz-date, x-amz-content-sha256 and authorization.

    ``url`` must carry an already percent-encoded path (as it goes on the wire).
    All headers passed in are signed.
    """
    parts = urlsplit(url)
    moment = _now(now)
    amz_date = format_amz_date(moment)
    result = {name.lower(): value for name, value in (headers or {}).items()}
    result.setdefault("host", _host_for(parts))
    result["x-amz-date"] = amz_date
    result["x-amz-content-sha256"] = payload_hash
    result.pop("authorization", None)
    credential = Credential(access_key_id, amz_date[:8], region, service)
    normalized = {name: normalize_header_value(value) for name, value in result.items()}
    signed = sorted(normalized)
    canonical = canonical_request(
        method,
        canonical_uri(parts.path or "/"),
        canonical_query(parts.query),
        normalized,
        signed,
        payload_hash,
    )
    key = derive_signing_key(secret_access_key, credential.date, region, service)
    sig = signature(key, string_to_sign(amz_date, credential.scope, canonical))
    result["authorization"] = (
        f"{ALGORITHM} Credential={access_key_id}/{credential.scope}, "
        f"SignedHeaders={';'.join(signed)}, Signature={sig}"
    )
    return result


def presign_url(
    method: str,
    url: str,
    *,
    access_key_id: str,
    secret_access_key: str,
    region: str,
    expires: int = 3600,
    now: datetime | None = None,
    extra_params: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    service: str = SERVICE,
) -> str:
    """Build a query-signed (presigned) URL. Extra params (e.g. ``x-mrk-share``) are signed too."""
    if not 1 <= int(expires) <= MAX_PRESIGN_EXPIRES:
        raise ValueError("expires must be between 1 and 604800 seconds")
    parts = urlsplit(url)
    moment = _now(now)
    amz_date = format_amz_date(moment)
    credential = Credential(access_key_id, amz_date[:8], region, service)
    signed_headers = {"host": _host_for(parts)}
    for name, value in (headers or {}).items():
        signed_headers[name.lower()] = normalize_header_value(value)
    signed = sorted(signed_headers)
    params = parse_query(parts.query)
    params.extend((extra_params or {}).items())
    params.extend(
        [
            ("X-Amz-Algorithm", ALGORITHM),
            ("X-Amz-Credential", f"{access_key_id}/{credential.scope}"),
            ("X-Amz-Date", amz_date),
            ("X-Amz-Expires", str(int(expires))),
            ("X-Amz-SignedHeaders", ";".join(signed)),
        ]
    )
    query = canonical_query_from_params(params)
    canonical = canonical_request(
        method, canonical_uri(parts.path or "/"), query, signed_headers, signed, UNSIGNED_PAYLOAD
    )
    key = derive_signing_key(secret_access_key, credential.date, region, service)
    sig = signature(key, string_to_sign(amz_date, credential.scope, canonical))
    return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}?{query}&X-Amz-Signature={sig}"


class ChunkedPayloadSigner:
    """Client-side encoder for ``STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]`` bodies."""

    def __init__(self, signing_key: bytes, amz_date: str, scope: str, seed_signature: str) -> None:
        self.signing_key = signing_key
        self.amz_date = amz_date
        self.scope = scope
        self.previous = seed_signature

    def chunk(self, data: bytes) -> bytes:
        sig = chunk_signature(
            self.signing_key,
            self.amz_date,
            self.scope,
            self.previous,
            hashlib.sha256(data).hexdigest(),
        )
        self.previous = sig
        return f"{len(data):x};chunk-signature={sig}\r\n".encode("ascii") + data + b"\r\n"

    def final(self, trailers: list[tuple[str, str]] | None = None) -> bytes:
        last = self.chunk(b"")
        if trailers is None:
            return last
        # The final chunk line is followed by the trailer instead of an empty line.
        body = last[:-2]
        body += canonical_trailer(trailers).replace(b"\n", b"\r\n")
        sig = trailer_signature(
            self.signing_key, self.amz_date, self.scope, self.previous, trailers
        )
        return body + f"x-amz-trailer-signature:{sig}\r\n\r\n".encode("ascii")


def parse_authorization_header(header_value: str) -> tuple[Credential, tuple[str, ...], str]:
    algorithm, _, rest = header_value.strip().partition(" ")
    if algorithm != ALGORITHM:
        raise SigV4Error("InvalidRequest", "Please use AWS4-HMAC-SHA256.", 400)
    fields: dict[str, str] = {}
    for item in rest.split(","):
        name, sep, value = item.strip().partition("=")
        if not sep:
            raise SigV4Error(
                "AuthorizationHeaderMalformed", "The authorization header is malformed.", 400
            )
        fields[name.strip()] = value.strip()
    try:
        credential = parse_credential(fields["Credential"])
        signed = tuple(fields["SignedHeaders"].split(";"))
        sig = fields["Signature"]
    except KeyError as exc:
        raise SigV4Error(
            "AuthorizationHeaderMalformed", "The authorization header is malformed.", 400
        ) from exc
    return credential, signed, sig


def parse_credential(value: str) -> Credential:
    parts = value.split("/")
    if len(parts) != 5 or parts[4] != "aws4_request" or not parts[0]:
        raise SigV4Error(
            "AuthorizationHeaderMalformed",
            "The authorization header is malformed; the Credential is mal-formed.",
            400,
        )
    if not re.fullmatch(r"\d{8}", parts[1]):
        raise SigV4Error(
            "AuthorizationHeaderMalformed",
            "The authorization header is malformed; incorrect date format.",
            400,
        )
    return Credential(parts[0], parts[1], parts[2], parts[3])


# --------------------------------------------------------------------------- verifier

SecretLookup = Callable[[str], str | None]


def detect_auth(raw_query: str, headers: Mapping[str, str]) -> str:
    """Return ``header``, ``query``, ``anonymous``; raise for SigV2 or unknown schemes."""
    authorization = headers.get("authorization", "")
    if authorization:
        if authorization.startswith(ALGORITHM + " "):
            return "header"
        if authorization.startswith("AWS "):
            raise SigV4Error("InvalidRequest", "Please use AWS4-HMAC-SHA256.", 400)
        if authorization.startswith("AWS4-ECDSA-P256-SHA256"):
            raise SigV4Error("NotImplemented", "SigV4a is not implemented.", 501)
        raise SigV4Error("InvalidArgument", "Unsupported Authorization Type", 400)
    names = {name for name, _ in parse_query(raw_query)}
    if "X-Amz-Algorithm" in names or "X-Amz-Signature" in names or "X-Amz-Credential" in names:
        return "query"
    if "Signature" in names and "AWSAccessKeyId" in names:
        raise SigV4Error("InvalidRequest", "Please use AWS4-HMAC-SHA256.", 400)
    return "anonymous"


def _check_region(credential: Credential, region: str | None) -> None:
    if credential.service != SERVICE:
        raise SigV4Error(
            "AuthorizationHeaderMalformed",
            f"The authorization header is malformed; incorrect service '{credential.service}'.",
            400,
        )
    if region is not None and credential.region != region:
        raise SigV4Error(
            "AuthorizationHeaderMalformed",
            f"The authorization header is malformed; the region '{credential.region}' is wrong; "
            f"expecting '{region}'",
            400,
            Region=region,
        )


def _check_unsigned_amz_headers(headers: Mapping[str, str], signed: Iterable[str]) -> None:
    signed_set = set(signed)
    for name in headers:
        if name.startswith("x-amz-") and name not in signed_set:
            raise SigV4Error(
                "AccessDenied",
                f"There were headers present in the request which were not signed: {name}",
            )


def _secret(secret_lookup: SecretLookup, access_key_id: str) -> str:
    secret = secret_lookup(access_key_id)
    if not secret:
        raise SigV4Error(
            "InvalidAccessKeyId",
            "The AWS Access Key Id you provided does not exist in our records.",
            403,
            AWSAccessKeyId=access_key_id,
        )
    return secret


def _uri_candidates(raw_path: str) -> list[str]:
    primary = canonical_uri(raw_path)
    # Some clients sign the path exactly as sent (e.g. "!" left unescaped). The raw
    # path decodes to the same key we route on, so accepting it is not a bypass.
    if raw_path and raw_path != primary:
        return [primary, raw_path]
    return [primary]


def _signature_mismatch(debug: bool, string_to_sign_value: str, canonical: str) -> SigV4Error:
    details = {"StringToSign": string_to_sign_value, "CanonicalRequest": canonical} if debug else {}
    return SigV4Error(
        "SignatureDoesNotMatch",
        "The request signature we calculated does not match the signature you provided. "
        "Check your key and signing method.",
        403,
        **details,
    )


def verify_request(
    method: str,
    raw_path: str,
    raw_query: str,
    headers: Iterable[tuple[str, str]],
    secret_lookup: SecretLookup,
    *,
    now: datetime | None = None,
    max_skew_seconds: int = 900,
    region: str | None = None,
    require_content_sha256: bool = True,
    debug: bool = False,
) -> VerifiedRequest | None:
    """Verify header or presigned SigV4 auth. ``None`` means an anonymous request.

    ``region=None`` accepts any region in the credential scope (the signature is
    computed with the region the client stated). ``secret_lookup`` maps an access
    key id to its secret, or ``None`` for unknown/disabled keys.
    """
    header_list = list(headers)
    hmap = header_map(header_list)
    mode = detect_auth(raw_query, hmap)
    if mode == "anonymous":
        return None
    current = _now(now)
    if mode == "header":
        return _verify_header(
            method,
            raw_path,
            raw_query,
            hmap,
            secret_lookup,
            current,
            max_skew_seconds,
            region,
            require_content_sha256,
            debug,
        )
    return _verify_query(
        method, raw_path, raw_query, hmap, secret_lookup, current, max_skew_seconds, region, debug
    )


def _verify_header(
    method: str,
    raw_path: str,
    raw_query: str,
    hmap: dict[str, str],
    secret_lookup: SecretLookup,
    current: datetime,
    max_skew_seconds: int,
    region: str | None,
    require_content_sha256: bool,
    debug: bool,
) -> VerifiedRequest:
    credential, signed, provided = parse_authorization_header(hmap["authorization"])
    _check_region(credential, region)
    if "host" not in signed:
        raise SigV4Error("AccessDenied", "Host header is not signed.")
    if len(set(signed)) != len(signed) or any(name != name.lower() for name in signed):
        raise SigV4Error(
            "AuthorizationHeaderMalformed", "SignedHeaders must be lower-case and unique.", 400
        )
    if "authorization" in signed:
        raise SigV4Error(
            "AuthorizationHeaderMalformed", "Authorization header cannot be signed.", 400
        )
    _check_unsigned_amz_headers(hmap, signed)
    amz_date_value = hmap.get("x-amz-date")
    if amz_date_value:
        try:
            request_time = parse_amz_date(amz_date_value)
        except ValueError as exc:
            raise SigV4Error(
                "AccessDenied", "AWS authentication requires a valid Date or x-amz-date header"
            ) from exc
        amz_date = amz_date_value
    elif hmap.get("date"):
        if "date" not in signed:
            raise SigV4Error("AccessDenied", "Date header is not signed.")
        try:
            request_time = parsedate_to_datetime(hmap["date"]).astimezone(UTC)
        except (TypeError, ValueError) as exc:
            raise SigV4Error(
                "AccessDenied", "AWS authentication requires a valid Date or x-amz-date header"
            ) from exc
        amz_date = format_amz_date(request_time)
    else:
        raise SigV4Error(
            "AccessDenied", "AWS authentication requires a valid Date or x-amz-date header"
        )
    _check_skew(request_time, current, max_skew_seconds)
    if credential.date != amz_date[:8]:
        raise SigV4Error(
            "SignatureDoesNotMatch",
            "The credential scope date does not match the request date.",
            403,
        )
    payload_hash = hmap.get("x-amz-content-sha256")
    if payload_hash is None:
        if require_content_sha256:
            raise SigV4Error(
                "InvalidRequest",
                "Missing required header for this request: x-amz-content-sha256",
                400,
            )
        payload_hash = UNSIGNED_PAYLOAD
    elif payload_hash not in STREAMING_MODES and payload_hash != UNSIGNED_PAYLOAD:
        if payload_hash.startswith("STREAMING-"):
            raise SigV4Error(
                "NotImplemented", "This streaming payload mode is not implemented.", 501
            )
        if not _HEX64.match(payload_hash):
            raise SigV4Error(
                "InvalidArgument",
                "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-* or a SHA-256 digest",
                400,
            )
    secret = _secret(secret_lookup, credential.access_key_id)
    key = derive_signing_key(secret, credential.date, credential.region, credential.service)
    query = canonical_query(raw_query)
    canonical = ""
    to_sign = ""
    for uri in _uri_candidates(raw_path):
        canonical = canonical_request(method, uri, query, hmap, signed, payload_hash)
        to_sign = string_to_sign(amz_date, credential.scope, canonical)
        expected = signature(key, to_sign)
        if hmac.compare_digest(expected, provided.lower()):
            return VerifiedRequest(
                access_key_id=credential.access_key_id,
                credential=credential,
                amz_date=amz_date,
                signing_key=key,
                signature=expected,
                payload_hash=payload_hash,
                auth_type="header",
                signed_headers=signed,
                request_time=request_time,
            )
    raise _signature_mismatch(debug, to_sign, canonical)


def _check_skew(request_time: datetime, current: datetime, max_skew_seconds: int) -> None:
    if abs((current - request_time).total_seconds()) > max_skew_seconds:
        raise SigV4Error(
            "RequestTimeTooSkewed",
            "The difference between the request time and the current time is too large.",
            403,
            RequestTime=format_amz_date(request_time),
            ServerTime=format_amz_date(current),
            MaxAllowedSkewMilliseconds=str(max_skew_seconds * 1000),
        )


def _verify_query(
    method: str,
    raw_path: str,
    raw_query: str,
    hmap: dict[str, str],
    secret_lookup: SecretLookup,
    current: datetime,
    max_skew_seconds: int,
    region: str | None,
    debug: bool,
) -> VerifiedRequest:
    params = parse_query(raw_query)
    values: dict[str, str] = {}
    for name, value in params:
        if name.startswith("X-Amz-"):
            if name in values:
                raise SigV4Error(
                    "AuthorizationQueryParametersError", f"Duplicate query parameter {name}", 400
                )
            values[name] = value
    required = (
        "X-Amz-Algorithm",
        "X-Amz-Credential",
        "X-Amz-Date",
        "X-Amz-Expires",
        "X-Amz-SignedHeaders",
        "X-Amz-Signature",
    )
    missing = [name for name in required if not values.get(name)]
    if missing:
        raise SigV4Error(
            "AuthorizationQueryParametersError",
            "Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, "
            "X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.",
            400,
        )
    if values["X-Amz-Algorithm"] != ALGORITHM:
        raise SigV4Error(
            "AuthorizationQueryParametersError",
            'X-Amz-Algorithm only supports "AWS4-HMAC-SHA256"',
            400,
        )
    try:
        credential = parse_credential(values["X-Amz-Credential"])
    except SigV4Error as exc:
        raise SigV4Error("AuthorizationQueryParametersError", exc.message, 400) from exc
    _check_region(credential, region)
    try:
        expires = int(values["X-Amz-Expires"])
    except ValueError as exc:
        raise SigV4Error(
            "AuthorizationQueryParametersError", "X-Amz-Expires should be a number", 400
        ) from exc
    if expires < 1:
        raise SigV4Error(
            "AuthorizationQueryParametersError", "X-Amz-Expires must be non-negative", 400
        )
    if expires > MAX_PRESIGN_EXPIRES:
        raise SigV4Error(
            "AuthorizationQueryParametersError",
            "X-Amz-Expires must be less than a week (in seconds) that is 604800",
            400,
        )
    amz_date = values["X-Amz-Date"]
    try:
        request_time = parse_amz_date(amz_date)
    except ValueError as exc:
        raise SigV4Error(
            "AuthorizationQueryParametersError",
            "X-Amz-Date must be in the ISO8601 Long Format",
            400,
        ) from exc
    if credential.date != amz_date[:8]:
        raise SigV4Error(
            "SignatureDoesNotMatch", "The credential scope date does not match X-Amz-Date.", 403
        )
    if (request_time - current).total_seconds() > max_skew_seconds:
        raise SigV4Error("AccessDenied", "Request is not valid yet")
    if current > request_time + timedelta(seconds=expires):
        raise SigV4Error(
            "AccessDenied",
            "Request has expired",
            403,
            X_Amz_Expires=str(expires),
            Expires=format_amz_date(request_time + timedelta(seconds=expires)),
            ServerTime=format_amz_date(current),
        )
    signed = tuple(values["X-Amz-SignedHeaders"].split(";"))
    if "host" not in signed:
        raise SigV4Error("AccessDenied", "Host header is not signed.")
    _check_unsigned_amz_headers(hmap, signed)
    payload_hash = hmap.get("x-amz-content-sha256", UNSIGNED_PAYLOAD)
    if payload_hash != UNSIGNED_PAYLOAD and not _HEX64.match(payload_hash):
        raise SigV4Error(
            "InvalidArgument", "Streaming payloads are not supported with presigned URLs", 400
        )
    secret = _secret(secret_lookup, credential.access_key_id)
    key = derive_signing_key(secret, credential.date, credential.region, credential.service)
    query = canonical_query_from_params(params, exclude=("X-Amz-Signature",))
    provided = values["X-Amz-Signature"].lower()
    canonical = ""
    to_sign = ""
    for uri in _uri_candidates(raw_path):
        canonical = canonical_request(method, uri, query, hmap, signed, payload_hash)
        to_sign = string_to_sign(amz_date, credential.scope, canonical)
        expected = signature(key, to_sign)
        if hmac.compare_digest(expected, provided):
            return VerifiedRequest(
                access_key_id=credential.access_key_id,
                credential=credential,
                amz_date=amz_date,
                signing_key=key,
                signature=expected,
                payload_hash=payload_hash,
                auth_type="query",
                signed_headers=signed,
                request_time=request_time,
            )
    raise _signature_mismatch(debug, to_sign, canonical)


__all__ = [
    "ALGORITHM",
    "EMPTY_SHA256",
    "STREAMING_MODES",
    "STREAMING_SIGNED",
    "STREAMING_SIGNED_TRAILER",
    "STREAMING_UNSIGNED_TRAILER",
    "UNSIGNED_PAYLOAD",
    "ChunkedPayloadSigner",
    "Credential",
    "SigV4Error",
    "VerifiedRequest",
    "canonical_query",
    "canonical_request",
    "canonical_uri",
    "chunk_signature",
    "derive_signing_key",
    "presign_url",
    "sign_request",
    "string_to_sign",
    "trailer_signature",
    "uri_encode",
    "verify_request",
]
