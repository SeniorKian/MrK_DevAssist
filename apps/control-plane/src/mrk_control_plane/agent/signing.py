"""HMAC request signing shared by the agent (verify) and the control plane (sign)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import OrderedDict

KEY_BYTES = 32
HEADER_TIMESTAMP = "X-MRK-Timestamp"
HEADER_NONCE = "X-MRK-Nonce"
HEADER_SIGNATURE = "X-MRK-Signature"
MAX_CLOCK_SKEW_SECONDS = 30
NONCE_TTL_SECONDS = 60
NONCE_CACHE_SIZE = 10_000
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_SIGNATURE_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_PATTERN = re.compile(r"^[0-9]{1,12}$")


class SignatureError(Exception):
    """Raised when a request fails authentication. ``reason`` is a short code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def encode_key(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")


def decode_key(value: str) -> bytes:
    """Decode a base64url (padding optional) key; it must be exactly 32 bytes."""
    text = value.strip()
    if not text or not re.fullmatch(r"[A-Za-z0-9_-]+=*", text):
        raise ValueError("agent key must be base64url")
    try:
        key = base64.urlsafe_b64decode(text.rstrip("=") + "=" * (-len(text.rstrip("=")) % 4))
    except (ValueError, TypeError) as exc:
        raise ValueError("agent key must be base64url") from exc
    if len(key) != KEY_BYTES:
        raise ValueError("agent key must decode to 32 bytes")
    return key


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def canonical_message(
    method: str, path_with_query: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path_with_query}\n{timestamp}\n{nonce}\n{body_hash}".encode()


def compute_signature(
    key: bytes, method: str, path_with_query: str, timestamp: str, nonce: str, body: bytes
) -> str:
    message = canonical_message(method, path_with_query, timestamp, nonce, body)
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def sign_headers(
    key: bytes,
    method: str,
    path_with_query: str,
    body: bytes = b"",
    *,
    now: float | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    timestamp = str(int(time.time() if now is None else now))
    nonce = nonce or secrets.token_urlsafe(18)
    return {
        HEADER_TIMESTAMP: timestamp,
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: compute_signature(key, method, path_with_query, timestamp, nonce, body),
    }


class NonceCache:
    """Remembers nonces for NONCE_TTL_SECONDS; bounded so it cannot grow without limit."""

    def __init__(self, ttl_seconds: int = NONCE_TTL_SECONDS, max_size: int = NONCE_CACHE_SIZE):
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._items: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        while self._items:
            nonce, expires_at = next(iter(self._items.items()))
            if expires_at > now:
                break
            self._items.pop(nonce, None)

    def add(self, nonce: str, now: float | None = None) -> None:
        """Record a nonce; raise SignatureError if it was seen or the cache is full."""
        current = time.monotonic() if now is None else now
        with self._lock:
            self._prune(current)
            if nonce in self._items:
                raise SignatureError("replay")
            if len(self._items) >= self.max_size:
                # Evicting a live nonce would reopen a replay window, so refuse instead.
                raise SignatureError("nonce_cache_full")
            self._items[nonce] = current + self.ttl_seconds

    def __len__(self) -> int:
        return len(self._items)


class RequestVerifier:
    def __init__(
        self,
        key: bytes,
        *,
        max_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
        nonce_cache: NonceCache | None = None,
    ) -> None:
        if len(key) != KEY_BYTES:
            raise ValueError("agent key must be 32 bytes")
        self._key = key
        self.max_skew_seconds = max_skew_seconds
        self.nonces = nonce_cache or NonceCache()

    def verify(
        self,
        method: str,
        path_with_query: str,
        headers: dict[str, str],
        body: bytes,
        *,
        now: float | None = None,
    ) -> None:
        lowered = {key.lower(): value for key, value in headers.items()}
        timestamp = lowered.get(HEADER_TIMESTAMP.lower(), "")
        nonce = lowered.get(HEADER_NONCE.lower(), "")
        signature = lowered.get(HEADER_SIGNATURE.lower(), "")
        if not (timestamp and nonce and signature):
            raise SignatureError("missing_headers")
        if (
            not _TIMESTAMP_PATTERN.fullmatch(timestamp)
            or not _NONCE_PATTERN.fullmatch(nonce)
            or not _SIGNATURE_PATTERN.fullmatch(signature)
        ):
            raise SignatureError("malformed_headers")
        current = time.time() if now is None else now
        if abs(current - int(timestamp)) > self.max_skew_seconds:
            raise SignatureError("clock_skew")
        expected = compute_signature(self._key, method, path_with_query, timestamp, nonce, body)
        if not hmac.compare_digest(expected, signature):
            raise SignatureError("bad_signature")
        # Only authenticated requests may occupy the nonce cache.
        self.nonces.add(nonce)
