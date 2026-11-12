"""Two-step sign-in primitives: TOTP (RFC 6238), recovery codes and signed tokens.

Standard library only. TOTP uses HMAC-SHA1, 6 digits and 30 second steps (what
Google Authenticator, Microsoft Authenticator, Aegis, 1Password, ... expect) and
accepts one step of clock drift either way. The caller stores the last accepted
step so a code can never be used twice.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
from urllib.parse import quote, urlencode

TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_DRIFT_STEPS = 1
SECRET_BYTES = 20
RECOVERY_CODE_COUNT = 10
ISSUER = "MrK DevAssist"

_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_CODE = re.compile(r"^\d{6}$")


def new_secret() -> str:
    """A fresh 160-bit secret, base32 without padding (what authenticator apps show)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _secret_bytes(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8), casefold=True)


def time_step(now: float) -> int:
    return int(now // TOTP_PERIOD)


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_secret_bytes(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**TOTP_DIGITS).zfill(TOTP_DIGITS)


def normalize_code(code: str) -> str:
    """Digits only: people paste «123 456» or «123-456»."""
    return "".join(char for char in code if not char.isspace() and char != "-")


def matching_step(secret: str, code: str, now: float, last_step: int = 0) -> int | None:
    """The time step ``code`` belongs to (within the drift window), or None.

    Steps at or before ``last_step`` never match: that is the replay protection.
    Every candidate is compared in constant time.
    """
    candidate = normalize_code(code)
    if not _CODE.fullmatch(candidate):
        return None
    current = time_step(now)
    found: int | None = None
    for step in range(current - TOTP_DRIFT_STEPS, current + TOTP_DRIFT_STEPS + 1):
        if step <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, step), candidate) and found is None:
            found = step
    return found


def otpauth_uri(secret: str, account: str, issuer: str = ISSUER) -> str:
    label = quote(f"{issuer}:{account}", safe="")
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": TOTP_DIGITS,
            "period": TOTP_PERIOD,
        },
        quote_via=quote,
    )
    return f"otpauth://totp/{label}?{query}"


# ----- recovery codes -----------------------------------------------------------------


def new_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Readable one-time codes such as ``k7pq2-x9mrt`` (50 bits each)."""
    codes: list[str] = []
    while len(codes) < count:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        code = f"{raw[:5]}-{raw[5:]}"
        if code not in codes:
            codes.append(code)
    return codes


def normalize_recovery_code(code: str) -> str:
    return "".join(char for char in code.lower() if char.isalnum())


def recovery_hash(user_id: int, code: str) -> str:
    material = f"mrk-recovery:{user_id}:{normalize_recovery_code(code)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# ----- signed tokens (short-lived challenges) -----------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(key: bytes, purpose: str, payload: dict[str, object]) -> str:
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    mac = hmac.new(key, f"{purpose}|{body}".encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64(mac)}"


def unsign(key: bytes, purpose: str, token: str) -> dict[str, object] | None:
    """The payload of a token made by :func:`sign` with the same key and purpose, or None."""
    if not token or len(token) > 4096 or token.count(".") != 1:
        return None
    body, mac = token.split(".", 1)
    try:
        expected = hmac.new(key, f"{purpose}|{body}".encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(mac)):
            return None
        payload = json.loads(_unb64(body))
    except (ValueError, UnicodeError):
        return None
    return payload if isinstance(payload, dict) else None
