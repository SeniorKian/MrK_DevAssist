"""Checks for credentials a person chooses (panel, registry, Git and S3 users).

Every place that creates or resets a human-facing credential accepts an
optional value typed by the operator and falls back to a generated one. A typed
value goes through the panel's password policy (``auth.password_policy``) plus
the limits of the backend that will store it. Errors are ``FieldError`` so the
caller can return the usual ``{code, message, fields}`` shape; the value itself
is never part of an error, a log line or an audit entry.
"""

from __future__ import annotations

from .auth import FieldError, password_policy

SECRET_KEY_MIN = 8
SECRET_KEY_MAX = 128


def _has_control(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def check_password(
    value: object,
    field: str = "password",
    *,
    min_length: int | None = None,
    max_length: int = 256,
    max_bytes: int | None = None,
) -> str:
    """Return ``value`` when it satisfies the panel policy and the backend limits.

    ``min_length`` raises the policy minimum (e.g. Gitea needs 8), ``max_bytes``
    caps the UTF-8 size (bcrypt reads only 72 bytes).
    """
    if not isinstance(value, str):
        raise FieldError("weak_password", "password must be text", field, "invalid")
    policy = password_policy()
    minimum = max(int(policy["min_length"]), min_length or 0)  # type: ignore[call-overload]
    params = {"min_length": minimum, "max_length": max_length}
    if len(value) < minimum:
        raise FieldError("weak_password", f"password must be at least {minimum} characters",
                         field, "too_short", params=params)
    if len(value) > max_length or (max_bytes is not None
                                   and len(value.encode("utf-8")) > max_bytes):
        limit = max_length if max_bytes is None else min(max_length, max_bytes)
        raise FieldError("weak_password", f"password must be at most {limit} characters",
                         field, "too_long", params={**params, "max_length": limit})
    if _has_control(value):
        raise FieldError("weak_password", "password must not contain control characters",
                         field, "invalid_characters")
    if policy["require_letters"] and not any(char.isalpha() for char in value):
        raise FieldError("weak_password", "password must contain at least one letter",
                         field, "missing_letter")
    if policy["require_digits"] and not any(char.isdigit() for char in value):
        raise FieldError("weak_password", "password must contain at least one digit",
                         field, "missing_digit")
    return value


def check_secret_key(value: object, field: str = "secret_access_key") -> str:
    """An S3 secret key: 8-128 printable ASCII characters, no spaces, letters and digits.

    SigV4 only feeds the secret into HMAC ("AWS4" + secret), so any byte string
    works for the engine; printable ASCII keeps it safe in config files, env
    vars and shell snippets the panel shows.
    """
    params = {"min_length": SECRET_KEY_MIN, "max_length": SECRET_KEY_MAX}
    if not isinstance(value, str):
        raise FieldError("invalid_secret_key", "secret key must be text", field, "invalid")
    if len(value) < SECRET_KEY_MIN:
        raise FieldError("invalid_secret_key",
                         f"secret key must be at least {SECRET_KEY_MIN} characters",
                         field, "too_short", params=params)
    if len(value) > SECRET_KEY_MAX:
        raise FieldError("invalid_secret_key",
                         f"secret key must be at most {SECRET_KEY_MAX} characters",
                         field, "too_long", params=params)
    if not all(33 <= ord(char) <= 126 for char in value):
        raise FieldError("invalid_secret_key",
                         "secret key must be printable ASCII without spaces",
                         field, "invalid_characters")
    policy = password_policy()
    if policy["require_letters"] and not any(char.isalpha() for char in value):
        raise FieldError("invalid_secret_key", "secret key must contain at least one letter",
                         field, "missing_letter")
    if policy["require_digits"] and not any(char.isdigit() for char in value):
        raise FieldError("invalid_secret_key", "secret key must contain at least one digit",
                         field, "missing_digit")
    return value


def error_extra(exc: FieldError) -> dict[str, object]:
    """Keyword arguments for a module error built from a ``FieldError``."""
    return {"fields": exc.fields}
