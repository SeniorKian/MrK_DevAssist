"""Our own IAM-subset policy evaluator (docs/30 §2.5).

Supported: ``Effect`` Allow/Deny, ``Action``/``NotAction`` (``*``/``?`` wildcards,
case-insensitive), ``Resource``/``NotResource`` (``arn:aws:s3:::bucket``,
``arn:aws:s3:::bucket/key-glob``; ``arn:mrk:s3:::`` is an alias), policy variable
``${aws:username}``, and ``Condition`` operators ``String[Not]Equals[IgnoreCase]``,
``String[Not]Like``, ``Bool``, ``[Not]IpAddress``, ``Numeric*``, ``Null`` (each also
with ``...IfExists``). Explicit Deny wins over Allow; no statement means deny.

An unknown condition operator never grants: an Allow statement with one does not
apply, a Deny statement with one does (fail closed).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

ALLOW = "allow"
DENY = "deny"
IMPLICIT = "implicit"

ARN_PREFIX = "arn:aws:s3:::"
_VARIABLE = re.compile(r"\$\{([^}]+)\}")


@dataclass(slots=True)
class RequestContext:
    username: str = ""
    source_ip: str = ""
    secure_transport: bool = False
    auth_type: str = ""
    user_agent: str = ""
    referer: str = ""
    content_sha256: str = ""
    values: dict[str, str] = field(default_factory=dict)  # s3:prefix, s3:delimiter, s3:max-keys

    def get(self, key: str) -> str | None:
        lowered = key.lower()
        builtins = {
            "aws:username": self.username,
            "aws:sourceip": self.source_ip,
            "aws:securetransport": "true" if self.secure_transport else "false",
            "s3:authtype": self.auth_type,
            "aws:useragent": self.user_agent,
            "aws:referer": self.referer,
            "s3:x-amz-content-sha256": self.content_sha256,
        }
        if lowered in builtins:
            value = builtins[lowered]
            return value if value != "" or lowered == "aws:securetransport" else None
        for name, value in self.values.items():
            if name.lower() == lowered:
                return value
        return None


class PolicyError(ValueError):
    pass


def resource_arn(bucket: str | None, key: str | None = None) -> str:
    if bucket is None:
        return ARN_PREFIX + "*"
    if key is None:
        return ARN_PREFIX + bucket
    return f"{ARN_PREFIX}{bucket}/{key}"


@lru_cache(maxsize=4096)
def _glob(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    regex = "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern)
    return re.compile(rf"\A{regex}\Z", re.IGNORECASE | re.DOTALL if ignore_case else re.DOTALL)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _substitute(pattern: str, ctx: RequestContext) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name == "*":
            return "*"
        if name == "?":
            return "?"
        if name == "$":
            return "$"
        value = ctx.get(name)
        # Unknown variables never match anything.
        return value if value is not None else "\x00unresolved\x00"

    return _VARIABLE.sub(replace, pattern)


def _normalize_resource(pattern: str) -> str:
    if pattern.startswith("arn:mrk:s3:::"):
        return ARN_PREFIX + pattern[len("arn:mrk:s3:::") :]
    return pattern


def _match_any(
    patterns: list[Any], value: str, ignore_case: bool, ctx: RequestContext | None = None
) -> bool:
    for pattern in patterns:
        if not isinstance(pattern, str):
            continue
        text = _substitute(pattern, ctx) if ctx is not None else pattern
        if not ignore_case:
            text = _normalize_resource(text)
        if _glob(text, ignore_case).match(value):
            return True
    return False


def _condition_values(raw: Any) -> list[str]:
    return [str(item).lower() if isinstance(item, bool) else str(item) for item in _as_list(raw)]


def _ip_match(value: str, patterns: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    for pattern in patterns:
        try:
            if address in ipaddress.ip_network(pattern, strict=False):
                return True
        except ValueError:
            continue
    return False


def _numeric(op: str, value: str, patterns: list[str]) -> bool:
    try:
        number = float(value)
    except ValueError:
        return False
    for pattern in patterns:
        try:
            other = float(pattern)
        except ValueError:
            continue
        if (
            (op == "NumericEquals" and number == other)
            or (op == "NumericNotEquals" and number != other)
            or (op == "NumericLessThan" and number < other)
            or (op == "NumericLessThanEquals" and number <= other)
            or (op == "NumericGreaterThan" and number > other)
            or (op == "NumericGreaterThanEquals" and number >= other)
        ):
            return True
    return False


_NEGATED = {"StringNotEquals", "StringNotEqualsIgnoreCase", "StringNotLike", "NotIpAddress"}
_KNOWN = {
    "StringEquals",
    "StringNotEquals",
    "StringEqualsIgnoreCase",
    "StringNotEqualsIgnoreCase",
    "StringLike",
    "StringNotLike",
    "Bool",
    "IpAddress",
    "NotIpAddress",
    "NumericEquals",
    "NumericNotEquals",
    "NumericLessThan",
    "NumericLessThanEquals",
    "NumericGreaterThan",
    "NumericGreaterThanEquals",
    "Null",
}


def _evaluate_operator(op: str, key: str, raw: Any, ctx: RequestContext) -> bool | None:
    """True/False for a known operator, None when the operator is unknown."""
    if_exists = op.endswith("IfExists") and op != "IfExists"
    base = op[: -len("IfExists")] if if_exists else op
    if base not in _KNOWN:
        return None
    patterns = [_substitute(item, ctx) for item in _condition_values(raw)]
    value = ctx.get(key)
    if base == "Null":
        want_null = patterns and patterns[0].lower() == "true"
        return (value is None) == bool(want_null)
    if value is None:
        if if_exists:
            return True
        return base in _NEGATED
    if base == "StringEquals":
        return value in patterns
    if base == "StringNotEquals":
        return value not in patterns
    if base == "StringEqualsIgnoreCase":
        return value.lower() in {item.lower() for item in patterns}
    if base == "StringNotEqualsIgnoreCase":
        return value.lower() not in {item.lower() for item in patterns}
    if base == "StringLike":
        return any(_glob(item, False).match(value) for item in patterns)
    if base == "StringNotLike":
        return not any(_glob(item, False).match(value) for item in patterns)
    if base == "Bool":
        return value.lower() in {item.lower() for item in patterns}
    if base == "IpAddress":
        return _ip_match(value, patterns)
    if base == "NotIpAddress":
        return not _ip_match(value, patterns)
    return _numeric(base, value, patterns)


def _conditions_hold(conditions: Any, ctx: RequestContext, effect: str) -> bool:
    if not conditions:
        return True
    if not isinstance(conditions, dict):
        return effect == DENY
    for op, entries in conditions.items():
        if not isinstance(entries, dict):
            return effect == DENY
        for key, raw in entries.items():
            result = _evaluate_operator(str(op), str(key), raw, ctx)
            if result is None:
                return effect == DENY
            if not result:
                return False
    return True


def statements(policy: Any) -> list[dict[str, Any]]:
    if not isinstance(policy, dict):
        return []
    raw = policy.get("Statement")
    return [item for item in _as_list(raw) if isinstance(item, dict)]


def validate_policy(policy: Any) -> None:
    if not isinstance(policy, dict):
        raise PolicyError("policy must be a JSON object")
    items = policy.get("Statement")
    if not isinstance(items, list | dict):
        raise PolicyError("policy needs a Statement")
    for item in _as_list(items):
        if not isinstance(item, dict):
            raise PolicyError("each Statement must be an object")
        if item.get("Effect") not in {"Allow", "Deny"}:
            raise PolicyError("Effect must be Allow or Deny")
        if ("Action" in item) == ("NotAction" in item):
            raise PolicyError("a Statement needs exactly one of Action/NotAction")
        if ("Resource" in item) == ("NotResource" in item):
            raise PolicyError("a Statement needs exactly one of Resource/NotResource")
        for name in ("Action", "NotAction", "Resource", "NotResource"):
            if name in item and not all(isinstance(x, str) for x in _as_list(item[name])):
                raise PolicyError(f"{name} entries must be strings")
        if "Condition" in item and not isinstance(item["Condition"], dict):
            raise PolicyError("Condition must be an object")


def _statement_applies(
    stmt: dict[str, Any], action: str, resource: str, ctx: RequestContext
) -> bool:
    effect = DENY if stmt.get("Effect") == "Deny" else ALLOW
    if "Action" in stmt:
        if not _match_any(_as_list(stmt["Action"]), action, True):
            return False
    elif "NotAction" in stmt:
        if _match_any(_as_list(stmt["NotAction"]), action, True):
            return False
    else:
        return False
    if "Resource" in stmt:
        if not _match_any(_as_list(stmt["Resource"]), resource, False, ctx):
            return False
    elif "NotResource" in stmt:
        if _match_any(_as_list(stmt["NotResource"]), resource, False, ctx):
            return False
    else:
        return False
    return _conditions_hold(stmt.get("Condition"), ctx, effect)


def evaluate(policies: list[Any], action: str, resource: str, ctx: RequestContext) -> str:
    allowed = False
    for policy in policies:
        for stmt in statements(policy):
            if stmt.get("Effect") not in {"Allow", "Deny"}:
                continue
            if _statement_applies(stmt, action, resource, ctx):
                if stmt["Effect"] == "Deny":
                    return DENY
                allowed = True
    return ALLOW if allowed else IMPLICIT
