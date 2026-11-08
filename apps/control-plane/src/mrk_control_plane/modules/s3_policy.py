"""S3 naming rules, policy templates and IAM-subset policy validation (docs/30 §1.2, §2.5)."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

POLICY_VERSION = "2012-10-17"
POLICY_TEMPLATES = ("read_only", "read_write", "admin", "backup_client", "custom")
PANEL_IDENTITY = "__mrk_panel__"
MAX_IDENTITY_POLICY_BYTES = 6144
MAX_STATEMENTS = 50
MAX_KEY_BYTES = 1024

_BUCKET_CHARS = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
RESERVED_BUCKETS = frozenset({"mrk", "admin", "api", "www", "_"})
_IDENTITY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+=-]{0,63}$")

# Actions the engine understands (docs/30 §1.3 / §2.5). Wildcards are accepted too.
KNOWN_ACTIONS = frozenset(
    {
        "s3:*",
        "s3:ListAllMyBuckets",
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "s3:ListBucketMultipartUploads",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:GetBucketCORS",
        "s3:PutBucketCORS",
        "s3:GetBucketVersioning",
        "s3:PutBucketVersioning",
        "s3:GetLifecycleConfiguration",
        "s3:PutLifecycleConfiguration",
        "s3:GetBucketTagging",
        "s3:PutBucketTagging",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:GetObjectTagging",
        "s3:PutObjectTagging",
        "s3:DeleteObjectTagging",
        "s3:GetObjectAttributes",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts",
    }
)
CONDITION_OPERATORS = frozenset(
    {
        "StringEquals",
        "StringNotEquals",
        "StringEqualsIgnoreCase",
        "StringNotEqualsIgnoreCase",
        "StringLike",
        "StringNotLike",
        "IpAddress",
        "NotIpAddress",
        "Bool",
        "DateEquals",
        "DateNotEquals",
        "DateLessThan",
        "DateLessThanEquals",
        "DateGreaterThan",
        "DateGreaterThanEquals",
        "NumericEquals",
        "NumericNotEquals",
        "NumericLessThan",
        "NumericLessThanEquals",
        "NumericGreaterThan",
        "NumericGreaterThanEquals",
        "Null",
    }
)
CONDITION_KEYS = frozenset(
    {
        "aws:SourceIp",
        "aws:SecureTransport",
        "aws:CurrentTime",
        "aws:username",
        "aws:UserAgent",
        "aws:Referer",
        "s3:prefix",
        "s3:delimiter",
        "s3:max-keys",
        "s3:x-amz-acl",
        "s3:signatureAge",
        "s3:authType",
        "s3:x-amz-content-sha256",
    }
)
_CONDITION_KEY_PREFIXES = ("s3:ExistingObjectTag/", "s3:RequestObjectTag/")
_ARN = re.compile(r"^arn:(aws|mrk):s3:::(?P<bucket>[^/]+)(?P<key>/.*)?$")
_ACTION = re.compile(r"^s3:[A-Za-z*?]+$")


class PolicyError(ValueError):
    """Raised with a precise, user-facing message; mapped to ``invalid_policy``."""


def bucket_name_error(name: object) -> str | None:
    """Return why ``name`` is not a valid bucket name, or None if it is valid."""
    if not isinstance(name, str):
        return "bucket name must be a string"
    if not 3 <= len(name) <= 63:
        return "bucket name must be 3 to 63 characters"
    if not _BUCKET_CHARS.fullmatch(name):
        return (
            "bucket name may contain only lowercase letters, digits, dots and hyphens, "
            "and must start and end with a letter or digit"
        )
    if ".." in name:
        return "bucket name must not contain two adjacent dots"
    try:
        ipaddress.IPv4Address(name)
    except ValueError:
        pass
    else:
        return "bucket name must not be formatted as an IP address"
    if name.startswith(("xn--", "sthree-")):
        return "bucket name must not start with 'xn--' or 'sthree-'"
    if name.endswith(("-s3alias", "--ol-s3", ".mrap", "--x-s3")):
        return "bucket name must not end with a reserved AWS suffix"
    if name in RESERVED_BUCKETS:
        return f"bucket name '{name}' is reserved"
    return None


def identity_name_error(name: object) -> str | None:
    if not isinstance(name, str) or not _IDENTITY_NAME.fullmatch(name):
        return (
            "identity name must be 1 to 64 characters: letters, digits and . _ @ + = -, "
            "starting with a letter or digit"
        )
    return None


def object_key_error(key: object, *, folder: bool = False) -> str | None:
    if not isinstance(key, str) or not key:
        return "object key must be a non-empty string"
    if len(key.encode("utf-8")) > MAX_KEY_BYTES:
        return "object key must be at most 1024 bytes"
    if any(ord(char) < 32 or ord(char) == 127 for char in key):
        return "object key must not contain control characters"
    if key.startswith("/"):
        return "object key must not start with '/'"
    segments = key.split("/")
    if folder:
        if not key.endswith("/"):
            return "folder prefix must end with '/'"
        segments = segments[:-1]
    if any(segment in {".", ".."} for segment in segments):
        return "object key must not contain '.' or '..' segments"
    if any(segment == "" for segment in segments):
        return "object key must not contain empty segments ('//')"
    if key.startswith(".mrk/"):
        return "object keys under '.mrk/' are reserved"
    return None


def _arn(bucket: str, key: str | None = None) -> str:
    return f"arn:aws:s3:::{bucket}" + ("" if key is None else f"/{key}")


_READ_OBJECT = ["s3:GetObject", "s3:GetObjectTagging", "s3:GetObjectAttributes"]
_READ_BUCKET = ["s3:ListBucket", "s3:GetBucketLocation"]
_WRITE_OBJECT = [
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:PutObjectTagging",
    "s3:DeleteObjectTagging",
    "s3:AbortMultipartUpload",
    "s3:ListMultipartUploadParts",
]


def template_policy(template: str, buckets: list[str]) -> dict[str, Any]:
    """Build the effective policy document for a built-in template."""
    if template == "admin" and not buckets:
        return {
            "Version": POLICY_VERSION,
            "Statement": [{"Sid": "Admin", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        }
    if not buckets:
        # Every bucket was removed: the identity keeps existing but may do nothing.
        return {"Version": POLICY_VERSION, "Statement": []}
    bucket_arns = [_arn(bucket) for bucket in buckets]
    object_arns = [_arn(bucket, "*") for bucket in buckets]
    statements: list[dict[str, Any]]
    if template == "read_only":
        statements = [
            {"Sid": "List", "Effect": "Allow", "Action": _READ_BUCKET, "Resource": bucket_arns},
            {"Sid": "Read", "Effect": "Allow", "Action": _READ_OBJECT, "Resource": object_arns},
        ]
    elif template == "read_write":
        statements = [
            {
                "Sid": "List",
                "Effect": "Allow",
                "Action": [*_READ_BUCKET, "s3:ListBucketMultipartUploads"],
                "Resource": bucket_arns,
            },
            {
                "Sid": "ReadWrite",
                "Effect": "Allow",
                "Action": [*_READ_OBJECT, *_WRITE_OBJECT],
                "Resource": object_arns,
            },
        ]
    elif template == "backup_client":
        # Get/Put/List/Delete on the chosen buckets (+ multipart), plus ListAllMyBuckets
        # because Dokploy/rclone "test connection" lists buckets first.
        statements = [
            {"Sid": "Buckets", "Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
            {
                "Sid": "List",
                "Effect": "Allow",
                "Action": [*_READ_BUCKET, "s3:ListBucketMultipartUploads"],
                "Resource": bucket_arns,
            },
            {
                "Sid": "Objects",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:AbortMultipartUpload",
                    "s3:ListMultipartUploadParts",
                ],
                "Resource": object_arns,
            },
        ]
    elif template == "admin":
        statements = [
            {
                "Sid": "Admin",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": [*bucket_arns, *object_arns],
            },
        ]
    else:
        raise PolicyError(f"unknown policy template: {template}")
    return {"Version": POLICY_VERSION, "Statement": statements}


def panel_policy() -> dict[str, Any]:
    return {
        "Version": POLICY_VERSION,
        "Statement": [{"Sid": "Panel", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
    }


def _strings(value: object, field: str, where: str) -> list[str]:
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not items:
        raise PolicyError(f"{where}: {field} must be a string or a non-empty list of strings")
    if not all(isinstance(item, str) and item for item in items):
        raise PolicyError(f"{where}: {field} must contain only non-empty strings")
    if len(items) > 100:
        raise PolicyError(f"{where}: {field} may list at most 100 entries")
    return items


def _check_action(action: str, where: str) -> None:
    if action == "*":
        return
    if not _ACTION.fullmatch(action):
        raise PolicyError(f"{where}: action '{action}' must look like 's3:GetObject'")
    if "*" not in action and "?" not in action and action not in KNOWN_ACTIONS:
        raise PolicyError(f"{where}: action '{action}' is not supported")


def _check_resource(resource: str, where: str) -> None:
    if resource == "*":
        return
    match = _ARN.fullmatch(resource)
    if match is None:
        raise PolicyError(
            f"{where}: resource '{resource}' must be '*' or 'arn:aws:s3:::bucket[/key]'"
        )
    bucket = match.group("bucket")
    if "*" not in bucket and "?" not in bucket and bucket_name_error(bucket) is not None:
        raise PolicyError(f"{where}: resource '{resource}' names an invalid bucket")


def _check_condition(condition: object, where: str) -> None:
    if not isinstance(condition, dict) or not condition:
        raise PolicyError(f"{where}: Condition must be a non-empty object")
    for operator, clauses in condition.items():
        base = operator
        for prefix in ("ForAnyValue:", "ForAllValues:"):
            if base.startswith(prefix):
                base = base[len(prefix) :]
        if base.endswith("IfExists"):
            base = base[: -len("IfExists")]
        if base not in CONDITION_OPERATORS:
            raise PolicyError(f"{where}: condition operator '{operator}' is not supported")
        if not isinstance(clauses, dict) or not clauses:
            raise PolicyError(f"{where}: condition '{operator}' must map keys to values")
        for key, value in clauses.items():
            if key not in CONDITION_KEYS and not key.startswith(_CONDITION_KEY_PREFIXES):
                raise PolicyError(f"{where}: condition key '{key}' is not supported")
            values = value if isinstance(value, list) else [value]
            if not values or not all(isinstance(item, (str, bool, int, float)) for item in values):
                raise PolicyError(f"{where}: condition values for '{key}' must be scalars")


def validate_policy(document: object) -> dict[str, Any]:
    """Validate an identity policy against our IAM subset; returns the normalized document."""
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError:
            raise PolicyError("policy must be valid JSON") from None
    if not isinstance(document, dict):
        raise PolicyError("policy must be a JSON object")
    unknown = set(document) - {"Version", "Id", "Statement"}
    if unknown:
        raise PolicyError(f"policy has unsupported element(s): {', '.join(sorted(unknown))}")
    if document.get("Version") not in {"2012-10-17", "2008-10-17"}:
        raise PolicyError("policy Version must be '2012-10-17'")
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise PolicyError("policy Statement must be a non-empty list")
    if len(statements) > MAX_STATEMENTS:
        raise PolicyError(f"policy may contain at most {MAX_STATEMENTS} statements")
    allowed = {"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition"}
    for index, statement in enumerate(statements):
        where = f"Statement[{index}]"
        if not isinstance(statement, dict):
            raise PolicyError(f"{where} must be an object")
        if "Principal" in statement or "NotPrincipal" in statement:
            raise PolicyError(f"{where}: Principal is not allowed in an identity policy")
        extra = set(statement) - allowed
        if extra:
            raise PolicyError(f"{where}: unsupported element(s) {', '.join(sorted(extra))}")
        sid = statement.get("Sid")
        if sid is not None and (not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9]*", sid)):
            raise PolicyError(f"{where}: Sid must be alphanumeric")
        if statement.get("Effect") not in {"Allow", "Deny"}:
            raise PolicyError(f"{where}: Effect must be 'Allow' or 'Deny'")
        if ("Action" in statement) == ("NotAction" in statement):
            raise PolicyError(f"{where}: exactly one of Action or NotAction is required")
        if ("Resource" in statement) == ("NotResource" in statement):
            raise PolicyError(f"{where}: exactly one of Resource or NotResource is required")
        field = "Action" if "Action" in statement else "NotAction"
        for action in _strings(statement[field], field, where):
            _check_action(action, where)
        field = "Resource" if "Resource" in statement else "NotResource"
        for resource in _strings(statement[field], field, where):
            _check_resource(resource, where)
        if "Condition" in statement:
            _check_condition(statement["Condition"], where)
    normalized = {"Version": document["Version"], "Statement": statements}
    if "Id" in document:
        normalized["Id"] = document["Id"]
    if len(json.dumps(normalized, separators=(",", ":"))) > MAX_IDENTITY_POLICY_BYTES:
        raise PolicyError(f"policy must be at most {MAX_IDENTITY_POLICY_BYTES} bytes")
    return normalized
