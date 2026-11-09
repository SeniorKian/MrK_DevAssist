"""Bucket lifecycle rules and the expiration worker (docs/30 §1.10).

Supported: ``Rule{ID, Status, Filter{Prefix|Tag|ObjectSizeGreaterThan|
ObjectSizeLessThan|And{...}}}`` (or the legacy rule-level ``Prefix``) with
``Expiration{Days|Date|ExpiredObjectDeleteMarker}``,
``NoncurrentVersionExpiration{NoncurrentDays, NewerNoncurrentVersions}`` and
``AbortIncompleteMultipartUpload{DaysAfterInitiation}``. ``Transition`` and
``NoncurrentVersionTransition`` are rejected with ``NotImplemented`` (single tier).

The configuration is stored as JSON in the bucket index (``settings.lifecycle``).
The worker scans by prefix, deletes in batches of 1000, and records one summary
per bucket and run (``settings.lifecycle_last_run`` + a log line), never one row
per object. ``dry_run`` gives the panel preview without deleting anything.
Due times are rounded up to the next midnight UTC, like AWS.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

from . import tagging
from .errors import S3Error
from .storage import BaseBucket, ManagedBucket
from .xmlio import XmlWriter, child_text, children, parse_xml

LOGGER = logging.getLogger("mrk.s3.lifecycle")
MAX_RULES = 1000
BATCH = 1000
MAX_PER_RUN = 100_000  # candidates per bucket and run; the next run continues
SAMPLE = 20
DAY_NS = 86400 * 1_000_000_000
SETTING = "lifecycle"
LAST_RUN = "lifecycle_last_run"


# --------------------------------------------------------------------------- parsing


def _positive_int(text: str | None, name: str, *, allow_zero: bool = False) -> int:
    try:
        value = int((text or "").strip())
    except ValueError as exc:
        raise S3Error("MalformedXML", f"'{name}' must be an integer.") from exc
    if value < 0 or (value == 0 and not allow_zero):
        raise S3Error("InvalidArgument", f"'{name}' must be a positive integer.", ArgumentName=name)
    return value


def _parse_date(text: str) -> int:
    value = text.strip()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise S3Error("MalformedXML", "'Date' must be an ISO 8601 date.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    parsed = parsed.astimezone(UTC)
    if (parsed.hour, parsed.minute, parsed.second, parsed.microsecond) != (0, 0, 0, 0):
        raise S3Error(
            "InvalidArgument",
            "'Date' must be at midnight GMT",
            ArgumentName="Date",
        )
    return int(parsed.timestamp()) * 1_000_000_000


def _parse_filter(rule: Any, out: dict[str, Any]) -> None:
    legacy = child_text(rule, "Prefix")
    filters = list(children(rule, "Filter"))
    if legacy is not None and filters:
        raise S3Error("MalformedXML", "A rule cannot have both Prefix and Filter.")
    if legacy is not None:
        out["prefix"] = legacy
        out["legacy_prefix"] = True
        return
    if len(filters) > 1:
        raise S3Error("MalformedXML")
    if not filters:
        return
    node = filters[0]
    ands = list(children(node, "And"))
    direct = [child.tag for child in node]
    if ands:
        if len(direct) != 1:
            raise S3Error("MalformedXML", "Filter.And cannot be combined with other filters.")
        node = ands[0]
    elif len(direct) > 1:
        raise S3Error("MalformedXML", "Use Filter.And to combine filters.")
    prefix = child_text(node, "Prefix")
    if prefix is not None:
        out["prefix"] = prefix
    tags: tagging.Tags = []
    for tag in children(node, "Tag"):
        key, value = child_text(tag, "Key"), child_text(tag, "Value")
        if key is None or value is None:
            raise S3Error("MalformedXML")
        tags.append((key, value))
    if tags:
        out["tags"] = [list(pair) for pair in tagging.validate(tags, tagging.MAX_OBJECT_TAGS)]
    greater = child_text(node, "ObjectSizeGreaterThan")
    if greater is not None:
        out["size_gt"] = _positive_int(greater, "ObjectSizeGreaterThan", allow_zero=True)
    less = child_text(node, "ObjectSizeLessThan")
    if less is not None:
        out["size_lt"] = _positive_int(less, "ObjectSizeLessThan")
    if "size_gt" in out and "size_lt" in out and out["size_gt"] >= out["size_lt"]:
        raise S3Error(
            "InvalidArgument",
            "ObjectSizeGreaterThan must be less than ObjectSizeLessThan",
            ArgumentName="ObjectSizeGreaterThan",
        )
    out["filter"] = True


def parse_config(body: bytes) -> list[dict[str, Any]]:
    root = parse_xml(body)
    if root.tag != "LifecycleConfiguration":
        raise S3Error("MalformedXML")
    nodes = list(children(root, "Rule"))
    if not nodes or len(nodes) > MAX_RULES:
        raise S3Error("MalformedXML")
    rules: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, node in enumerate(nodes, start=1):
        if list(children(node, "Transition")) or list(
            children(node, "NoncurrentVersionTransition")
        ):
            raise S3Error(
                "NotImplemented",
                "Storage class transitions are not supported (single storage tier).",
            )
        rule: dict[str, Any] = {}
        rule_id = child_text(node, "ID")
        if rule_id is None or not rule_id.strip():
            rule_id = f"rule-{index}"
        if len(rule_id) > 255:
            raise S3Error(
                "InvalidArgument",
                "ID length should not exceed allowed limit of 255",
                ArgumentName="ID",
            )  # noqa: E501
        if rule_id in ids:
            raise S3Error("InvalidArgument", "Rule ID must be unique.", ArgumentName="ID")
        ids.add(rule_id)
        rule["id"] = rule_id
        status = (child_text(node, "Status") or "").strip()
        if status not in {"Enabled", "Disabled"}:
            raise S3Error("MalformedXML", "Status must be Enabled or Disabled.")
        rule["status"] = status
        _parse_filter(node, rule)
        expiration = list(children(node, "Expiration"))
        if len(expiration) > 1:
            raise S3Error("MalformedXML")
        if expiration:
            exp = expiration[0]
            days, date = child_text(exp, "Days"), child_text(exp, "Date")
            marker = child_text(exp, "ExpiredObjectDeleteMarker")
            given = [item for item in (days, date, marker) if item is not None]
            if len(given) != 1:
                raise S3Error(
                    "MalformedXML",
                    "Expiration needs exactly one of Days, Date or ExpiredObjectDeleteMarker.",
                )
            if days is not None:
                rule["expiration_days"] = _positive_int(days, "Days")
            elif date is not None:
                rule["expiration_date_ns"] = _parse_date(date)
            else:
                flag = (marker or "").strip().lower()
                if flag not in {"true", "false"}:
                    raise S3Error("MalformedXML")
                if flag == "true" and rule.get("tags"):
                    raise S3Error(
                        "InvalidRequest",
                        "ExpiredObjectDeleteMarker cannot be specified with object tags.",
                    )
                rule["expired_object_delete_marker"] = flag == "true"
        noncurrent = list(children(node, "NoncurrentVersionExpiration"))
        if len(noncurrent) > 1:
            raise S3Error("MalformedXML")
        if noncurrent:
            rule["noncurrent_days"] = _positive_int(
                child_text(noncurrent[0], "NoncurrentDays"), "NoncurrentDays"
            )
            newer = child_text(noncurrent[0], "NewerNoncurrentVersions")
            if newer is not None:
                rule["newer_noncurrent"] = _positive_int(newer, "NewerNoncurrentVersions")
        abort = list(children(node, "AbortIncompleteMultipartUpload"))
        if len(abort) > 1:
            raise S3Error("MalformedXML")
        if abort:
            if rule.get("tags") or "size_gt" in rule or "size_lt" in rule:
                raise S3Error(
                    "InvalidRequest",
                    "AbortIncompleteMultipartUpload cannot be specified with tags or object size filters.",  # noqa: E501
                )
            rule["abort_days"] = _positive_int(
                child_text(abort[0], "DaysAfterInitiation"), "DaysAfterInitiation"
            )
        if not any(
            name in rule
            for name in (
                "expiration_days",
                "expiration_date_ns",
                "expired_object_delete_marker",
                "noncurrent_days",
                "abort_days",
            )
        ):
            raise S3Error("InvalidRequest", "At least one action needs to be specified in a rule.")
        rules.append(rule)
    return rules


def to_xml(rules: list[dict[str, Any]]) -> bytes:
    writer = XmlWriter().open("LifecycleConfiguration", xmlns=True)
    for rule in rules:
        writer.open("Rule").elem("ID", rule["id"])
        if rule.get("legacy_prefix"):
            writer.elem("Prefix", rule.get("prefix", ""))
        elif rule.get("filter"):
            parts = (
                (1 if "prefix" in rule else 0)
                + len(rule.get("tags") or [])
                + (1 if "size_gt" in rule else 0)
                + (1 if "size_lt" in rule else 0)
            )
            writer.open("Filter")
            if parts > 1:
                writer.open("And")
            if "prefix" in rule:
                writer.elem("Prefix", rule["prefix"])
            for key, value in rule.get("tags") or []:
                writer.open("Tag").elem("Key", key).elem("Value", value).close("Tag")
            if "size_gt" in rule:
                writer.elem("ObjectSizeGreaterThan", rule["size_gt"])
            if "size_lt" in rule:
                writer.elem("ObjectSizeLessThan", rule["size_lt"])
            if parts > 1:
                writer.close("And")
            writer.close("Filter")
        else:
            writer.empty("Filter")
        writer.elem("Status", rule["status"])
        if "expiration_days" in rule:
            writer.open("Expiration").elem("Days", rule["expiration_days"]).close("Expiration")
        elif "expiration_date_ns" in rule:
            date = datetime.fromtimestamp(rule["expiration_date_ns"] / 1e9, UTC)
            writer.open("Expiration").elem("Date", date.strftime("%Y-%m-%dT%H:%M:%S.000Z")).close(
                "Expiration"
            )
        elif "expired_object_delete_marker" in rule:
            writer.open("Expiration").elem(
                "ExpiredObjectDeleteMarker", rule["expired_object_delete_marker"]
            ).close("Expiration")
        if "noncurrent_days" in rule:
            writer.open("NoncurrentVersionExpiration").elem(
                "NoncurrentDays", rule["noncurrent_days"]
            )
            if "newer_noncurrent" in rule:
                writer.elem("NewerNoncurrentVersions", rule["newer_noncurrent"])
            writer.close("NoncurrentVersionExpiration")
        if "abort_days" in rule:
            writer.open("AbortIncompleteMultipartUpload").elem(
                "DaysAfterInitiation", rule["abort_days"]
            ).close("AbortIncompleteMultipartUpload")
        writer.close("Rule")
    return writer.close("LifecycleConfiguration").to_bytes()


def load_rules(bucket: BaseBucket) -> list[dict[str, Any]] | None:
    raw = bucket.index.get_setting(SETTING)
    if not raw:
        return None
    try:
        rules = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return rules if isinstance(rules, list) else None


def save_rules(bucket: BaseBucket, rules: list[dict[str, Any]] | None) -> None:
    bucket.index.set_setting(
        SETTING, None if rules is None else json.dumps(rules, separators=(",", ":"))
    )


# --------------------------------------------------------------------------- evaluation


def due_ns(start_ns: int, days: int) -> int:
    """``start + days``, rounded up to the next midnight UTC (AWS semantics)."""
    target = start_ns + days * DAY_NS
    remainder = target % DAY_NS
    return target if remainder == 0 else target - remainder + DAY_NS


def _object_matches(rule: dict[str, Any], key: str, size: int, stored_tags: str | None) -> bool:
    if not key.startswith(rule.get("prefix", "")):
        return False
    if "size_gt" in rule and not size > rule["size_gt"]:
        return False
    if "size_lt" in rule and not size < rule["size_lt"]:
        return False
    required = [(item[0], item[1]) for item in rule.get("tags") or []]
    return tagging.matches(stored_tags, required)


class _Summary:
    def __init__(self, dry_run: bool) -> None:
        self.dry_run = dry_run
        self.counts = {"objects": 0, "bytes": 0, "versions": 0, "version_bytes": 0}
        self.counts.update(markers=0, uploads=0)
        self.rules: dict[str, int] = {}
        self.sample: list[dict[str, Any]] = []
        self.truncated = False

    def add(self, rule_id: str, kind: str, key: str, size: int = 0) -> None:
        self.rules[rule_id] = self.rules.get(rule_id, 0) + 1
        if kind == "object":
            self.counts["objects"] += 1
            self.counts["bytes"] += size
        elif kind == "version":
            self.counts["versions"] += 1
            self.counts["version_bytes"] += size
        elif kind == "marker":
            self.counts["markers"] += 1
        else:
            self.counts["uploads"] += 1
        if len(self.sample) < SAMPLE:
            self.sample.append({"key": key, "kind": kind, "size": size, "rule": rule_id})

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.counts,
            "dry_run": self.dry_run,
            "rules": self.rules,
            "sample": self.sample,
            "truncated": self.truncated,
        }


def _scan_current(
    bucket: BaseBucket, rule: dict[str, Any], now_ns: int
) -> list[tuple[str, int, int]]:
    """Current objects whose Expiration is due: ``(key, size, last_modified_ns)``."""
    prefix = rule.get("prefix", "")
    found: list[tuple[str, int, int]] = []
    if "expiration_days" not in rule and "expiration_date_ns" not in rule:
        return found
    if "expiration_date_ns" in rule and now_ns < rule["expiration_date_ns"]:
        return found
    needs_meta = bool(rule.get("tags"))
    if isinstance(bucket, ManagedBucket):
        records = (
            (record.key, record.size, record.last_modified_ns, record.meta.get("tagging"))
            for record in bucket.index.iter_objects(prefix=prefix)
        )
    else:
        source = bucket.iter_entries(prefix, "")

        def linked() -> Any:
            for entry in source("", False):
                kind, _parts, stat = entry.payload
                if kind != "file" or stat is None:
                    continue
                tags = None
                if needs_meta:
                    tags = bucket.entry_info(entry).meta.get("tagging")  # type: ignore[attr-defined]
                yield entry.key, stat.st_size, stat.st_mtime_ns, tags

        records = linked()
    for key, size, modified, tags in records:
        if "expiration_days" in rule and now_ns < due_ns(modified, rule["expiration_days"]):
            continue
        if not _object_matches(rule, key, size, tags):
            continue
        found.append((key, size, modified))
        if len(found) >= MAX_PER_RUN:
            break
    return found


def _version_actions(
    bucket: ManagedBucket, rule: dict[str, Any], now_ns: int
) -> list[tuple[str, str, int, str]]:
    """Noncurrent versions / expired delete markers due: ``(key, version, size, kind)``."""
    wants_noncurrent = "noncurrent_days" in rule
    wants_markers = bool(rule.get("expired_object_delete_marker")) or (
        # AWS also cleans up lone delete markers when noncurrent versions expire.
        wants_noncurrent and not rule.get("tags")
    )
    found: list[tuple[str, str, int, str]] = []
    if not (wants_noncurrent or wants_markers) or not bucket.index.has_versions():
        return found
    prefix = rule.get("prefix", "")
    required = [(item[0], item[1]) for item in rule.get("tags") or []]
    start, inclusive = "", False
    while len(found) < MAX_PER_RUN:
        keys = bucket.index.version_keys(start, inclusive=inclusive, prefix=prefix, limit=500)
        if not keys:
            break
        for key in keys:
            versions = bucket.index.versions_for(key)
            if wants_noncurrent:
                kept = 0
                for version in versions:
                    if version.is_latest:
                        continue
                    if not version.delete_marker:
                        kept += 1
                        if kept <= rule.get("newer_noncurrent", 0):
                            continue
                    if now_ns < due_ns(version.noncurrent_ns, rule["noncurrent_days"]):
                        continue
                    if not version.delete_marker and not _object_matches(
                        rule, key, version.size, version.meta.get("tagging")
                    ):
                        continue
                    if version.delete_marker and required:
                        continue
                    found.append(
                        (
                            key,
                            version.version_id,
                            version.size,
                            "marker" if version.delete_marker else "version",
                        )
                    )
            if wants_markers:
                remaining = [
                    version
                    for version in versions
                    if not any(item[0] == key and item[1] == version.version_id for item in found)
                ]
                if len(remaining) == 1 and remaining[0].delete_marker and remaining[0].is_latest:
                    found.append((key, remaining[0].version_id, 0, "marker"))
        start, inclusive = keys[-1], False
    return found[:MAX_PER_RUN]


def run_bucket(bucket: BaseBucket, now_ns: int | None = None, *, dry_run: bool) -> dict[str, Any]:
    """Apply (or, with ``dry_run``, only count) every enabled rule of one bucket."""
    now_ns = time.time_ns() if now_ns is None else now_ns
    summary = _Summary(dry_run)
    rules = [rule for rule in load_rules(bucket) or [] if rule.get("status") == "Enabled"]
    writable = not bucket.config.read_only
    for rule in rules:
        rule_id = rule["id"]
        expired = _scan_current(bucket, rule, now_ns)
        if len(expired) >= MAX_PER_RUN:
            summary.truncated = True
        for offset in range(0, len(expired), BATCH):
            for key, size, modified in expired[offset : offset + BATCH]:
                if not dry_run:
                    if not writable:
                        continue
                    current = bucket.head(key)
                    # Skip objects rewritten since the scan.
                    if current is None or current.last_modified_ns != modified:
                        continue
                    try:
                        bucket.delete(key)
                    except S3Error:
                        continue
                summary.add(rule_id, "object", key, size)
        if isinstance(bucket, ManagedBucket):
            versions = _version_actions(bucket, rule, now_ns)
            for offset in range(0, len(versions), BATCH):
                for key, version_id, size, kind in versions[offset : offset + BATCH]:
                    if not dry_run and bucket.index.delete_version(key, version_id) is None:
                        continue
                    summary.add(rule_id, kind, key, size)
        if "abort_days" in rule:
            prefix = rule.get("prefix", "")
            for upload in bucket.index.list_uploads():
                if not upload.key.startswith(prefix):
                    continue
                if now_ns < due_ns(upload.initiated_ns, rule["abort_days"]):
                    continue
                if not dry_run:
                    if not writable:
                        continue
                    bucket.abort_upload(upload.upload_id)
                summary.add(rule_id, "upload", upload.key)
    result = summary.as_dict()
    result["at"] = now_ns // 1_000_000_000
    result["bucket"] = bucket.name
    if not dry_run and rules:
        bucket.index.set_setting(LAST_RUN, json.dumps(result, separators=(",", ":")))
        LOGGER.info(
            "lifecycle run",
            extra={
                "bucket": bucket.name,
                "objects": result["objects"],
                "bytes": result["bytes"],
                "versions": result["versions"],
                "markers": result["markers"],
                "uploads": result["uploads"],
            },
        )
    return result


def last_run(bucket: BaseBucket) -> dict[str, Any] | None:
    raw = bucket.index.get_setting(LAST_RUN)
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None
