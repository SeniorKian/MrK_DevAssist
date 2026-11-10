"""Configuration snapshot written by the control plane (docs/31 §2).

``/data/modules/s3/config.json`` is polled by mtime. A snapshot that fails
validation is ignored and the last good one stays active; individual invalid
buckets or identities are dropped with a warning. Without any valid snapshot
the engine answers ``503 ServiceUnavailable``.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..secret_store import SecretStore
from .policy import PolicyError, validate_policy
from .settings import EngineSettings

LOGGER = logging.getLogger("mrk.s3.snapshot")
RESERVED_BUCKETS = frozenset({"mrk", "admin", "api", "www", "_"})
MAX_CONFIG_BYTES = 16 * 1024 * 1024


def validate_bucket_name(name: object) -> bool:
    if not isinstance(name, str) or not 3 <= len(name) <= 63:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if any(ch not in allowed for ch in name):
        return False
    if not (name[0].isalnum() and name[-1].isalnum()):
        return False
    if ".." in name or name.startswith("xn--") or name.endswith(("-s3alias", "--ol-s3")):
        return False
    if name in RESERVED_BUCKETS:
        return False
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return True
    return False


@dataclass(frozen=True, slots=True)
class BucketConfig:
    name: str
    mode: str  # managed | linked
    link_path: Path | None
    link_mode: str  # rw | ro
    public_read: bool
    public_list: bool
    quota_bytes: int | None
    created_at_ns: int
    # docs/43: the bucket's workspace is suspended, so nothing may be written.
    frozen: bool = False

    @property
    def linked(self) -> bool:
        return self.mode == "linked"

    @property
    def read_only(self) -> bool:
        return self.frozen or (self.linked and self.link_mode == "ro")


@dataclass(frozen=True, slots=True)
class QuotaGroup:
    """A «my space» workspace: byte/object limits shared by its buckets (docs/43 §3)."""

    id: str
    buckets: tuple[str, ...]
    max_bytes: int | None
    max_objects: int | None


@dataclass(frozen=True, slots=True)
class AccessKey:
    access_key_id: str
    secret_ref: str
    enabled: bool
    # Pushed by the panel to an engine in its own container (docs/44), which cannot
    # read the panel's SecretStore. None = look the secret up by secret_ref.
    secret: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class Identity:
    id: str
    name: str
    enabled: bool
    system: bool
    policy: dict[str, Any] | None
    keys: tuple[AccessKey, ...]

    @property
    def canonical_id(self) -> str:
        return self.id.replace("-", "").lower().ljust(32, "0")[:64]


@dataclass(frozen=True, slots=True)
class Snapshot:
    enabled: bool
    region: str
    public_endpoint: str
    virtual_host_suffix: str
    max_object_bytes: int
    buckets: dict[str, BucketConfig]
    identities: tuple[Identity, ...]
    keys: dict[str, tuple[Identity, AccessKey]] = field(default_factory=dict)
    generation: int = 0
    # Extra virtual-host suffixes (other S3 domains, docs/35 §4); the primary is above.
    extra_suffixes: tuple[str, ...] = ()
    # docs/43: bucket name -> its workspace quota group; verified bucket domains.
    groups: dict[str, QuotaGroup] = field(default_factory=dict)
    bucket_hosts: dict[str, str] = field(default_factory=dict)


def _created_ns(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0
    number = float(value)
    if number > 1e17:  # already ns
        return int(number)
    if number > 1e12:  # ms
        return int(number * 1_000_000)
    return int(number * 1_000_000_000)


def _within_roots(path: Path, roots: tuple[Path, ...]) -> bool:
    try:
        resolved = Path(os.path.realpath(path))
    except OSError:
        return False
    for root in roots:
        try:
            base = Path(os.path.realpath(root))
        except OSError:
            continue
        if resolved != base and resolved.is_relative_to(base):
            return True
    return False


def parse_snapshot(payload: Any, settings: EngineSettings, generation: int = 0) -> Snapshot:
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("config snapshot must be an object with version 1")
    enabled = payload.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    region = payload.get("region") or "us-east-1"
    if not isinstance(region, str) or not 1 <= len(region) <= 64:
        raise ValueError("region is invalid")
    suffix = payload.get("virtual_host_suffix") or ""
    endpoint = payload.get("public_endpoint") or ""
    if not isinstance(suffix, str) or not isinstance(endpoint, str):
        raise ValueError("virtual_host_suffix/public_endpoint must be strings")
    raw_extra = payload.get("virtual_host_suffixes") or []
    if not isinstance(raw_extra, list) or not all(isinstance(item, str) for item in raw_extra):
        raise ValueError("virtual_host_suffixes must be a list of strings")
    primary_suffix = suffix.strip().lower().strip(".")
    extra = tuple(
        dict.fromkeys(
            item.strip().lower().strip(".")
            for item in raw_extra[:256]
            if item.strip().strip(".") and item.strip().lower().strip(".") != primary_suffix
        )
    )
    max_object = payload.get("max_object_bytes") or 5 * 1024**4
    if isinstance(max_object, bool) or not isinstance(max_object, int) or max_object < 1:
        raise ValueError("max_object_bytes must be a positive integer")
    raw_buckets = payload.get("buckets") or []
    raw_identities = payload.get("identities") or []
    if not isinstance(raw_buckets, list) or not isinstance(raw_identities, list):
        raise ValueError("buckets and identities must be lists")
    buckets: dict[str, BucketConfig] = {}
    for item in raw_buckets:
        bucket = _parse_bucket(item, settings)
        if bucket is None:
            continue
        if bucket.name in buckets:
            raise ValueError(f"duplicate bucket {bucket.name}")
        buckets[bucket.name] = bucket
    identities: list[Identity] = []
    keys: dict[str, tuple[Identity, AccessKey]] = {}
    for item in raw_identities:
        identity = _parse_identity(item)
        if identity is None:
            continue
        identities.append(identity)
        for key in identity.keys:
            if key.access_key_id in keys:
                raise ValueError("duplicate access key id")
            keys[key.access_key_id] = (identity, key)
    return Snapshot(
        enabled=enabled,
        region=region,
        public_endpoint=endpoint.rstrip("/"),
        virtual_host_suffix=suffix.strip().lower().strip("."),
        max_object_bytes=max_object,
        buckets=buckets,
        identities=tuple(identities),
        keys=keys,
        generation=generation,
        extra_suffixes=extra,
        groups=_parse_groups(payload.get("quota_groups"), buckets),
        bucket_hosts=_parse_hosts(payload.get("bucket_hosts"), buckets),
    )


def _parse_bucket(item: Any, settings: EngineSettings) -> BucketConfig | None:
    if not isinstance(item, dict) or not validate_bucket_name(item.get("name")):
        LOGGER.warning("dropping invalid bucket entry from S3 config snapshot")
        return None
    name = item["name"]
    mode = item.get("mode", "managed")
    link_mode = item.get("link_mode") or "rw"
    if mode not in {"managed", "linked"} or link_mode not in {"rw", "ro"}:
        LOGGER.warning("dropping bucket with invalid mode", extra={"bucket": name})
        return None
    link_path: Path | None = None
    if mode == "linked":
        raw_path = item.get("link_path")
        if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path:
            LOGGER.warning("dropping linked bucket without link_path", extra={"bucket": name})
            return None
        link_path = Path(raw_path)
        if not link_path.is_absolute() or not _within_roots(link_path, settings.link_roots):
            LOGGER.warning("dropping linked bucket outside the link roots", extra={"bucket": name})
            return None
    quota = item.get("quota_bytes")
    if quota is not None and (isinstance(quota, bool) or not isinstance(quota, int) or quota < 0):
        LOGGER.warning("ignoring invalid bucket quota", extra={"bucket": name})
        quota = None
    return BucketConfig(
        name=name,
        mode=mode,
        link_path=link_path,
        link_mode=link_mode,
        public_read=item.get("public_read") is True,
        public_list=item.get("public_list") is True,
        quota_bytes=quota,
        created_at_ns=_created_ns(item.get("created_at")),
        frozen=item.get("frozen") is True,
    )


def _limit(value: object) -> int | None:
    if value is None or isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _parse_groups(raw: Any, buckets: dict[str, BucketConfig]) -> dict[str, QuotaGroup]:
    if not isinstance(raw, list):
        return {}
    groups: dict[str, QuotaGroup] = {}
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            continue
        names = tuple(name for name in item.get("buckets") or [] if isinstance(name, str)
                      and name in buckets)
        group = QuotaGroup(item["id"], names, _limit(item.get("bytes")),
                           _limit(item.get("objects")))
        for name in names:
            groups[name] = group
    return groups


def _parse_hosts(raw: Any, buckets: dict[str, BucketConfig]) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {
        host.strip().lower().rstrip("."): bucket
        for host, bucket in list(raw.items())[:10000]
        if isinstance(host, str) and isinstance(bucket, str) and bucket in buckets
    }


def _parse_identity(item: Any) -> Identity | None:
    if not isinstance(item, dict):
        return None
    identity_id = item.get("id")
    name = item.get("name")
    if not isinstance(identity_id, str) or not identity_id or not isinstance(name, str) or not name:
        LOGGER.warning("dropping identity without id/name from S3 config snapshot")
        return None
    policy = item.get("policy")
    if policy is not None:
        try:
            validate_policy(policy)
        except PolicyError as exc:
            LOGGER.warning(
                "identity policy is malformed; identity gets no permissions",
                extra={"identity": name, "error": str(exc)},
            )
            policy = None
    keys: list[AccessKey] = []
    for raw in item.get("keys") or []:
        if not isinstance(raw, dict):
            continue
        akid = raw.get("access_key_id")
        ref = raw.get("secret_ref")
        if not isinstance(akid, str) or not akid or not isinstance(ref, str) or not ref:
            continue
        inline = raw.get("secret_access_key")
        keys.append(
            AccessKey(
                akid,
                ref,
                raw.get("enabled", True) is True,
                inline if isinstance(inline, str) and inline else None,
            )
        )
    return Identity(
        id=identity_id,
        name=name,
        enabled=item.get("enabled", True) is True,
        system=item.get("system", False) is True,
        policy=policy,
        keys=tuple(keys),
    )


class SnapshotManager:
    def __init__(self, settings: EngineSettings, secret_store: SecretStore | None = None) -> None:
        self.settings = settings
        self._secret_store = secret_store
        self.current: Snapshot | None = None
        self.last_error: str | None = None
        self.loaded_at: float = 0.0
        self._mtime: int | None = None
        self._lock = threading.RLock()
        self._secrets: dict[str, tuple[str, float]] = {}

    @property
    def secret_store(self) -> SecretStore:
        if self._secret_store is None:
            self._secret_store = SecretStore(self.settings.secrets_root)
        return self._secret_store

    def reload(self, *, force: bool = False) -> bool:
        path = self.settings.config_file
        with self._lock:
            try:
                stat = path.stat()
            except FileNotFoundError:
                if self.current is not None:
                    LOGGER.warning("S3 config snapshot disappeared; keeping the last good one")
                self.last_error = "config snapshot missing"
                return False
            except OSError as exc:
                self.last_error = f"config snapshot unreadable: {exc.__class__.__name__}"
                return False
            if not force and self._mtime == stat.st_mtime_ns:
                return False
            self._mtime = stat.st_mtime_ns
            try:
                if stat.st_size > MAX_CONFIG_BYTES:
                    raise ValueError("config snapshot is too large")
                payload = json.loads(path.read_text(encoding="utf-8"))
                snapshot = parse_snapshot(payload, self.settings, stat.st_mtime_ns)
            except (OSError, ValueError) as exc:
                self.last_error = str(exc)[:300]
                LOGGER.error(
                    "invalid S3 config snapshot; keeping the last good one",
                    extra={"error": self.last_error},
                )
                return False
            self.current = snapshot
            self.last_error = None
            self.loaded_at = time.time()
            self._secrets.clear()
            LOGGER.info(
                "loaded S3 config snapshot",
                extra={
                    "enabled": snapshot.enabled,
                    "buckets": len(snapshot.buckets),
                    "identities": len(snapshot.identities),
                },
            )
            return True

    def accept(self, payload: object) -> str | None:
        """Store a snapshot pushed over the admin API (docs/44). Returns an error or None.

        It is validated first, so a bad push never replaces the last good config.
        The file holds access-key secrets: mode 0600, atomic replace.
        """
        if not isinstance(payload, dict):
            return "config must be a JSON object"
        try:
            parse_snapshot(payload, self.settings, 0)
        except ValueError as exc:
            return str(exc)[:300]
        path = self.settings.config_file
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        self.reload(force=True)
        return self.last_error

    def secret_for(self, access_key_id: str) -> str | None:
        snapshot = self.current
        if snapshot is None:
            return None
        entry = snapshot.keys.get(access_key_id)
        if entry is None:
            return None
        identity, key = entry
        if not identity.enabled or not key.enabled:
            return None
        if key.secret is not None:
            return key.secret
        now = time.monotonic()
        cached = self._secrets.get(key.secret_ref)
        if cached and cached[1] > now:
            return cached[0]
        try:
            value = self.secret_store.get(key.secret_ref)
        except (KeyError, ValueError, OSError):
            LOGGER.warning(
                "access key secret is unavailable", extra={"access_key_id": access_key_id}
            )
            return None
        secret = value.get("secret_access_key") or value.get("secret")
        if not secret:
            return None
        self._secrets[key.secret_ref] = (secret, now + self.settings.secret_cache_seconds)
        return secret
