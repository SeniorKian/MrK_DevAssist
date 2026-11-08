"""Startup settings of the S3 engine (``MRK_S3_*`` environment variables, docs/27 §3)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB
TIB = 1024 * GIB


def _int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return min(max(value, minimum), maximum)


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _listen(raw: str, default: tuple[str, int]) -> tuple[str, int]:
    raw = raw.strip()
    if not raw:
        return default
    host, sep, port = raw.rpartition(":")
    if not sep:
        return default
    try:
        number = int(port)
    except ValueError:
        return default
    if not 0 <= number <= 65535:
        return default
    return (host.strip("[]") or default[0], number)


@dataclass(frozen=True, slots=True)
class EngineSettings:
    data_root: Path
    listen: tuple[str, int] = ("0.0.0.0", 9000)  # noqa: S104 - published via compose
    admin_listen: tuple[str, int] = ("127.0.0.1", 9001)
    secret_data_dir: Path | None = None
    link_roots: tuple[Path, ...] = (Path("/mnt/links"),)
    config_poll_seconds: float = 2.0
    clock_skew_seconds: int = 900
    accept_any_region: bool = True
    require_content_sha256: bool = True
    debug_signatures: bool = False
    max_single_put_bytes: int = 5 * GIB
    max_part_bytes: int = 5 * GIB
    multipart_min_part_bytes: int = 5 * MIB
    multipart_max_parts: int = 10000
    multipart_upload_ttl_days: int = 7
    max_xml_body_bytes: int = 2 * MIB
    max_header_bytes: int = 16 * KIB
    max_user_metadata_bytes: int = 2 * KIB
    max_key_bytes: int = 1024
    max_keys_per_list: int = 1000
    max_delete_objects: int = 1000
    max_chunk_bytes: int = 16 * MIB
    idle_body_timeout_seconds: int = 120
    fsync_policy: str = "object"  # none | object | strict
    gc_interval_seconds: int = 300
    tmp_ttl_seconds: int = 6 * 3600
    trash_grace_seconds: int = 60
    disk_block_percent: int = 90
    hash_rate_bytes: int = 50 * MIB
    hash_max_file_bytes: int = 1 * GIB
    secret_cache_seconds: int = 300
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def config_file(self) -> Path:
        return self.data_root / "config.json"

    @property
    def admin_token_file(self) -> Path:
        return self.data_root / "admin.token"

    @property
    def buckets_dir(self) -> Path:
        return self.data_root / "buckets"

    @property
    def meta_dir(self) -> Path:
        return self.data_root / "meta"

    @property
    def secrets_root(self) -> Path:
        return self.secret_data_dir or self.data_root.parent.parent

    def with_overrides(self, **values: object) -> EngineSettings:
        return replace(self, **values)  # type: ignore[arg-type]

    @classmethod
    def from_env(cls) -> EngineSettings:
        data_dir = Path(os.getenv("MRK_DATA_DIR", "/data").strip() or "/data")
        root = Path(os.getenv("MRK_S3_DATA_DIR", "").strip() or data_dir / "modules" / "s3")
        roots = tuple(
            Path(item.strip())
            for item in os.getenv("MRK_S3_LINK_ROOTS", "/mnt/links").split(",")
            if item.strip()
        )
        fsync_policy = os.getenv("MRK_S3_FSYNC_POLICY", "object").strip().lower()
        if fsync_policy not in {"none", "object", "strict"}:
            fsync_policy = "object"
        return cls(
            data_root=root,
            listen=_listen(os.getenv("MRK_S3_LISTEN", ""), ("0.0.0.0", 9000)),  # noqa: S104
            admin_listen=_listen(os.getenv("MRK_S3_ADMIN_LISTEN", ""), ("127.0.0.1", 9001)),
            secret_data_dir=data_dir,
            link_roots=roots or (Path("/mnt/links"),),
            config_poll_seconds=float(_int("MRK_S3_CONFIG_POLL_SECONDS", 2, 1, 300)),
            clock_skew_seconds=_int("MRK_S3_CLOCK_SKEW_SECONDS", 900, 60, 86400),
            accept_any_region=_bool("MRK_S3_ACCEPT_ANY_REGION", True),
            require_content_sha256=_bool("MRK_S3_REQUIRE_CONTENT_SHA256", True),
            debug_signatures=_bool("MRK_S3_DEBUG_SIGNATURES", False),
            max_single_put_bytes=_int("MRK_S3_MAX_SINGLE_PUT_BYTES", 5 * GIB, 1, 5 * TIB),
            max_part_bytes=_int("MRK_S3_MAX_PART_BYTES", 5 * GIB, MIB, 5 * TIB),
            multipart_min_part_bytes=_int("MRK_S3_MULTIPART_MIN_PART_BYTES", 5 * MIB, 1, 5 * GIB),
            multipart_max_parts=_int("MRK_S3_MULTIPART_MAX_PARTS", 10000, 1, 10000),
            multipart_upload_ttl_days=_int("MRK_S3_MULTIPART_UPLOAD_TTL_DAYS", 7, 1, 3650),
            max_xml_body_bytes=_int("MRK_S3_MAX_XML_BODY_BYTES", 2 * MIB, 64 * KIB, 64 * MIB),
            max_header_bytes=_int("MRK_S3_MAX_HEADER_BYTES", 16 * KIB, 4 * KIB, 1 * MIB),
            max_user_metadata_bytes=_int("MRK_S3_MAX_USER_METADATA_BYTES", 2 * KIB, 256, 64 * KIB),
            max_chunk_bytes=_int("MRK_S3_MAX_CHUNK_BYTES", 16 * MIB, 64 * KIB, 1 * GIB),
            idle_body_timeout_seconds=_int("MRK_S3_IDLE_BODY_TIMEOUT_SECONDS", 120, 5, 3600),
            fsync_policy=fsync_policy,
            gc_interval_seconds=_int("MRK_S3_GC_INTERVAL_SECONDS", 300, 10, 86400),
            tmp_ttl_seconds=_int("MRK_S3_TMP_TTL_SECONDS", 6 * 3600, 60, 30 * 86400),
            disk_block_percent=_int("MRK_S3_DISK_BLOCK_PERCENT", 90, 50, 100),
            hash_rate_bytes=_int("MRK_S3_HASH_RATE_BYTES", 50 * MIB, 0, 10 * GIB),
            hash_max_file_bytes=_int("MRK_S3_HASH_MAX_FILE_BYTES", 1 * GIB, 0, 5 * TIB),
        )
