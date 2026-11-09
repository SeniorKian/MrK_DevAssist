"""S3 module state: settings, bucket registry, identities/keys and the engine snapshot.

The control plane is the only writer. Every change is committed to the database and
then rendered into ``<data>/modules/s3/config.json`` (atomic replace), which the engine
reloads on mtime change (docs/31 §2). Secrets never enter the snapshot or the database:
only ``secret_ref`` references into ``SecretStore`` do.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import string
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..database import Database
from ..models import (
    ResourceOwner,
    S3AccessKey,
    S3Bucket,
    S3Identity,
    SystemSetting,
    TenancyPlan,
    Workspace,
)
from ..secret_store import SecretStore
from .s3_policy import (
    PANEL_IDENTITY,
    POLICY_TEMPLATES,
    PolicyError,
    bucket_name_error,
    identity_name_error,
    panel_policy,
    template_policy,
    validate_policy,
    workspace_policy,
)

SETTINGS_KEY = "s3.settings"
# Written by the services module (docs/35 §4): every S3 domain, for virtual-host style.
DOMAIN_SUFFIXES_KEY = "s3.domain_suffixes"
PANEL_SECRET_REF = "s3-panel"  # noqa: S105 - SecretStore reference, not a secret
MAX_OBJECT_BYTES = 5 * 1024**4  # 5 TiB, the S3 single-object maximum
MAX_ACTIVE_KEYS = 2
MAX_KEYS_PER_IDENTITY = 10
DEFAULT_LINKS_ROOT = "/mnt/links"
DEFAULT_SETTINGS: dict[str, Any] = {
    "enabled": True,
    "region": "us-east-1",
    "public_endpoint": None,
    "virtual_host_suffix": None,
    "max_object_bytes": MAX_OBJECT_BYTES,
    "default_quota_bytes": None,
}
_AKID_ALPHABET = string.ascii_uppercase + string.digits
_SECRET_ALPHABET = string.ascii_letters + string.digits + "+/"
_REGION = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_AKID = re.compile(r"^MRK[A-Z0-9]{17}$")


class S3Error(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


def _now() -> int:
    return int(time.time())


def generate_access_key_id() -> str:
    return "MRK" + "".join(secrets.choice(_AKID_ALPHABET) for _ in range(17))


def generate_secret_key() -> str:
    return "".join(secrets.choice(_SECRET_ALPHABET) for _ in range(40))


def links_root() -> Path:
    return Path(os.getenv("MRK_S3_LINKS_ROOT", "").strip() or DEFAULT_LINKS_ROOT)


def _bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise S3Error("invalid_settings", 422, f"{field} must be true or false")
    return value


def _optional_size(
    value: object, field: str, code: str, *, maximum: int | None = None
) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise S3Error(code, 422, f"{field} must be a positive integer or null")
    if maximum is not None and value > maximum:
        raise S3Error(code, 422, f"{field} must be at most {maximum}")
    return value


def validate_public_endpoint(value: object) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > 255 or any(c.isspace() for c in value):
        raise S3Error("invalid_public_endpoint", 422, "public_endpoint must be an http(s) URL")
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        raise S3Error(
            "invalid_public_endpoint", 422, "public_endpoint is not a valid URL"
        ) from None
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise S3Error("invalid_public_endpoint", 422, "public_endpoint must be http:// or https://")
    if parts.username is not None or parts.password is not None:
        raise S3Error(
            "invalid_public_endpoint", 422, "public_endpoint must not contain credentials"
        )
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise S3Error(
            "invalid_public_endpoint", 422, "public_endpoint must not contain a path or query"
        )
    host = parts.hostname.lower()
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return f"{parts.scheme}://{netloc}"


def validate_settings(payload: object, current: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise S3Error("invalid_settings", 422, "settings must be a JSON object")
    unknown = set(payload) - set(DEFAULT_SETTINGS)
    if unknown:
        raise S3Error("invalid_settings", 422, f"unknown setting(s): {', '.join(sorted(unknown))}")
    merged = {**current}
    if "enabled" in payload:
        merged["enabled"] = _bool(payload["enabled"], "enabled")
    if "region" in payload:
        region = payload["region"]
        if not isinstance(region, str) or not _REGION.fullmatch(region):
            raise S3Error("invalid_region", 422, "region must look like 'us-east-1'")
        merged["region"] = region
    if "public_endpoint" in payload:
        merged["public_endpoint"] = validate_public_endpoint(payload["public_endpoint"])
    if "virtual_host_suffix" in payload:
        suffix = payload["virtual_host_suffix"]
        if suffix in (None, ""):
            merged["virtual_host_suffix"] = None
        elif isinstance(suffix, str) and _HOSTNAME.fullmatch(suffix.strip().lower()):
            merged["virtual_host_suffix"] = suffix.strip().lower()
        else:
            raise S3Error(
                "invalid_virtual_host_suffix", 422, "virtual_host_suffix must be a hostname"
            )
    if "max_object_bytes" in payload:
        value = _optional_size(
            payload["max_object_bytes"],
            "max_object_bytes",
            "invalid_settings",
            maximum=MAX_OBJECT_BYTES,
        )
        if value is None:
            raise S3Error("invalid_settings", 422, "max_object_bytes is required")
        merged["max_object_bytes"] = value
    if "default_quota_bytes" in payload:
        merged["default_quota_bytes"] = _optional_size(
            payload["default_quota_bytes"], "default_quota_bytes", "invalid_quota"
        )
    return merged


def _bucket_item(row: S3Bucket) -> dict[str, Any]:
    return {
        "name": row.name,
        "mode": row.mode,
        "link_path": row.link_path,
        "link_mode": row.link_mode,
        "public_read": bool(row.public_read),
        "quota_bytes": row.quota_bytes,
        "created_at": row.created_at,
    }


def _key_item(row: S3AccessKey) -> dict[str, Any]:
    return {
        "access_key_id": row.access_key_id,
        "enabled": bool(row.enabled),
        "created_at": row.created_at,
        "last_used_at": row.last_used_at,
    }


def _identity_item(row: S3Identity) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "enabled": bool(row.enabled),
        "policy_template": row.policy_template,
        "buckets": list(row.buckets or []),
        "policy": row.policy,
        "keys": [_key_item(key) for key in row.keys],
        "created_at": row.created_at,
    }


class S3Store:
    def __init__(self, data_dir: Path, database: Database, secret_store: SecretStore) -> None:
        self.data_dir = data_dir
        self.module_dir = data_dir / "modules" / "s3"
        self.snapshot_path = self.module_dir / "config.json"
        self.admin_token_path = self.module_dir / "admin.token"
        self.db = database
        self.secrets = secret_store
        self._snapshot_lock = threading.Lock()
        self._panel_lock = threading.Lock()

    # ------------------------------------------------------------ bootstrap

    def ensure_dirs(self) -> None:
        self.module_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def ensure_admin_token(self) -> None:
        """Create the shared admin token (0600) if neither side has created it yet."""
        self.ensure_dirs()
        if self.admin_token_path.exists():
            return
        try:
            fd = os.open(self.admin_token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(secrets.token_urlsafe(32) + "\n")

    def panel_credentials(self) -> tuple[str, str]:
        """The hidden full-access identity; its secret is generated once."""
        with self._panel_lock:
            try:
                value = self.secrets.get(PANEL_SECRET_REF)
                akid, secret = value.get("access_key_id"), value.get("secret_access_key")
                if akid and secret and _AKID.fullmatch(akid):
                    return akid, secret
            except KeyError:
                pass
            akid, secret = generate_access_key_id(), generate_secret_key()
            self.secrets.replace(
                PANEL_SECRET_REF, {"access_key_id": akid, "secret_access_key": secret}
            )
            return akid, secret

    def startup(self) -> None:
        self.ensure_admin_token()
        self.panel_credentials()
        self.write_snapshot()

    # ------------------------------------------------------------ settings

    def get_settings(self) -> dict[str, Any]:
        with self.db.session() as db:
            row = db.get(SystemSetting, SETTINGS_KEY)
            stored = dict(row.value) if row is not None and isinstance(row.value, dict) else {}
        return {**DEFAULT_SETTINGS, **{k: v for k, v in stored.items() if k in DEFAULT_SETTINGS}}

    def put_settings(self, payload: object, actor_user_id: int | None) -> dict[str, Any]:
        merged = validate_settings(payload, self.get_settings())
        with self.db.session() as db, db.begin():
            row = db.get(SystemSetting, SETTINGS_KEY)
            if row is None:
                row = SystemSetting(key=SETTINGS_KEY, value=merged, updated_at=_now())
                db.add(row)
            row.value = merged
            row.updated_at = _now()
            row.updated_by_user_id = actor_user_id
        self.write_snapshot()
        return merged

    # ------------------------------------------------------------ snapshot

    def snapshot(self) -> dict[str, Any]:
        settings = self.get_settings()
        akid, _secret = self.panel_credentials()
        with self.db.session() as db:
            buckets = db.scalars(select(S3Bucket).order_by(S3Bucket.name)).all()
            identities = db.scalars(
                select(S3Identity).options(selectinload(S3Identity.keys)).order_by(S3Identity.name)
            ).all()
            identity_items = [
                {
                    "id": row.id,
                    "name": row.name,
                    "enabled": bool(row.enabled),
                    "system": False,
                    "policy": row.policy,
                    "keys": [
                        {
                            "access_key_id": key.access_key_id,
                            "secret_ref": key.secret_ref,
                            "enabled": bool(key.enabled),
                        }
                        for key in row.keys
                    ],
                }
                for row in identities
            ]
            bucket_items = [_bucket_item(row) for row in buckets]
            groups, frozen, hosts = self._tenancy_snapshot(db)
            for item in bucket_items:
                if item["name"] in frozen:
                    item["frozen"] = True
            suffix_row = db.get(SystemSetting, DOMAIN_SUFFIXES_KEY)
            extra_suffixes = (
                [item for item in suffix_row.value.get("hosts", []) if isinstance(item, str)]
                if suffix_row is not None and isinstance(suffix_row.value, dict)
                else []
            )
        panel = {
            "id": PANEL_IDENTITY,
            "name": PANEL_IDENTITY,
            "enabled": True,
            "system": True,
            "policy": panel_policy(),
            "keys": [{"access_key_id": akid, "secret_ref": PANEL_SECRET_REF, "enabled": True}],
        }
        return {
            "version": 1,
            "enabled": bool(settings["enabled"]),
            "region": settings["region"],
            "public_endpoint": settings["public_endpoint"],
            "virtual_host_suffix": settings["virtual_host_suffix"],
            "virtual_host_suffixes": extra_suffixes,
            "max_object_bytes": settings["max_object_bytes"],
            "buckets": bucket_items,
            "identities": [panel, *identity_items],
            # docs/43 §3: per-workspace byte/object quotas (enforced by the engine on
            # writes) and verified bucket domains. Both empty without «my space».
            "quota_groups": groups,
            "bucket_hosts": hosts,
        }

    @staticmethod
    def _tenancy_snapshot(db: Any) -> tuple[list[dict[str, Any]], set[str], dict[str, str]]:
        from ..tenancy import effective_limits

        owners = db.scalars(select(ResourceOwner).where(
            ResourceOwner.kind.in_(["s3_bucket", "bucket_domain"]))).all()
        if not owners:
            return [], set(), {}
        workspaces = {row.id: row for row in db.scalars(select(Workspace))}
        plans = {row.id: row for row in db.scalars(select(TenancyPlan))}
        by_workspace: dict[str, list[str]] = {}
        hosts: dict[str, str] = {}
        for owner in owners:
            if owner.kind == "s3_bucket":
                by_workspace.setdefault(owner.workspace_id, []).append(owner.resource_id)
            elif (owner.meta or {}).get("verified") and (owner.meta or {}).get("bucket"):
                hosts[owner.resource_id] = str(owner.meta["bucket"])
        groups: list[dict[str, Any]] = []
        frozen: set[str] = set()
        for workspace_id, names in sorted(by_workspace.items()):
            workspace = workspaces.get(workspace_id)
            if workspace is None:
                continue
            plan = plans.get(workspace.plan_id)
            limits = effective_limits(
                {"features": plan.features, "quotas": plan.quotas} if plan else None,
                workspace.quota_overrides,
            )["quotas"]
            groups.append({"id": workspace_id, "buckets": sorted(names),
                           "bytes": limits.get("s3_bytes"), "objects": limits.get("s3_objects")})
            if workspace.status == "suspended":
                frozen.update(names)
        return groups, frozen, hosts

    def write_snapshot(self) -> None:
        self._write_snapshot_file()
        self._notify_engine()

    def _notify_engine(self) -> None:
        """Ask the engine to reload now (best effort; it also polls every ~2s).

        Without this a key created in the panel could be rejected for a moment.
        """
        import urllib.request

        try:
            token = self.admin_token_path.read_text(encoding="utf-8").strip()
        except OSError:
            return
        base = (os.getenv("MRK_S3_ADMIN_URL", "").strip() or "http://127.0.0.1:9001").rstrip("/")
        if not base.startswith(("http://", "https://")):
            return
        request = urllib.request.Request(  # noqa: S310 - scheme checked above
            f"{base}/admin/reload", method="POST", headers={"X-MRK-Admin-Token": token}
        )
        try:
            # Fixed loopback admin URL (operator-configurable), short timeout.
            with urllib.request.urlopen(request, timeout=1.5):  # noqa: S310
                pass
        except Exception:  # noqa: BLE001 - the engine may be down; polling catches up
            return

    def _write_snapshot_file(self) -> None:
        with self._snapshot_lock:
            self.ensure_dirs()
            payload = json.dumps(self.snapshot(), ensure_ascii=False, indent=1, sort_keys=True)
            temporary = self.snapshot_path.with_name(
                f".{self.snapshot_path.name}.{secrets.token_hex(4)}.tmp"
            )
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(payload + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.snapshot_path)
            finally:
                if temporary.exists():
                    temporary.unlink(missing_ok=True)
            if hasattr(os, "O_DIRECTORY"):
                try:
                    dir_fd = os.open(self.module_dir, os.O_RDONLY | os.O_DIRECTORY)
                except OSError:
                    return
                try:
                    os.fsync(dir_fd)
                except OSError:
                    pass
                finally:
                    os.close(dir_fd)

    # ------------------------------------------------------------ links

    def resolve_link_path(self, raw: object) -> str:
        root = links_root()
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
            raise S3Error("link_path_invalid", 422, f"link_path must be a directory under {root}")
        text = raw.strip()
        if any(part == ".." for part in re.split(r"[\\/]", text)):
            raise S3Error("link_path_invalid", 422, "link_path must not contain '..'")
        candidate = Path(text)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            real_root = root.resolve(strict=True)
        except OSError:
            raise S3Error(
                "link_path_invalid", 422, f"no folders are mounted under {root}"
            ) from None
        real = candidate.resolve(strict=False)
        if real == real_root or real_root not in real.parents:
            raise S3Error("link_path_invalid", 422, f"link_path must be a directory under {root}")
        if not real.is_dir():
            raise S3Error(
                "link_path_invalid", 422, "link_path does not exist or is not a directory"
            )
        relative = real.relative_to(real_root).as_posix()
        return f"{str(root).rstrip('/')}/{relative}" if str(root) != "/" else f"/{relative}"

    def list_links(self) -> list[dict[str, Any]]:
        root = links_root()
        try:
            real_root = root.resolve(strict=True)
        except OSError:
            return []
        if not real_root.is_dir():
            return []
        used = {row["link_path"]: row["name"] for row in self.list_buckets() if row["link_path"]}
        items: list[dict[str, Any]] = []

        def visit(directory: Path, depth: int) -> None:
            try:
                entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
            except OSError:
                return
            for entry in entries:
                if len(items) >= 500:
                    return
                if entry.name.startswith((".mrk", "lost+found")):
                    continue
                try:
                    if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                path = Path(entry.path)
                relative = path.relative_to(real_root).as_posix()
                public = f"{str(root).rstrip('/')}/{relative}"
                items.append(
                    {
                        "path": public,
                        "writable": os.access(path, os.W_OK),
                        "size_bytes": None,
                        "bucket": used.get(public),
                    }
                )
                if depth < 2:
                    visit(path, depth + 1)

        visit(real_root, 1)
        return items

    # ------------------------------------------------------------ buckets

    def list_buckets(self) -> list[dict[str, Any]]:
        with self.db.session() as db:
            return [
                _bucket_item(row) for row in db.scalars(select(S3Bucket).order_by(S3Bucket.name))
            ]

    def get_bucket(self, name: str) -> dict[str, Any]:
        with self.db.session() as db:
            row = db.get(S3Bucket, name)
            if row is None:
                raise S3Error("bucket_not_found", 404, f"bucket '{name}' does not exist")
            return _bucket_item(row)

    def create_bucket(
        self, payload: object, actor_user_id: int | None, *, is_owner: bool
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise S3Error("invalid_request", 422, "request body must be a JSON object")
        allowed = {"name", "mode", "link_path", "link_mode", "public_read", "quota_bytes"}
        unknown = set(payload) - allowed
        if unknown:
            raise S3Error("invalid_request", 422, f"unknown field(s): {', '.join(sorted(unknown))}")
        name = payload.get("name")
        problem = bucket_name_error(name)
        if problem:
            raise S3Error("invalid_bucket_name", 422, problem)
        assert isinstance(name, str)
        mode = payload.get("mode", "managed")
        if mode not in {"managed", "linked"}:
            raise S3Error("invalid_bucket_mode", 422, "mode must be 'managed' or 'linked'")
        public_read = payload.get("public_read", False)
        if not isinstance(public_read, bool):
            raise S3Error("invalid_request", 422, "public_read must be true or false")
        settings = self.get_settings()
        quota = _optional_size(payload.get("quota_bytes"), "quota_bytes", "invalid_quota")
        link_path: str | None = None
        link_mode = "rw"
        if mode == "linked":
            if not is_owner:
                raise S3Error(
                    "linked_requires_owner",
                    403,
                    "only the owner may link a server folder (it exposes host files)",
                )
            link_mode = payload.get("link_mode", "ro")
            if link_mode not in {"ro", "rw"}:
                raise S3Error("invalid_link_mode", 422, "link_mode must be 'ro' or 'rw'")
            link_path = self.resolve_link_path(payload.get("link_path"))
        else:
            if payload.get("link_path") not in (None, ""):
                raise S3Error(
                    "link_path_invalid", 422, "link_path is only valid for linked buckets"
                )
            if quota is None:
                quota = settings["default_quota_bytes"]
        now = _now()
        with self.db.session() as db, db.begin():
            if db.get(S3Bucket, name) is not None:
                raise S3Error("bucket_exists", 409, f"bucket '{name}' already exists")
            if link_path is not None:
                for other in db.scalars(select(S3Bucket).where(S3Bucket.mode == "linked")):
                    existing = (other.link_path or "").rstrip("/") + "/"
                    wanted = link_path.rstrip("/") + "/"
                    if existing.startswith(wanted) or wanted.startswith(existing):
                        raise S3Error(
                            "link_path_in_use",
                            409,
                            f"link_path overlaps the folder of bucket '{other.name}'",
                        )
            row = S3Bucket(
                name=name,
                mode=mode,
                link_path=link_path,
                link_mode=link_mode,
                public_read=public_read,
                quota_bytes=quota,
                created_by_user_id=actor_user_id,
                created_at=now,
                updated_at=now,
            )
            db.add(row)
            db.flush()
            item = _bucket_item(row)
        self.write_snapshot()
        return item

    def update_bucket(self, name: str, payload: object, *, is_owner: bool) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise S3Error("invalid_request", 422, "request body must be a JSON object")
        unknown = set(payload) - {"public_read", "quota_bytes", "link_mode"}
        if unknown:
            raise S3Error("invalid_request", 422, f"unknown field(s): {', '.join(sorted(unknown))}")
        with self.db.session() as db, db.begin():
            row = db.get(S3Bucket, name)
            if row is None:
                raise S3Error("bucket_not_found", 404, f"bucket '{name}' does not exist")
            if "public_read" in payload:
                if not isinstance(payload["public_read"], bool):
                    raise S3Error("invalid_request", 422, "public_read must be true or false")
                row.public_read = payload["public_read"]
            if "quota_bytes" in payload:
                row.quota_bytes = _optional_size(
                    payload["quota_bytes"], "quota_bytes", "invalid_quota"
                )
            if "link_mode" in payload:
                if row.mode != "linked":
                    raise S3Error(
                        "invalid_link_mode", 422, "link_mode applies to linked buckets only"
                    )
                if not is_owner:
                    raise S3Error(
                        "linked_requires_owner", 403, "only the owner may change a linked folder"
                    )
                if payload["link_mode"] not in {"ro", "rw"}:
                    raise S3Error("invalid_link_mode", 422, "link_mode must be 'ro' or 'rw'")
                row.link_mode = payload["link_mode"]
            row.updated_at = _now()
            item = _bucket_item(row)
        self.write_snapshot()
        return item

    def delete_bucket_record(self, name: str) -> None:
        """Remove the bucket and strip it from templated identities."""
        with self.db.session() as db, db.begin():
            row = db.get(S3Bucket, name)
            if row is None:
                raise S3Error("bucket_not_found", 404, f"bucket '{name}' does not exist")
            db.delete(row)
            identities = db.scalars(select(S3Identity)).all()
            tenant_identities = set(db.scalars(select(ResourceOwner.resource_id).where(
                ResourceOwner.kind == "s3_identity")))
            for identity in identities:
                current = list(identity.buckets or [])
                if name not in current:
                    continue
                remaining = [item for item in current if item != name]
                identity.buckets = remaining
                if identity.id in tenant_identities:
                    # A «my space» key: no bucket left means no permission (never «*»).
                    identity.policy = workspace_policy(identity.policy_template, remaining)
                elif identity.policy_template != "custom":
                    identity.policy = template_policy(identity.policy_template, remaining)
                identity.updated_at = _now()
        self.write_snapshot()

    # ------------------------------------------------------------ identities

    def _bucket_names(self, db: Any) -> set[str]:
        return set(db.scalars(select(S3Bucket.name)).all())

    def _policy_for(
        self, db: Any, template: object, buckets: object, policy: object
    ) -> tuple[str, list[str], dict[str, Any]]:
        if template not in POLICY_TEMPLATES:
            raise S3Error(
                "invalid_policy_template",
                422,
                f"policy_template must be one of {', '.join(POLICY_TEMPLATES)}",
            )
        assert isinstance(template, str)
        if buckets is None:
            buckets = []
        if not isinstance(buckets, list) or not all(isinstance(item, str) for item in buckets):
            raise S3Error("invalid_request", 422, "buckets must be a list of bucket names")
        unique = sorted(set(buckets))
        if len(unique) > 100:
            raise S3Error("invalid_request", 422, "at most 100 buckets per identity")
        missing = [item for item in unique if item not in self._bucket_names(db)]
        if missing:
            raise S3Error("bucket_not_found", 404, f"unknown bucket(s): {', '.join(missing)}")
        try:
            if template == "custom":
                if policy is None:
                    raise PolicyError("a custom policy document is required")
                return template, unique, validate_policy(policy)
            if template != "admin" and not unique:
                raise S3Error(
                    "invalid_request", 422, f"template '{template}' needs at least one bucket"
                )
            return template, unique, template_policy(template, unique)
        except PolicyError as exc:
            raise S3Error("invalid_policy", 422, str(exc)) from None

    def list_identities(self) -> list[dict[str, Any]]:
        with self.db.session() as db:
            rows = db.scalars(
                select(S3Identity).options(selectinload(S3Identity.keys)).order_by(S3Identity.name)
            ).all()
            return [_identity_item(row) for row in rows]

    def _identity(self, db: Any, identity_id: str) -> S3Identity:
        row = db.get(S3Identity, identity_id, options=[selectinload(S3Identity.keys)])
        if row is None:
            raise S3Error("identity_not_found", 404, "identity does not exist")
        return row

    def create_identity(self, payload: object, actor_user_id: int | None) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise S3Error("invalid_request", 422, "request body must be a JSON object")
        unknown = set(payload) - {"name", "policy_template", "buckets", "policy", "enabled"}
        if unknown:
            raise S3Error("invalid_request", 422, f"unknown field(s): {', '.join(sorted(unknown))}")
        name = payload.get("name")
        problem = identity_name_error(name)
        if problem:
            raise S3Error("invalid_identity_name", 422, problem)
        enabled = payload.get("enabled", True)
        if not isinstance(enabled, bool):
            raise S3Error("invalid_request", 422, "enabled must be true or false")
        now = _now()
        with self.db.session() as db, db.begin():
            template, buckets, policy = self._policy_for(
                db, payload.get("policy_template"), payload.get("buckets"), payload.get("policy")
            )
            if db.scalar(select(S3Identity.id).where(S3Identity.name == name)) is not None:
                raise S3Error("identity_exists", 409, f"identity '{name}' already exists")
            row = S3Identity(
                id=secrets.token_hex(16),
                name=name,
                enabled=enabled,
                policy_template=template,
                buckets=buckets,
                policy=policy,
                created_by_user_id=actor_user_id,
                created_at=now,
                updated_at=now,
            )
            row.keys = []
            db.add(row)
            db.flush()
            item = _identity_item(row)
        self.write_snapshot()
        return item

    def update_identity(self, identity_id: str, payload: object) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise S3Error("invalid_request", 422, "request body must be a JSON object")
        unknown = set(payload) - {"name", "policy_template", "buckets", "policy", "enabled"}
        if unknown:
            raise S3Error("invalid_request", 422, f"unknown field(s): {', '.join(sorted(unknown))}")
        with self.db.session() as db, db.begin():
            row = self._identity(db, identity_id)
            if "name" in payload and payload["name"] != row.name:
                problem = identity_name_error(payload["name"])
                if problem:
                    raise S3Error("invalid_identity_name", 422, problem)
                clash = db.scalar(select(S3Identity.id).where(S3Identity.name == payload["name"]))
                if clash is not None:
                    raise S3Error(
                        "identity_exists", 409, f"identity '{payload['name']}' already exists"
                    )
                row.name = payload["name"]
            if "enabled" in payload:
                if not isinstance(payload["enabled"], bool):
                    raise S3Error("invalid_request", 422, "enabled must be true or false")
                row.enabled = payload["enabled"]
            if {"policy_template", "buckets", "policy"} & set(payload):
                template = payload.get("policy_template", row.policy_template)
                policy = payload.get("policy")
                if template == "custom" and policy is None and row.policy_template == "custom":
                    policy = row.policy
                template, buckets, document = self._policy_for(
                    db, template, payload.get("buckets", row.buckets), policy
                )
                row.policy_template, row.buckets, row.policy = template, buckets, document
            row.updated_at = _now()
            item = _identity_item(row)
        self.write_snapshot()
        return item

    def set_workspace_policy(
        self, identity_id: str, access: str, buckets: list[str]
    ) -> dict[str, Any]:
        """A «my space» key's policy, always built here (docs/43 §3; never user JSON)."""
        try:
            document = workspace_policy(access, sorted(set(buckets)))
        except PolicyError as exc:
            raise S3Error("invalid_policy_template", 422, str(exc)) from None
        with self.db.session() as db, db.begin():
            row = self._identity(db, identity_id)
            missing = [item for item in buckets if item not in self._bucket_names(db)]
            if missing:
                raise S3Error("bucket_not_found", 404, "unknown bucket")
            row.policy_template = access
            row.buckets = sorted(set(buckets))
            row.policy = document
            row.updated_at = _now()
            item = _identity_item(row)
        self.write_snapshot()
        return item

    def delete_identity(self, identity_id: str, confirmation: object) -> dict[str, Any]:
        with self.db.session() as db, db.begin():
            row = self._identity(db, identity_id)
            if confirmation != row.name:
                raise S3Error(
                    "confirmation_mismatch", 422, "confirmation must equal the identity name"
                )
            refs = [key.secret_ref for key in row.keys]
            item = {"id": row.id, "name": row.name}
            db.delete(row)
        self.write_snapshot()
        for ref in refs:
            self.secrets.delete(ref)
        return item

    # ------------------------------------------------------------ keys

    def create_key(self, identity_id: str) -> dict[str, Any]:
        secret = generate_secret_key()
        with self.db.session() as db, db.begin():
            row = self._identity(db, identity_id)
            if sum(1 for key in row.keys if key.enabled) >= MAX_ACTIVE_KEYS:
                raise S3Error(
                    "key_limit_reached",
                    409,
                    f"an identity may have at most {MAX_ACTIVE_KEYS} active keys; "
                    "disable or delete one first",
                )
            if len(row.keys) >= MAX_KEYS_PER_IDENTITY:
                raise S3Error(
                    "key_limit_reached",
                    409,
                    f"an identity may have at most {MAX_KEYS_PER_IDENTITY} keys",
                )
            akid = generate_access_key_id()
            while db.get(S3AccessKey, akid) is not None:  # pragma: no cover - 36^17 space
                akid = generate_access_key_id()
            reference, _updated = self.secrets.replace(
                None, {"access_key_id": akid, "secret_access_key": secret}
            )
            now = _now()
            try:
                db.add(
                    S3AccessKey(
                        access_key_id=akid,
                        identity_id=row.id,
                        secret_ref=reference,
                        enabled=True,
                        created_at=now,
                    )
                )
                db.flush()
            except Exception:
                self.secrets.delete(reference)
                raise
        self.write_snapshot()
        return {
            "access_key_id": akid,
            "secret_access_key": secret,
            "identity_id": identity_id,
            "enabled": True,
            "created_at": now,
        }

    def _key(self, db: Any, identity_id: str, akid: str) -> S3AccessKey:
        row = db.get(S3AccessKey, akid)
        if row is None or row.identity_id != identity_id:
            raise S3Error("key_not_found", 404, "access key does not exist")
        return row

    def update_key(self, identity_id: str, akid: str, payload: object) -> dict[str, Any]:
        if (
            not isinstance(payload, dict)
            or set(payload) - {"enabled"}
            or not isinstance(payload.get("enabled"), bool)
        ):
            raise S3Error("invalid_request", 422, 'body must be {"enabled": true|false}')
        with self.db.session() as db, db.begin():
            identity = self._identity(db, identity_id)
            row = self._key(db, identity_id, akid)
            if payload["enabled"] and not row.enabled:
                active = sum(1 for key in identity.keys if key.enabled)
                if active >= MAX_ACTIVE_KEYS:
                    raise S3Error(
                        "key_limit_reached",
                        409,
                        f"an identity may have at most {MAX_ACTIVE_KEYS} active keys",
                    )
            row.enabled = payload["enabled"]
            item = _key_item(row)
        self.write_snapshot()
        return item

    def delete_key(self, identity_id: str, akid: str) -> None:
        with self.db.session() as db, db.begin():
            row = self._key(db, identity_id, akid)
            reference = row.secret_ref
            db.delete(row)
        self.write_snapshot()
        self.secrets.delete(reference)
