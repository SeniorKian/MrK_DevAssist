from __future__ import annotations

import ipaddress
import json
import os
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit


class UpstreamStore:
    def __init__(self, data_dir: Path) -> None:
        self.root = data_dir / "control-plane"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root / "upstreams.json"
        self.offline_files = {
            "pypi": self.root / "pypi-offline",
            "npm": self.root / "npm-offline",
        }
        self._lock = threading.RLock()

    @staticmethod
    def validate_url(value: str) -> str:
        parsed = urlsplit(value.strip())
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("upstream URL must be HTTPS")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("credentials, query strings and fragments are forbidden")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise ValueError("private and local upstream addresses are forbidden")
        return value.strip().rstrip("/") + "/"

    def ensure_defaults(
        self,
        primary: str,
        fallback: str,
        npm_primary: str = "https://registry.npmjs.org/",
        npm_fallback: str = "https://package-mirror.liara.ir/repository/npm/",
    ) -> None:
        with self._lock:
            now = int(time.time())
            items = self._read()
            changed = False
            defaults = [
                {
                    "id": secrets.token_hex(8),
                    "name": "pypi.org",
                    "ecosystem": "pypi",
                    "url": self.validate_url(primary),
                    "priority": 10,
                    "timeout_seconds": 90,
                    "enabled": True,
                    "blocked_until": None,
                    "blocked_reason": None,
                    "created_at": now,
                    "updated_at": now,
                },
                {
                    "id": secrets.token_hex(8),
                    "name": "Liara",
                    "ecosystem": "pypi",
                    "url": self.validate_url(fallback),
                    "priority": 20,
                    "timeout_seconds": 90,
                    "enabled": True,
                    "blocked_until": None,
                    "blocked_reason": None,
                    "created_at": now,
                    "updated_at": now,
                },
                {
                    "id": secrets.token_hex(8),
                    "name": "npmjs.org",
                    "ecosystem": "npm",
                    "url": self.validate_url(npm_primary),
                    "priority": 10,
                    "timeout_seconds": 7,
                    "enabled": True,
                    "blocked_until": None,
                    "blocked_reason": None,
                    "created_at": now,
                    "updated_at": now,
                },
                {
                    "id": secrets.token_hex(8),
                    "name": "Liara npm",
                    "ecosystem": "npm",
                    "url": self.validate_url(npm_fallback),
                    "priority": 20,
                    "timeout_seconds": 7,
                    "enabled": True,
                    "blocked_until": None,
                    "blocked_reason": None,
                    "created_at": now,
                    "updated_at": now,
                },
            ]
            for default in defaults:
                if any(
                    item.get("ecosystem") == default["ecosystem"]
                    and item.get("name") == default["name"]
                    for item in items
                ):
                    continue
                items.append(default)
                changed = True
            if changed or not self.path.exists():
                self._write(items)

    def _read(self) -> list[dict[str, object]]:
        if not self.path.exists():
            return []
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("upstream store is invalid")
        return [dict(item) for item in payload]

    def _write(self, items: list[dict[str, object]]) -> None:
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(
            json.dumps(items, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, self.path)

    def list(self) -> list[dict[str, object]]:
        with self._lock:
            return sorted(
                [self.public(item) for item in self._read()],
                key=lambda item: (str(item["ecosystem"]), int(item["priority"])),
            )

    def raw_list(self) -> list[dict[str, object]]:
        with self._lock:
            return sorted(
                self._read(),
                key=lambda item: (str(item["ecosystem"]), int(item["priority"])),
            )

    @staticmethod
    def public(item: dict[str, object]) -> dict[str, object]:
        result = dict(item)
        result["credential_configured"] = bool(result.pop("credential_ref", None))
        return result

    def get(self, upstream_id: str) -> dict[str, object]:
        with self._lock:
            item = next(
                (item for item in self._read() if item["id"] == upstream_id), None
            )
            if item is None:
                raise KeyError(upstream_id)
            return dict(item)

    def create(
        self,
        name: str,
        ecosystem: str,
        url: str,
        priority: int,
        timeout_seconds: int,
    ) -> dict[str, object]:
        normalized_name = name.strip()
        if not 2 <= len(normalized_name) <= 80:
            raise ValueError("upstream name must be between 2 and 80 characters")
        if ecosystem not in {"npm", "pypi"}:
            raise ValueError("ecosystem must be npm or pypi")
        if not 1 <= priority <= 10000 or not 1 <= timeout_seconds <= 300:
            raise ValueError("priority or timeout is outside the supported range")
        now = int(time.time())
        item: dict[str, object] = {
            "id": secrets.token_hex(8),
            "name": normalized_name,
            "ecosystem": ecosystem,
            "url": self.validate_url(url),
            "priority": priority,
            "timeout_seconds": timeout_seconds,
            "enabled": True,
            "blocked_until": None,
            "blocked_reason": None,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            items = self._read()
            if any(
                str(existing["name"]).lower() == normalized_name.lower()
                and existing["ecosystem"] == ecosystem
                for existing in items
            ):
                raise ValueError("upstream name already exists in this ecosystem")
            items.append(item)
            self._write(items)
        return item

    def update(self, upstream_id: str, changes: dict[str, object]) -> dict[str, object]:
        allowed = {
            "name",
            "url",
            "priority",
            "timeout_seconds",
            "enabled",
            "blocked_until",
            "blocked_reason",
            "credential_ref",
            "credential_type",
            "credential_updated_at",
        }
        if set(changes) - allowed:
            raise ValueError("unsupported upstream field")
        with self._lock:
            items = self._read()
            target = next((item for item in items if item["id"] == upstream_id), None)
            if target is None:
                raise KeyError(upstream_id)
            if "url" in changes:
                changes["url"] = self.validate_url(str(changes["url"]))
            if "priority" in changes and not 1 <= int(changes["priority"]) <= 10000:
                raise ValueError("priority is outside the supported range")
            if "timeout_seconds" in changes and not 1 <= int(changes["timeout_seconds"]) <= 300:
                raise ValueError("timeout is outside the supported range")
            if changes.get("enabled") is False and target.get("enabled") is True:
                other_enabled = any(
                    item["id"] != upstream_id
                    and item["ecosystem"] == target["ecosystem"]
                    and item.get("enabled") is True
                    for item in items
                )
                if not other_enabled and not self.offline(str(target["ecosystem"])):
                    raise ValueError(
                        "the last enabled upstream can only be disabled in offline mode"
                    )
            target.update(changes)
            target["updated_at"] = int(time.time())
            self._write(items)
            return dict(target)

    def delete(self, upstream_id: str) -> dict[str, object]:
        with self._lock:
            items = self._read()
            target = next((item for item in items if item["id"] == upstream_id), None)
            if target is None:
                raise KeyError(upstream_id)
            remaining = [item for item in items if item["id"] != upstream_id]
            remaining_enabled = any(
                item["ecosystem"] == target["ecosystem"] and item.get("enabled") is True
                for item in remaining
            )
            if (
                target.get("enabled") is True
                and not remaining_enabled
                and not self.offline(str(target["ecosystem"]))
            ):
                raise ValueError(
                    "the last enabled upstream can only be deleted in offline mode"
                )
            self._write(remaining)
            return dict(target)

    def set_offline(self, ecosystem: str, offline: bool) -> None:
        if ecosystem not in self.offline_files:
            raise ValueError("unknown ecosystem")
        marker = self.offline_files[ecosystem]
        if offline:
            marker.touch(mode=0o600, exist_ok=True)
        else:
            marker.unlink(missing_ok=True)

    def offline(self, ecosystem: str) -> bool:
        if ecosystem not in self.offline_files:
            raise ValueError("unknown ecosystem")
        return self.offline_files[ecosystem].exists()
