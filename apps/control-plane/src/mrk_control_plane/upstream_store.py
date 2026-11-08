from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from .netresolve import upstream_address_allowed
from .outbound import validate_reference

# LAN-style names; allowed only with the allow_private_upstreams setting.
_LOCAL_SUFFIXES = (".local", ".internal", ".lan", ".home.arpa", ".intranet")


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
    def validate_url(value: str, allow_private: bool = False) -> str:
        """Check an upstream URL.

        ``allow_private`` is the operator's ``allow_private_upstreams`` setting:
        it admits RFC1918/ULA/CGNAT addresses and LAN-style names (nexus.lan,
        single-label hosts). Loopback, link-local/metadata and ``localhost``
        stay forbidden either way.
        """
        parsed = urlsplit(value.strip())
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("upstream URL must be HTTPS")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("credentials, query strings and fragments are forbidden")
        hostname = parsed.hostname.lower().rstrip(".")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None
        if address is None and hostname[:1].isdigit():
            # Shorthand IPv4 forms ("127.1", "2130706433", "0x7f.1") are not IP
            # literals to ipaddress, but every resolver (and Node) maps them to IPs.
            try:
                address = ipaddress.IPv4Address(socket.inet_aton(hostname))
            except OSError:
                address = None
        if address is not None and not upstream_address_allowed(str(address), allow_private):
            raise ValueError("private and local upstream addresses are forbidden")
        if address is None and (hostname == "localhost" or hostname.endswith(".localhost")):
            raise ValueError("private and local upstream addresses are forbidden")
        if (
            address is None
            and not allow_private
            and ("." not in hostname or hostname.endswith(_LOCAL_SUFFIXES))
        ):
            # Verdaccio fetches npm uplinks itself, without the router's
            # resolved-address check, so obviously-internal names stop here.
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
            # Seed each ecosystem only once. Matching by name alone brought back
            # (enabled) any default the operator had deleted or renamed.
            seeded_marker = self.root / "upstream-defaults-seeded.json"
            try:
                seeded = set(json.loads(seeded_marker.read_text(encoding="utf-8")))
            except (OSError, ValueError, TypeError):
                seeded = set()
            for default in defaults:
                if default["ecosystem"] in seeded:
                    continue
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
            all_ecosystems = {str(item["ecosystem"]) for item in defaults}
            if not all_ecosystems <= seeded:
                temporary = seeded_marker.with_name(f".{seeded_marker.name}.tmp")
                temporary.write_text(json.dumps(sorted(all_ecosystems)), encoding="utf-8")
                temporary.chmod(0o600)
                os.replace(temporary, seeded_marker)

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
        # None = direct, "default" = the default proxy, otherwise a proxy profile id.
        result["proxy_id"] = result.get("proxy_id") or None
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
        allow_private: bool = False,
        proxy_id: str | None = None,
    ) -> dict[str, object]:
        """``proxy_id`` must already be checked against the proxy profiles."""
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
            "url": self.validate_url(url, allow_private),
            "priority": priority,
            "timeout_seconds": timeout_seconds,
            "enabled": True,
            "blocked_until": None,
            "blocked_reason": None,
            "proxy_id": validate_reference(proxy_id),
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

    def update(
        self, upstream_id: str, changes: dict[str, object], allow_private: bool = False
    ) -> dict[str, object]:
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
            "proxy_id",
        }
        if set(changes) - allowed:
            raise ValueError("unsupported upstream field")
        with self._lock:
            items = self._read()
            target = next((item for item in items if item["id"] == upstream_id), None)
            if target is None:
                raise KeyError(upstream_id)
            if "name" in changes:
                normalized_name = str(changes["name"]).strip()
                if not 2 <= len(normalized_name) <= 80:
                    raise ValueError("upstream name must be between 2 and 80 characters")
                if any(
                    item["id"] != upstream_id
                    and item["ecosystem"] == target["ecosystem"]
                    and str(item["name"]).lower() == normalized_name.lower()
                    for item in items
                ):
                    # create() already refused duplicates; a rename must too.
                    raise ValueError("upstream name already exists in this ecosystem")
                changes["name"] = normalized_name
            if "url" in changes:
                changes["url"] = self.validate_url(str(changes["url"]), allow_private)
                old_host = (urlsplit(str(target["url"])).hostname or "").lower()
                new_host = (urlsplit(str(changes["url"])).hostname or "").lower()
                if (
                    old_host != new_host
                    and target.get("credential_ref")
                    and "credential_ref" not in changes
                ):
                    # Otherwise an admin who cannot read the secret could point the
                    # URL at their own host and receive it via a connection test.
                    raise ValueError(
                        "remove the stored credential before moving an upstream to another host"
                    )
            if "proxy_id" in changes:
                changes["proxy_id"] = validate_reference(changes["proxy_id"])
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
            now = int(time.time())
            blocking = changes.get("blocked_until") is not None and int(
                str(changes["blocked_until"])
            ) > now
            if blocking and target.get("enabled") is True:
                # Blocking is the same as disabling for traffic, so it gets the same guard.
                other_usable = any(
                    item["id"] != upstream_id
                    and item["ecosystem"] == target["ecosystem"]
                    and item.get("enabled") is True
                    and (
                        item.get("blocked_until") is None
                        or int(item["blocked_until"]) <= now
                    )
                    for item in items
                )
                if not other_usable and not self.offline(str(target["ecosystem"])):
                    raise ValueError(
                        "the last usable upstream can only be blocked in offline mode"
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
