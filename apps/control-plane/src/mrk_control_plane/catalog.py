from __future__ import annotations

import json
import re
import secrets
import threading
from pathlib import Path

PYPI_FILENAME = re.compile(r"^(?P<name>.+?)-(?P<version>[0-9][A-Za-z0-9.!+_-]*)")


class PackageCatalog:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.pypi_files = data_dir / "pypi" / "server" / "+files"
        self.npm_storage = data_dir / "npm" / "storage"
        self.policy_file = data_dir / "control-plane" / "package-policies.json"
        self.policy_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()

    def _policies(self) -> dict[str, dict[str, object]]:
        if not self.policy_file.is_file():
            return {}
        payload = json.loads(self.policy_file.read_text(encoding="utf-8"))
        return dict(payload) if isinstance(payload, dict) else {}

    def _write_policies(self, policies: dict[str, dict[str, object]]) -> None:
        temporary = self.policy_file.with_name(
            f".{self.policy_file.name}.{secrets.token_hex(4)}.tmp"
        )
        temporary.write_text(
            json.dumps(policies, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(self.policy_file)

    @staticmethod
    def _pypi_identity(filename: str) -> tuple[str, str]:
        stem = filename
        for suffix in (".tar.gz", ".tar.bz2", ".whl", ".zip", ".tgz"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        match = PYPI_FILENAME.match(stem)
        if match is None:
            return stem, "unknown"
        return match.group("name").replace("_", "-"), match.group("version")

    def _scan_pypi(self) -> list[dict[str, object]]:
        packages: dict[str, dict[str, object]] = {}
        if not self.pypi_files.is_dir():
            return []
        for artifact in self.pypi_files.rglob("*"):
            if not artifact.is_file():
                continue
            name, version = self._pypi_identity(artifact.name)
            key = name.lower()
            item = packages.setdefault(
                key,
                {
                    "name": name,
                    "ecosystem": "pypi",
                    "versions": set(),
                    "artifact_count": 0,
                    "size_bytes": 0,
                    "latest_mtime": 0,
                },
            )
            item["versions"].add(version)
            item["artifact_count"] = int(item["artifact_count"]) + 1
            stat = artifact.stat()
            item["size_bytes"] = int(item["size_bytes"]) + stat.st_size
            item["latest_mtime"] = max(float(item["latest_mtime"]), stat.st_mtime)
        return [
            {**item, "versions": sorted(item["versions"], reverse=True)}
            for item in packages.values()
        ]

    def _scan_npm(self) -> list[dict[str, object]]:
        packages: list[dict[str, object]] = []
        if not self.npm_storage.is_dir():
            return packages
        for metadata in self.npm_storage.rglob("package.json"):
            try:
                payload = json.loads(metadata.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            name = str(payload.get("name") or metadata.parent.name)
            versions = payload.get("versions", {})
            artifacts = [path for path in metadata.parent.iterdir() if path.suffix == ".tgz"]
            packages.append(
                {
                    "name": name,
                    "ecosystem": "npm",
                    "versions": sorted(
                        [str(value) for value in versions], reverse=True
                    ),
                    "artifact_count": len(artifacts),
                    "size_bytes": sum(path.stat().st_size for path in artifacts),
                    "latest_mtime": metadata.stat().st_mtime,
                }
            )
        return packages

    def search(
        self, query: str = "", ecosystem: str | None = None, limit: int = 100
    ) -> list[dict[str, object]]:
        normalized_query = query.strip().lower()
        packages = self._scan_npm() + self._scan_pypi()
        policies = self._policies()
        result: list[dict[str, object]] = []
        for item in packages:
            if ecosystem and item["ecosystem"] != ecosystem:
                continue
            if normalized_query and normalized_query not in str(item["name"]).lower():
                continue
            policy = policies.get(f"{item['ecosystem']}:{str(item['name']).lower()}", {})
            result.append(
                {
                    **item,
                    "pinned": bool(policy.get("pinned", False)),
                    "quarantined": bool(policy.get("quarantined", False)),
                    "quarantine_reason": policy.get("quarantine_reason"),
                }
            )
        result.sort(key=lambda item: (str(item["ecosystem"]), str(item["name"]).lower()))
        return result[: min(max(limit, 1), 500)]

    def set_policy(
        self,
        ecosystem: str,
        name: str,
        pinned: bool | None = None,
        quarantined: bool | None = None,
        quarantine_reason: str | None = None,
    ) -> dict[str, object]:
        if ecosystem not in {"npm", "pypi"}:
            raise ValueError("unknown ecosystem")
        key = f"{ecosystem}:{name.strip().lower()}"
        with self._lock:
            policies = self._policies()
            policy = policies.setdefault(key, {})
            if pinned is not None:
                policy["pinned"] = pinned
            if quarantined is not None:
                policy["quarantined"] = quarantined
                policy["quarantine_reason"] = quarantine_reason if quarantined else None
            self._write_policies(policies)
            return {"ecosystem": ecosystem, "name": name, **policy}

    def purge_preview(self, ecosystem: str, name: str) -> dict[str, object]:
        item = next(
            (
                value
                for value in self.search(name, ecosystem, 500)
                if str(value["name"]).lower() == name.lower()
            ),
            None,
        )
        if item is None:
            raise KeyError(name)
        return {
            "ecosystem": ecosystem,
            "name": item["name"],
            "artifact_count": item["artifact_count"],
            "size_bytes": item["size_bytes"],
            "blocked_by_pin": item["pinned"],
            "confirmation": f"PURGE {ecosystem}/{item['name']}",
        }
