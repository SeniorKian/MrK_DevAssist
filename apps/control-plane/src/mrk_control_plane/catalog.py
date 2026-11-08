from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

# Strict names: package names reach filesystem paths, URLs and audit rows.
PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
NPM_NAME = re.compile(r"^(?:@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$")
# Verdaccio keeps legacy mixed-case package directories (e.g. JSONStream).
NPM_STORAGE_NAME = re.compile(NPM_NAME.pattern, re.IGNORECASE)
MAX_NAME_LENGTH = 214
PYPI_FILENAME = re.compile(r"^(?P<name>.+?)-(?P<version>[0-9][A-Za-z0-9.!+_]*)$")
SDIST_SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip")


def normalize_pypi(name: str) -> str:
    """PEP 503 normalized project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def normalize_name(ecosystem: str, name: str) -> str:
    stripped = name.strip()
    if ecosystem == "pypi":
        return normalize_pypi(stripped)
    return stripped.lower()


def valid_name(ecosystem: str, name: str) -> bool:
    if not name or len(name) > MAX_NAME_LENGTH:
        return False
    if ecosystem == "pypi":
        return PYPI_NAME.match(name) is not None
    if ecosystem == "npm":
        return NPM_STORAGE_NAME.match(name) is not None and ".." not in name.split("/")
    return False


def pypi_identity(filename: str) -> tuple[str, str] | None:
    """(normalized project, version) of a wheel or sdist filename."""
    lowered = filename.lower()
    if lowered.endswith(".whl"):
        parts = filename[:-4].split("-")
        if len(parts) < 5:
            return None
        return normalize_pypi(parts[0]), parts[1]
    for suffix in SDIST_SUFFIXES:
        if lowered.endswith(suffix):
            stem = filename[: -len(suffix)]
            break
    else:
        return None
    match = PYPI_FILENAME.match(stem)
    if match is None:
        if "-" not in stem:
            return None
        name, version = stem.rsplit("-", 1)
        return normalize_pypi(name), version
    return normalize_pypi(match.group("name")), match.group("version")


def _cache_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("MRK_CATALOG_CACHE_SECONDS", "30")))
    except ValueError:
        return 30.0


class PackageCatalog:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.pypi_files = data_dir / "pypi" / "server" / "+files"
        self.npm_storage = data_dir / "npm" / "storage"
        self.policy_file = data_dir / "control-plane" / "package-policies.json"
        self.policy_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._scan_lock = threading.Lock()
        self._index: list[dict[str, object]] | None = None
        self._index_at = 0.0

    # -- policies ---------------------------------------------------------
    def _policies(self) -> dict[str, dict[str, object]]:
        if not self.policy_file.is_file():
            return {}
        payload = json.loads(self.policy_file.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return {}
        normalized: dict[str, dict[str, object]] = {}
        for key, value in payload.items():
            ecosystem, _, name = str(key).partition(":")
            if not isinstance(value, dict) or not name:
                continue
            merged = normalized.setdefault(f"{ecosystem}:{normalize_name(ecosystem, name)}", {})
            # Legacy un-normalized duplicates: a pin/quarantine on any spelling wins.
            for flag in ("pinned", "quarantined"):
                if value.get(flag):
                    merged[flag] = True
                else:
                    merged.setdefault(flag, bool(value.get(flag, False)))
            if value.get("quarantine_reason"):
                merged["quarantine_reason"] = value["quarantine_reason"]
            else:
                merged.setdefault("quarantine_reason", None)
        return normalized

    def _write_policies(self, policies: dict[str, dict[str, object]]) -> None:
        temporary = self.policy_file.with_name(
            f".{self.policy_file.name}.{secrets.token_hex(4)}.tmp"
        )
        temporary.write_text(
            json.dumps(policies, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(self.policy_file)

    def policy(self, ecosystem: str, name: str) -> dict[str, object]:
        return dict(self._policies().get(f"{ecosystem}:{normalize_name(ecosystem, name)}", {}))

    def is_quarantined(self, ecosystem: str, name: str) -> bool:
        return bool(self.policy(ecosystem, name).get("quarantined", False))

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
        if not valid_name(ecosystem, name.strip()):
            raise ValueError("invalid package name")
        normalized = normalize_name(ecosystem, name)
        key = f"{ecosystem}:{normalized}"
        with self._lock:
            policies = self._policies()
            policy = policies.setdefault(
                key, {"pinned": False, "quarantined": False, "quarantine_reason": None}
            )
            if pinned is not None:
                policy["pinned"] = pinned
            if quarantined is not None:
                policy["quarantined"] = quarantined
                policy["quarantine_reason"] = quarantine_reason if quarantined else None
            self._write_policies(policies)
            return {"ecosystem": ecosystem, "name": normalized, **policy}

    # -- scanning ---------------------------------------------------------
    def _scan_pypi(self) -> list[dict[str, object]]:
        packages: dict[str, dict[str, object]] = {}
        if not self.pypi_files.is_dir():
            return []
        for directory, dirnames, filenames in os.walk(self.pypi_files):
            dirnames[:] = [
                name for name in dirnames if not os.path.islink(os.path.join(directory, name))
            ]
            for filename in filenames:
                path = os.path.join(directory, filename)
                identity = pypi_identity(filename)
                if identity is None:
                    continue
                try:
                    stat = os.lstat(path)
                except OSError:
                    continue
                name, version = identity
                item = packages.setdefault(
                    name,
                    {
                        "name": name,
                        "ecosystem": "pypi",
                        "versions": set(),
                        "artifact_count": 0,
                        "size_bytes": 0,
                        "latest_mtime": 0.0,
                    },
                )
                item["versions"].add(version)  # type: ignore[union-attr]
                item["artifact_count"] = int(item["artifact_count"]) + 1
                item["size_bytes"] = int(item["size_bytes"]) + stat.st_size
                item["latest_mtime"] = max(float(item["latest_mtime"]), stat.st_mtime)
        return [
            {**item, "versions": sorted(item["versions"], reverse=True)}  # type: ignore[arg-type]
            for item in packages.values()
        ]

    def _npm_package_dirs(self) -> list[tuple[str, Path]]:
        """(relative name, directory) of every Verdaccio package directory.

        Verdaccio stores ``<name>/`` and ``@scope/<name>/``; the directory path,
        not the upstream-controlled ``package.json`` name, identifies a package.
        """
        found: list[tuple[str, Path]] = []
        if not self.npm_storage.is_dir():
            return found
        with os.scandir(self.npm_storage) as top:
            for entry in top:
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    continue
                if entry.name.startswith("@"):
                    with os.scandir(entry.path) as scoped:
                        for child in scoped:
                            if child.is_symlink() or not child.is_dir(follow_symlinks=False):
                                continue
                            found.append((f"{entry.name}/{child.name}", Path(child.path)))
                else:
                    found.append((entry.name, Path(entry.path)))
        return [(name, path) for name, path in found if valid_name("npm", name)]

    def _scan_npm(self) -> list[dict[str, object]]:
        packages: list[dict[str, object]] = []
        for name, directory in self._npm_package_dirs():
            metadata = directory / "package.json"
            if metadata.is_symlink() or not metadata.is_file():
                continue
            try:
                payload = json.loads(metadata.read_text(encoding="utf-8"))
                versions = payload.get("versions", {}) if isinstance(payload, dict) else {}
                artifacts = [
                    entry
                    for entry in os.scandir(directory)
                    if entry.name.endswith(".tgz") and entry.is_file(follow_symlinks=False)
                ]
                size = sum(entry.stat(follow_symlinks=False).st_size for entry in artifacts)
                mtime = metadata.stat().st_mtime
            except (OSError, UnicodeDecodeError, ValueError):
                continue
            packages.append(
                {
                    "name": name,
                    "ecosystem": "npm",
                    "versions": sorted(
                        [str(value) for value in versions if isinstance(value, str)],
                        reverse=True,
                    ),
                    "artifact_count": len(artifacts),
                    "size_bytes": size,
                    "latest_mtime": mtime,
                }
            )
        return packages

    def invalidate(self) -> None:
        with self._scan_lock:
            self._index = None

    def _all(self) -> list[dict[str, object]]:
        with self._scan_lock:
            now = time.monotonic()
            if self._index is None or now - self._index_at > _cache_seconds():
                self._index = self._scan_npm() + self._scan_pypi()
                self._index_at = now
            return list(self._index)

    def all_packages(self, ecosystem: str | None = None) -> list[dict[str, object]]:
        """Every cached package with its policy flags, uncapped."""
        policies = self._policies()
        result: list[dict[str, object]] = []
        for item in self._all():
            if ecosystem and item["ecosystem"] != ecosystem:
                continue
            key = f"{item['ecosystem']}:{normalize_name(str(item['ecosystem']), str(item['name']))}"
            policy = policies.get(key, {})
            result.append(
                {
                    **item,
                    "pinned": bool(policy.get("pinned", False)),
                    "quarantined": bool(policy.get("quarantined", False)),
                    "quarantine_reason": policy.get("quarantine_reason"),
                }
            )
        result.sort(key=lambda item: (str(item["ecosystem"]), str(item["name"]).lower()))
        return result

    def search(
        self, query: str = "", ecosystem: str | None = None, limit: int = 100
    ) -> list[dict[str, object]]:
        normalized_query = query.strip().lower()
        result = [
            item
            for item in self.all_packages(ecosystem)
            if not normalized_query or normalized_query in str(item["name"]).lower()
        ]
        return result[: min(max(limit, 1), 500)]

    def lookup(self, ecosystem: str, name: str) -> dict[str, object]:
        """Exact (normalized) lookup; raises KeyError when the package is not cached."""
        if ecosystem not in {"npm", "pypi"} or not valid_name(ecosystem, name.strip()):
            raise KeyError(name)
        wanted = normalize_name(ecosystem, name)
        for item in self.all_packages(ecosystem):
            if normalize_name(ecosystem, str(item["name"])) == wanted:
                return item
        raise KeyError(name)

    def purge_preview(self, ecosystem: str, name: str) -> dict[str, object]:
        item = self.lookup(ecosystem, name)
        return {
            "ecosystem": ecosystem,
            "name": item["name"],
            "artifact_count": item["artifact_count"],
            "size_bytes": item["size_bytes"],
            "blocked_by_pin": item["pinned"],
            "quarantined": item["quarantined"],
            "recoverable": ecosystem == "npm",
            "confirmation": f"PURGE {ecosystem}/{item['name']}",
        }
