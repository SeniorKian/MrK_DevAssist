"""Read-only view of operator package policies for the serving path.

``PackageCatalog`` (catalog.py) owns ``/data/control-plane/package-policies.json``
and writes it atomically. The npm runtime config and the PyPI router only need
to know which names are quarantined, so they read the same file here, cached by
mtime, without importing the catalog's scanning code.
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path

# npm package names: optional @scope/, lowercase URL-safe characters, max 214.
NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
# PEP 508 project names.
PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def policy_file(data_dir: Path) -> Path:
    return data_dir / "control-plane" / "package-policies.json"


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def valid_npm_name(name: str) -> bool:
    return len(name) <= 214 and NPM_NAME.fullmatch(name) is not None


def valid_pypi_name(name: str) -> bool:
    return len(name) <= 200 and PYPI_NAME.fullmatch(name) is not None


def valid_package_name(ecosystem: str, name: str) -> bool:
    if ecosystem == "npm":
        return valid_npm_name(name.strip().lower())
    if ecosystem == "pypi":
        return valid_pypi_name(name.strip())
    return False


def _read_quarantined(path: Path) -> dict[str, frozenset[str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, set[str]] = {"npm": set(), "pypi": set()}
    if not isinstance(payload, dict):
        return {key: frozenset(value) for key, value in result.items()}
    for key, policy in payload.items():
        if not isinstance(key, str) or not isinstance(policy, dict):
            continue
        if policy.get("quarantined") is not True:
            continue
        ecosystem, _, name = key.partition(":")
        if ecosystem == "npm" and valid_npm_name(name):
            result["npm"].add(name)
        elif ecosystem == "pypi" and valid_pypi_name(name):
            result["pypi"].add(pep503(name))
    return {key: frozenset(value) for key, value in result.items()}


def quarantined_names(data_dir: Path, ecosystem: str) -> frozenset[str]:
    """Uncached read (used once per Verdaccio start). Errors mean "none"."""
    try:
        return _read_quarantined(policy_file(data_dir)).get(ecosystem, frozenset())
    except (OSError, ValueError):
        return frozenset()


class QuarantineCache:
    """mtime-cached quarantine set for request paths (PyPI router)."""

    def __init__(self, data_dir: Path | None) -> None:
        self.path = policy_file(data_dir) if data_dir is not None else None
        self._lock = threading.Lock()
        self._state: tuple[float, dict[str, frozenset[str]]] | None = None

    def names(self, ecosystem: str) -> frozenset[str]:
        if self.path is None:
            return frozenset()
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return frozenset()
        with self._lock:
            state = self._state
            if state is None or state[0] != mtime:
                try:
                    parsed = _read_quarantined(self.path)
                except (OSError, ValueError):
                    # Keep the last good view; a half-edited file must not lift
                    # every quarantine at once.
                    parsed = state[1] if state is not None else {}
                state = (mtime, parsed)
                self._state = state
        return state[1].get(ecosystem, frozenset())

    def is_quarantined_pypi(self, project: str) -> bool:
        return pep503(project) in self.names("pypi")
