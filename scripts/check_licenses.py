from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import sys
import tomllib
from collections import deque
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

APPROVED_LICENSES = {
    "AFL-2.1",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BlueOak-1.0.0",
    "CC0-1.0",
    "ISC",
    "GPL-2.0-or-later",
    "LGPL-3.0-only",
    "LicenseRef-Public-Domain",
    "LicenseRef-Repoze-BSD-derived",
    "MIT",
    "MIT-0",
    "MPL-2.0",
    "OFL-1.1",
    "PSF-2.0",
    "Unlicense",
    "WTFPL",
    "ZPL-2.1",
}
EXPRESSION_WORDS = {"AND", "OR", "WITH"}
LICENSE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
RUNTIME_IMAGE_REQUIREMENTS = (
    "supervisor==4.3.0",
    "setuptools==80.9.0",
    "devpi-server==6.21.0",
    "devpi-web==5.2.0",
    "devpi-client==7.3.0",
)
# These packages publish legacy or full-text metadata instead of an SPDX
# License-Expression. Each override was reviewed against the license file in
# the exact pinned wheel. Changing a version forces a fresh human review.
PYTHON_LICENSE_OVERRIDES = {
    ("beautifulsoup4", "4.15.0"): "MIT",
    ("chameleon", "4.6.0"): "LicenseRef-Repoze-BSD-derived",
    ("colorama", "0.4.6"): "BSD-3-Clause",
    ("comrak", "0.0.16"): "MIT",
    ("defusedxml", "0.7.1"): "PSF-2.0",
    ("devpi-client", "7.3.0"): "MIT",
    ("devpi-common", "4.1.2"): "MIT",
    ("devpi-server", "6.21.0"): "MIT",
    ("devpi-web", "5.2.0"): "MIT",
    ("docutils", "0.23"): (
        "BSD-2-Clause AND GPL-2.0-or-later AND LicenseRef-Public-Domain"
    ),
    ("itsdangerous", "2.2.0"): "BSD-3-Clause",
    ("packaging-legacy", "23.0.post0"): "Apache-2.0 OR BSD-2-Clause",
    ("passlib", "1.7.4"): "BSD-3-Clause",
    ("pkginfo", "2.0"): "MIT",
    ("plaster", "1.1.2"): "MIT",
    ("plaster-pastedeploy", "1.0.1"): "MIT",
    ("py", "1.11.0"): "MIT",
    ("pyramid", "2.1"): "LicenseRef-Repoze-BSD-derived",
    ("pyramid-chameleon", "0.3"): "LicenseRef-Repoze-BSD-derived",
    ("repoze-lru", "0.8"): "LicenseRef-Repoze-BSD-derived",
    ("supervisor", "4.3.0"): "LicenseRef-Repoze-BSD-derived",
    ("translationstring", "1.4"): "LicenseRef-Repoze-BSD-derived",
    ("venusian", "3.1.1"): "LicenseRef-Repoze-BSD-derived",
    ("waitress", "3.0.2"): "ZPL-2.1",
    ("whoosh", "2.7.4"): "BSD-2-Clause",
    ("zope.deprecation", "6.0"): "ZPL-2.1",
    ("zope.interface", "8.7"): "ZPL-2.1",
}


def _license_tokens(expression: str) -> set[str]:
    return {
        token
        for token in LICENSE_TOKEN.findall(expression)
        if token.upper() not in EXPRESSION_WORDS
    }


def _validate_license(expression: str | None) -> list[str]:
    if not expression or not expression.strip():
        return ["missing license metadata"]
    tokens = _license_tokens(expression)
    if not tokens:
        return [f"unparseable license expression: {expression}"]
    unknown = sorted(tokens - APPROVED_LICENSES)
    return [f"unreviewed license token: {item}" for item in unknown]


def _python_runtime_inventory(pyproject: Path) -> list[dict[str, str]]:
    payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    roots = [
        Requirement(item)
        for item in (*payload["project"]["dependencies"], *RUNTIME_IMAGE_REQUIREMENTS)
    ]
    installed = {
        canonicalize_name(dist.metadata["Name"]): dist
        for dist in importlib.metadata.distributions()
        if dist.metadata.get("Name")
    }
    queue: deque[tuple[Requirement, frozenset[str]]] = deque(
        (item, frozenset(item.extras)) for item in roots
    )
    visited: set[str] = set()
    result: list[dict[str, str]] = []
    while queue:
        requirement, requested_extras = queue.popleft()
        name = canonicalize_name(requirement.name)
        if name in visited:
            continue
        distribution = installed.get(name)
        if distribution is None:
            raise RuntimeError(f"required Python distribution is not installed: {requirement.name}")
        visited.add(name)
        override_key = (name, distribution.version)
        expression = PYTHON_LICENSE_OVERRIDES.get(override_key)
        if expression is None:
            expression = (
                distribution.metadata.get("License-Expression")
                or distribution.metadata.get("License")
                or ""
            ).strip()
        result.append(
            {
                "ecosystem": "python",
                "name": distribution.metadata["Name"],
                "version": distribution.version,
                "license": expression,
            }
        )
        marker_extras = requested_extras or frozenset({""})
        for raw_dependency in distribution.requires or []:
            dependency = Requirement(raw_dependency)
            if dependency.marker and not any(
                dependency.marker.evaluate({"extra": extra}) for extra in marker_extras
            ):
                continue
            queue.append((dependency, frozenset(dependency.extras)))
    return sorted(result, key=lambda item: item["name"].lower())


def _npm_inventory(lockfile: Path) -> list[dict[str, str]]:
    payload: dict[str, Any] = json.loads(lockfile.read_text(encoding="utf-8"))
    result: list[dict[str, str]] = []
    for path, package in payload.get("packages", {}).items():
        if not path:
            continue
        name = str(package.get("name") or path.removeprefix("node_modules/"))
        result.append(
            {
                "ecosystem": "npm",
                "name": name,
                "version": str(package.get("version", "")),
                "license": str(package.get("license", "")),
                "source": lockfile.as_posix(),
            }
        )
    return sorted(result, key=lambda item: (item["name"].lower(), item["version"]))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail on missing or unreviewed dependency licenses"
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    inventory = _python_runtime_inventory(root / "apps/control-plane/pyproject.toml")
    for relative in (
        "apps/admin-ui/package-lock.json",
        "deploy/verdaccio/package-lock.json",
        "deploy/pglite/package-lock.json",
    ):
        inventory.extend(_npm_inventory(root / relative))
    findings: list[dict[str, str]] = []
    for package in inventory:
        for problem in _validate_license(package.get("license")):
            findings.append({**package, "problem": problem})
    report = {
        "format": 1,
        "packages": len(inventory),
        "approved_licenses": sorted(APPROVED_LICENSES),
        "findings": findings,
        "inventory": inventory,
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(
        json.dumps(
            {"packages": len(inventory), "findings": len(findings)},
            sort_keys=True,
        )
    )
    if findings:
        for finding in findings:
            print(
                f"{finding['ecosystem']}:{finding['name']}@{finding['version']}: "
                f"{finding['problem']}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
