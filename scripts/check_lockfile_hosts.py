"""Reject npm lockfile ``resolved`` URLs that point outside an allowlist of hosts.

The allowlist comes from ``--allowed-host`` (repeatable) or, if none are given,
from the comma-separated ``NPM_LOCKFILE_ALLOWED_HOSTS`` environment variable,
falling back to ``DEFAULT_ALLOWED_HOSTS``. Only ``https`` URLs are accepted, and
every fetched entry must carry a ``sha512-`` integrity hash.
With no lockfile arguments every ``package-lock.json`` and
``npm-shrinkwrap.json`` under the repository (outside ``node_modules``) is checked.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_ALLOWED_HOSTS = ("registry.npmjs.org", "mirror-npm.rasadyar.net")
ENV_VAR = "NPM_LOCKFILE_ALLOWED_HOSTS"
LOCKFILE_NAMES = ("package-lock.json", "npm-shrinkwrap.json")
REPO_ROOT = Path(__file__).resolve().parents[1]


def _iter_resolved(lock: dict[str, object]) -> Iterator[tuple[str, str, object]]:
    """Yield ``(name, resolved, integrity)`` for every fetched package entry."""
    packages = lock.get("packages")
    if isinstance(packages, dict):
        for name, entry in packages.items():
            if isinstance(entry, dict) and isinstance(entry.get("resolved"), str):
                if entry.get("link") is True:
                    continue
                yield name or "<root>", entry["resolved"], entry.get("integrity")
        return
    # lockfileVersion 1: nested "dependencies" trees.
    stack: list[tuple[str, object]] = [("", lock.get("dependencies"))]
    while stack:
        prefix, deps = stack.pop()
        if not isinstance(deps, dict):
            continue
        for name, entry in deps.items():
            if not isinstance(entry, dict):
                continue
            path = f"{prefix}/{name}" if prefix else name
            if isinstance(entry.get("resolved"), str):
                yield path, entry["resolved"], entry.get("integrity")
            stack.append((path, entry.get("dependencies")))


def check_lockfile(path: Path, allowed: set[str]) -> list[str]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path}: unreadable lockfile: {exc}"]
    problems: list[str] = []
    for name, resolved, integrity in _iter_resolved(lock):
        parts = urlsplit(resolved)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https":
            problems.append(f"{path}: {name}: non-https resolved URL {resolved!r}")
        elif host not in allowed:
            problems.append(f"{path}: {name}: host {host!r} not in allowlist ({resolved})")
        # Without a strong integrity hash npm would install whatever the mirror serves.
        if not (isinstance(integrity, str) and integrity.startswith("sha512-")):
            problems.append(f"{path}: {name}: missing or weak integrity hash ({integrity!r})")
    return problems


def _discover(root: Path) -> list[Path]:
    found: list[Path] = []
    for name in LOCKFILE_NAMES:
        for candidate in root.rglob(name):
            if "node_modules" in candidate.relative_to(root).parts:
                continue
            found.append(candidate)
    return sorted(found)


def _allowed_hosts(cli_hosts: list[str]) -> set[str]:
    if cli_hosts:
        raw = cli_hosts
    elif os.environ.get(ENV_VAR, "").strip():
        raw = os.environ[ENV_VAR].split(",")
    else:
        raw = list(DEFAULT_ALLOWED_HOSTS)
    return {host.strip().lower() for host in raw if host.strip()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("lockfiles", nargs="*", type=Path)
    parser.add_argument("--allowed-host", action="append", default=[], dest="allowed_hosts")
    args = parser.parse_args(argv)

    allowed = _allowed_hosts(args.allowed_hosts)
    lockfiles = args.lockfiles or _discover(REPO_ROOT)
    if not lockfiles:
        print("no npm lockfiles found", file=sys.stderr)
        return 1
    problems: list[str] = []
    for lockfile in lockfiles:
        problems.extend(check_lockfile(lockfile, allowed))
    if problems:
        print("\n".join(problems), file=sys.stderr)
        print(f"{len(problems)} disallowed resolved URL(s)", file=sys.stderr)
        return 1
    print(f"checked {len(lockfiles)} lockfile(s); allowed hosts: {', '.join(sorted(allowed))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
