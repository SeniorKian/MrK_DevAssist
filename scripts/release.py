"""Cut a DevAssist release: one version everywhere, a changelog section, a tag.

    python scripts/release.py 0.2.0            # prepare: files, commit, annotated tag v0.2.0
    python scripts/release.py 0.2.0 --push     # ... and push the commit and the tag
    python scripts/release.py --check          # only verify every file agrees with VERSION

The pushed tag runs .github/workflows/publish-image.yml: every image
ghcr.io/<owner>/mrk-<name> is built, scanned and published as X.Y.Z, X.Y and
latest, and the panel image records X.Y.Z (MRK_IMAGE_TAG) so the add-service
wizard and the panel's update page offer service images of the same release.

VERSION is the single source. This script writes it into:
  apps/control-plane/pyproject.toml          version = "X.Y.Z"
  apps/control-plane/src/mrk_control_plane/__init__.py   __version__
  apps/admin-ui/package.json, package-lock.json (root entries)
  compose.yaml                               default panel image tag (both services)
  CHANGELOG.md                               [Unreleased] -> [X.Y.Z] - date
Only the standard library is used.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
PANEL_IMAGE = re.compile(r"(\$\{MRK_PANEL_IMAGE:-[^:}]+/mrk-panel:)([^}]+)(\})")


def _read(relative: str) -> str:
    return (ROOT / relative).read_bytes().decode("utf-8")


def _write(relative: str, text: str) -> None:
    (ROOT / relative).write_bytes(text.encode("utf-8"))


def current_version() -> str:
    return _read("VERSION").strip()


def versions_found() -> dict[str, str | list[str]]:
    """Every place a version is recorded, as found right now."""
    pyproject = re.search(r'^version = "([^"]+)"', _read("apps/control-plane/pyproject.toml"),
                          re.MULTILINE)
    init = re.search(r'^__version__ = "([^"]+)"',
                     _read("apps/control-plane/src/mrk_control_plane/__init__.py"), re.MULTILINE)
    package = json.loads(_read("apps/admin-ui/package.json"))
    lock = json.loads(_read("apps/admin-ui/package-lock.json"))
    return {
        "VERSION": current_version(),
        "pyproject.toml": pyproject.group(1) if pyproject else "?",
        "__init__.py": init.group(1) if init else "?",
        "package.json": package.get("version", "?"),
        "package-lock.json": lock.get("version", "?"),
        "package-lock.json packages['']": lock.get("packages", {}).get("", {}).get("version", "?"),
        "compose.yaml": [match.group(2) for match in PANEL_IMAGE.finditer(_read("compose.yaml"))],
    }


def check() -> list[str]:
    """Problems: files that do not carry VERSION."""
    found = versions_found()
    version = found["VERSION"]
    problems = []
    if not SEMVER.match(str(version)):
        problems.append(f"VERSION is not X.Y.Z: {version!r}")
    for where, value in found.items():
        if where == "compose.yaml":
            if not value or any(tag != version for tag in value):
                problems.append(f"compose.yaml panel image tags {value} != {version}")
        elif value != version:
            problems.append(f"{where} has {value!r}, VERSION has {version!r}")
    return problems


def bump(version: str) -> None:
    _write("VERSION", version + "\n")
    path = "apps/control-plane/pyproject.toml"
    _write(path, re.sub(r'^version = "[^"]+"', f'version = "{version}"', _read(path),
                        count=1, flags=re.MULTILINE))
    path = "apps/control-plane/src/mrk_control_plane/__init__.py"
    _write(path, re.sub(r'^__version__ = "[^"]+"', f'__version__ = "{version}"', _read(path),
                        count=1, flags=re.MULTILINE))
    # Only the package's own entries (a regex keeps the files' formatting untouched):
    # the top-level "version" of both files and the lockfile's root package entry.
    path = "apps/admin-ui/package.json"
    _write(path, re.sub(r'("version":\s*")[^"]+(")', rf"\g<1>{version}\g<2>", _read(path),
                        count=1))
    path = "apps/admin-ui/package-lock.json"
    text = re.sub(r'("version":\s*")[^"]+(")', rf"\g<1>{version}\g<2>", _read(path), count=1)
    text = re.sub(r'("":\s*\{\s*"name":\s*"@mrk/admin-ui",\s*"version":\s*")[^"]+(")',
                  rf"\g<1>{version}\g<2>", text, count=1)
    _write(path, text)
    _write("compose.yaml", PANEL_IMAGE.sub(rf"\g<1>{version}\g<3>", _read("compose.yaml")))


def changelog(version: str, today: str) -> None:
    text = _read("CHANGELOG.md")
    if "## [Unreleased]" not in text:
        raise SystemExit("CHANGELOG.md has no [Unreleased] section")
    if f"## [{version}]" in text:
        raise SystemExit(f"CHANGELOG.md already has a section for {version}")
    text = text.replace("## [Unreleased]", f"## [Unreleased]\n\n## [{version}] - {today}", 1)
    _write("CHANGELOG.md", text)


def notes(version: str) -> str:
    """The CHANGELOG section of a version (release notes for the GitHub release)."""
    text = _read("CHANGELOG.md")
    match = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text,
                      re.MULTILINE | re.DOTALL)
    return match.group(1).strip() if match else ""


def git(*args: str) -> str:
    done = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)  # noqa: S603, S607
    if done.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {done.stderr.strip()}")
    return done.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("version", nargs="?", help="new version X.Y.Z")
    parser.add_argument("--push", action="store_true", help="push the commit and the tag")
    parser.add_argument("--check", action="store_true", help="only verify the files")
    parser.add_argument("--notes", metavar="X.Y.Z", help="print the changelog section")
    args = parser.parse_args()
    if args.notes:
        print(notes(args.notes))
        return 0
    if args.check:
        problems = check()
        for problem in problems:
            print(problem, file=sys.stderr)
        print("versions agree" if not problems else "versions disagree")
        return 1 if problems else 0
    if not args.version or not SEMVER.match(args.version):
        raise SystemExit("give the new version as X.Y.Z")
    old = tuple(int(part) for part in current_version().split("."))
    new = tuple(int(part) for part in args.version.split("."))
    if new <= old and not (new == old and not git("tag", "--list", f"v{args.version}")):
        raise SystemExit(f"{args.version} is not newer than {current_version()}")
    if git("status", "--porcelain", "--untracked-files=no"):
        raise SystemExit("commit or stash your changes first")
    if git("rev-parse", "--abbrev-ref", "HEAD") != "main":
        raise SystemExit("release from the main branch")
    if git("tag", "--list", f"v{args.version}"):
        raise SystemExit(f"tag v{args.version} already exists")

    bump(args.version)
    changelog(args.version, dt.date.today().isoformat())
    problems = check()
    if problems:
        raise SystemExit("\n".join(problems))
    git("add", "VERSION", "CHANGELOG.md", "compose.yaml", "apps/control-plane/pyproject.toml",
        "apps/control-plane/src/mrk_control_plane/__init__.py",
        "apps/admin-ui/package.json", "apps/admin-ui/package-lock.json")
    git("commit", "-m", f"release: v{args.version}")
    git("tag", "-a", f"v{args.version}", "-m", f"MrK DevAssist {args.version}")
    print(f"prepared v{args.version} (commit + annotated tag)")
    if args.push:
        git("push", "origin", "main")
        git("push", "origin", f"v{args.version}")
        print("pushed; GitHub Actions now publishes the images")
    else:
        print(f"push with: git push origin main && git push origin v{args.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
