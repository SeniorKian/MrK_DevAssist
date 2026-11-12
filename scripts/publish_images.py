"""Build every DevAssist image on this machine and push it to a registry.

Used while GitHub publishing is paused (see .github/workflows/publish-image.yml): the
maintainer builds locally, checks, and pushes to the project's own registry, which the
servers (Dokploy) pull from.

    python scripts/publish_images.py --registry registry.example.com/seniorkian
    python scripts/publish_images.py --registry ... --targets panel,agent --no-scan
    python scripts/publish_images.py --registry ... --dry-run

Each image is tagged X.Y.Z (from VERSION), X.Y and latest. Before pushing it is scanned
with Trivy (HIGH/CRITICAL, fixed only) like CI does, unless --no-scan. Sign in once first:

    docker login registry.example.com

Only the standard library is used.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("panel", "agent", "firewall", "dns", "s3", "npm", "pypi")
TRIVY = "aquasec/trivy:0.76.1"
REGISTRY_RE = re.compile(r"^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)*$")


def run(args: list[str], *, dry: bool = False, quiet: bool = False) -> None:
    print("+", " ".join(args), flush=True)
    if dry:
        return
    done = subprocess.run(args, cwd=ROOT, check=False,  # noqa: S603 - fixed docker commands
                          capture_output=quiet, text=True)
    if done.returncode != 0:
        if quiet:
            print((done.stdout or "")[-3000:], (done.stderr or "")[-3000:], file=sys.stderr)
        raise SystemExit(f"command failed ({done.returncode}): {' '.join(args)}")


def git_ref() -> str:
    done = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=ROOT,  # noqa: S607
                          capture_output=True, text=True, check=False)
    return done.stdout.strip() or "local"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--registry", required=True,
                        help="registry host and namespace, e.g. registry.example.com/team")
    parser.add_argument("--targets", default=",".join(TARGETS),
                        help=f"comma-separated subset of {', '.join(TARGETS)}")
    parser.add_argument("--version", help="override VERSION (X.Y.Z)")
    parser.add_argument("--no-scan", action="store_true", help="skip the Trivy scan")
    parser.add_argument("--no-latest", action="store_true", help="do not move X.Y and latest")
    parser.add_argument("--dry-run", action="store_true", help="print the commands only")
    args = parser.parse_args()

    registry = args.registry.strip().rstrip("/").lower()
    if not REGISTRY_RE.match(registry):
        raise SystemExit("--registry must look like registry.example.com/namespace")
    version = (args.version or (ROOT / "VERSION").read_text(encoding="utf-8")).strip()
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise SystemExit(f"version must be X.Y.Z, got {version!r}")
    minor = f"{match.group(1)}.{match.group(2)}"
    targets = [item.strip() for item in args.targets.split(",") if item.strip()]
    unknown = sorted(set(targets) - set(TARGETS))
    if unknown:
        raise SystemExit(f"unknown targets: {', '.join(unknown)}")

    ref = git_ref()
    built: list[tuple[str, str]] = []
    for target in targets:
        local = f"mrk-{target}:{version}"
        run(["docker", "buildx", "build", "--load", "--file", "deploy/images/Dockerfile",
             "--target", target, "--build-arg", f"VCS_REF={ref}",
             "--build-arg", "BUILD_DATE=local", "--build-arg", f"IMAGE_TAG={version}",
             "--tag", local, "."], dry=args.dry_run, quiet=True)
        if not args.no_scan:
            run(["docker", "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock",
                 TRIVY, "image", "--quiet", "--exit-code", "1", "--ignore-unfixed",
                 "--severity", "HIGH,CRITICAL", "--no-progress", local], dry=args.dry_run)
        built.append((target, local))
        print(f"built {local}", flush=True)

    for target, local in built:
        tags = [version] if args.no_latest else [version, minor, "latest"]
        for tag in tags:
            remote = f"{registry}/mrk-{target}:{tag}"
            run(["docker", "tag", local, remote], dry=args.dry_run)
            run(["docker", "push", remote], dry=args.dry_run, quiet=True)
            print(f"pushed {remote}", flush=True)
    print(f"done: {len(built)} image(s) at {registry} ({version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
