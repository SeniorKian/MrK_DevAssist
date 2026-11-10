"""End-to-end smoke test of the split stack (docs/44), with real containers.

1. Start the panel from compose.yaml (image MRK_PANEL_IMAGE, built beforehand).
2. Create the owner account and, for each service, ask the wizard for its
   compose.yaml/.env, deploy that stack with `docker compose`, then connect it.
3. Fetch a real npm package through mrk-npm and a real Python package through
   mrk-pypi (which goes through the panel's PyPI router).

Only the standard library is used, so it runs on a bare CI runner.

    python scripts/smoke_split_stack.py --tag ci [--services npm,pypi,s3] [--keep]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = "http://127.0.0.1:{port}"
NODE = (
    "node:24.18.0-trixie-slim"
    "@sha256:ae91dcc111a68c9d2d81ff2a17bda61be126426176fde6fe7d08ab13b7f50573"
)
PYTHON = (
    "python:3.13-slim-trixie"
    "@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)


def sh(*args: str, check: bool = True, env: dict[str, str] | None = None) -> str:
    print("+", " ".join(args), flush=True)
    done = subprocess.run(args, capture_output=True, text=True, env=env, check=False)  # noqa: S603
    if done.stdout.strip():
        print(done.stdout.strip()[-2000:], flush=True)
    if check and done.returncode != 0:
        print(done.stderr.strip()[-4000:], file=sys.stderr, flush=True)
        raise SystemExit(f"command failed ({done.returncode}): {' '.join(args)}")
    return done.stdout


class Panel:
    def __init__(self, base: str) -> None:
        self.base = base
        # The panel's cookies are Secure; keep them by hand so plain http on
        # loopback works (a cookie jar would drop them).
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.cookies: dict[str, str] = {}
        self.csrf = ""

    def _remember(self, headers) -> None:
        for raw in headers.get_all("Set-Cookie") or []:
            name, _, rest = raw.partition("=")
            self.cookies[name.strip()] = rest.split(";", 1)[0]

    def call(self, method: str, path: str, body: object | None = None) -> tuple[int, dict]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(  # noqa: S310 - loopback test URL
            self.base + path, data=data, method=method,
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": self.csrf,
                "Cookie": "; ".join(f"{key}={value}" for key, value in self.cookies.items()),
            },
        )
        try:
            with self.opener.open(request, timeout=60) as response:
                self._remember(response.headers)
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            self._remember(exc.headers)
            return exc.code, json.loads(exc.read() or b"{}")


def wait_until(what: str, check, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                print(f"ok: {what}", flush=True)
                return
        except Exception:  # noqa: BLE001, S110 - retried until the deadline
            pass
        time.sleep(3)
    raise SystemExit(f"timed out: {what}")


def deploy(panel: Panel, service: str, tag: str, registry: str, workdir: Path) -> None:
    status, bundle = panel.call("POST", f"/api/v1/install/{service}/bundle", {})
    assert status == 200, (service, status, bundle)
    folder = workdir / service
    folder.mkdir()
    (folder / "compose.yaml").write_text(bundle["compose"], encoding="utf-8")
    env = re.sub(r"^MRK_IMAGE=.*$", f"MRK_IMAGE={registry}mrk-{service}:{tag}", bundle["env"],
                 flags=re.MULTILINE)
    (folder / ".env").write_text(env, encoding="utf-8")
    sh("docker", "compose", "--project-directory", str(folder), "-p", f"mrk-smoke-{service}",
       "up", "--detach")


def connect(panel: Panel, service: str) -> None:
    def connected() -> bool:
        status, result = panel.call("POST", f"/api/v1/install/{service}/connect", {})
        print(f"  {service}: {status} {result}", flush=True)
        return status == 200 and result.get("connection") == "connected"

    wait_until(f"{service} connected", connected, 600)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", default="ci")
    parser.add_argument("--registry", default="", help="image prefix, e.g. ghcr.io/owner/")
    parser.add_argument("--services", default="npm,pypi")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    services = [item for item in args.services.split(",") if item]
    env = dict(os.environ, MRK_PANEL_IMAGE=f"{args.registry}mrk-panel:{args.tag}",
               MRK_ADMIN_PORT=str(args.port), MRK_IMAGE_TAG=args.tag)
    workdir = Path(tempfile.mkdtemp(prefix="mrk-smoke-"))
    compose = ["docker", "compose", "-f", str(ROOT / "compose.yaml"), "-p", "mrk-smoke-panel"]
    try:
        sh(*compose, "up", "--detach", "--no-build", env=env)
        panel = Panel(PANEL.format(port=args.port))
        wait_until("panel ready", lambda: urllib.request.urlopen(  # noqa: S310
            panel.base + "/health/ready", timeout=5).status == 200, 400)
        password = secrets.token_urlsafe(18)
        status, session = panel.call("POST", "/api/v1/auth/setup", {
            "display_name": "Smoke Owner", "email": "owner@example.test",
            "password": password, "password_confirmation": password})
        assert status == 201, (status, session)
        panel.csrf = session["csrf_token"]

        for service in services:
            deploy(panel, service, args.tag, args.registry, workdir)
        for service in services:
            connect(panel, service)

        if "npm" in services:
            sh("docker", "run", "--rm", "--network", "mrk-net", NODE, "npm", "pack",
               "is-number@7.0.0", "--registry", "http://mrk-npm:4873")
        if "pypi" in services:
            def pypi_bootstrapped() -> bool:
                out = sh("docker", "exec", "mrk-smoke-pypi-mrk-pypi-1", "cat",
                         "/data/pypi/auth/upstream-configured", check=False)
                return "mrk-panel:3142" in out
            wait_until("devpi mirror bootstrapped", pypi_bootstrapped, 300)
            sh("docker", "run", "--rm", "--network", "mrk-net", PYTHON, "python", "-m", "pip",
               "download", "--no-deps", "--dest", "/tmp/pypi", "--index-url",  # noqa: S108
               "http://mrk-pypi:3141/root/pypi/+simple/", "--trusted-host", "mrk-pypi",
               "sampleproject==4.0.0")
        status, view = panel.call("GET", "/api/v1/services")
        states = {item["id"]: item["state"] for item in view.get("items", [])}
        print("services:", states, flush=True)
        bad = [name for name in services if states.get(name) != "running"]
        if bad:
            raise SystemExit(f"not running in the panel: {bad}")
        print("SMOKE OK", flush=True)
        return 0
    finally:
        if not args.keep:
            for service in services:
                folder = workdir / service
                if folder.exists():
                    sh("docker", "compose", "--project-directory", str(folder), "-p",
                       f"mrk-smoke-{service}", "logs", "--tail", "80", check=False)
                    sh("docker", "compose", "--project-directory", str(folder), "-p",
                       f"mrk-smoke-{service}", "down", "--volumes", check=False)
            sh(*compose, "logs", "--tail", "80", check=False, env=env)
            sh(*compose, "down", "--volumes", check=False, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
