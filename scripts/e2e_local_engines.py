from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORK_ROOT = (PROJECT_ROOT / ".tmp" / "e2e-local-engines").resolve()
PACKAGE_NAME = "mrk-e2e-package"
PACKAGE_VERSION = "1.0.0"


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _run(command: list[str], *, env: dict[str, str] | None = None) -> str:
    # Every executable and argument is constructed internally by this test harness.
    completed = subprocess.run(  # noqa: S603
        command,
        cwd=PROJECT_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
        creationflags=(
            subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        ),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout.strip()


def _spawn(command: list[str], log_path: Path) -> subprocess.Popen[bytes]:
    log = log_path.open("ab")
    try:
        # Every executable and argument is constructed internally by this harness.
        process = subprocess.Popen(  # noqa: S603
            command,
            cwd=PROJECT_ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=(
                subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            ),
        )
    finally:
        log.close()
    return process


def _stop(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def _wait_http(url: str, process: subprocess.Popen[bytes], log_path: Path) -> None:
    deadline = time.monotonic() + 35
    last_error = "not started"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log = log_path.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError(f"engine exited with {process.returncode}:\n{log}")
        try:
            # The caller only supplies loopback HTTP URLs allocated by this harness.
            with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310
                if response.status < 500:
                    return
        except (OSError, urllib.error.URLError) as error:
            last_error = str(error)
        time.sleep(0.25)
    raise TimeoutError(f"engine did not become ready: {url}: {last_error}")


def _create_wheel(destination: Path) -> Path:
    wheel = destination / f"mrk_e2e_package-{PACKAGE_VERSION}-py3-none-any.whl"
    metadata = (
        "Metadata-Version: 2.1\n"
        "Name: mrk-e2e-package\n"
        f"Version: {PACKAGE_VERSION}\n"
        "Summary: MRK isolated engine E2E artifact\n"
        "\n"
    )
    wheel_metadata = (
        "Wheel-Version: 1.0\n"
        "Generator: mrk-e2e-local-engines\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
        "\n"
    )
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("mrk_e2e_package/__init__.py", '__version__ = "1.0.0"\n')
        archive.writestr(
            "mrk_e2e_package-1.0.0.dist-info/METADATA", metadata
        )
        archive.writestr(
            "mrk_e2e_package-1.0.0.dist-info/WHEEL", wheel_metadata
        )
        archive.writestr("mrk_e2e_package-1.0.0.dist-info/RECORD", "")
    return wheel


def _verdaccio_config(run_dir: Path, port: int) -> Path:
    storage_path = run_dir / "data" / "npm" / "storage"
    htpasswd_path = run_dir / "data" / "npm" / "auth" / "htpasswd"
    storage_path.mkdir(parents=True)
    htpasswd_path.parent.mkdir(parents=True)
    storage = storage_path.as_posix()
    htpasswd = htpasswd_path.as_posix()
    config = run_dir / "verdaccio.yaml"
    config.write_text(
        "\n".join(
            [
                f"storage: {json.dumps(storage)}",
                "auth:",
                "  htpasswd:",
                f"    file: {json.dumps(htpasswd)}",
                # Public registration is enabled only in this isolated E2E instance.
                "    max_users: 100",
                "uplinks: {}",
                "packages:",
                "  '@*/*':",
                "    access: $all",
                "    publish: $authenticated",
                "  '**':",
                "    access: $all",
                "    publish: $authenticated",
                "web:",
                "  enable: false",
                "security:",
                "  api:",
                "    legacy: false",
                f"listen: 127.0.0.1:{port}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return config


def _create_verdaccio_user(registry: str) -> tuple[str, str]:
    username = "mrk-e2e"
    password = secrets.token_urlsafe(24)
    body = json.dumps(
        {
            "name": username,
            "password": password,
            "email": "e2e@example.invalid",
            "type": "user",
            "roles": [],
        }
    ).encode()
    request = urllib.request.Request(  # noqa: S310
        f"{registry}-/user/org.couchdb.user:{urllib.parse.quote(username)}",
        data=body,
        method="PUT",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            payload = json.loads(response.read())
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Verdaccio user creation failed with HTTP {error.code}: {detail}"
        ) from error
    token = payload.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError(f"Verdaccio did not issue a token: {payload}")
    return username, password


def _exercise_verdaccio(run_dir: Path) -> dict[str, object]:
    node = shutil.which("node")
    npm = shutil.which("npm")
    entry = (
        PROJECT_ROOT
        / "deploy"
        / "verdaccio"
        / "node_modules"
        / "verdaccio"
        / "bin"
        / "verdaccio"
    )
    if not node or not npm or not entry.is_file():
        raise RuntimeError("Node, npm, and local Verdaccio dependencies are required")
    port = _port()
    registry = f"http://127.0.0.1:{port}/"
    config = _verdaccio_config(run_dir, port)
    log_path = run_dir / "verdaccio.log"
    command = [node, str(entry), "--config", str(config)]
    process: subprocess.Popen[bytes] | None = None
    try:
        process = _spawn(command, log_path)
        _wait_http(f"{registry}-/ping", process, log_path)
        username, password = _create_verdaccio_user(registry)
        package_dir = run_dir / "npm-package"
        package_dir.mkdir()
        (package_dir / "package.json").write_text(
            json.dumps(
                {
                    "name": PACKAGE_NAME,
                    "version": PACKAGE_VERSION,
                    "main": "index.js",
                    "description": "MRK isolated engine E2E artifact",
                }
            ),
            encoding="utf-8",
        )
        (package_dir / "index.js").write_text(
            "module.exports = 'mrk-e2e';\n", encoding="utf-8"
        )
        npmrc = run_dir / ".npmrc"
        basic = base64.b64encode(f"{username}:{password}".encode()).decode()
        npmrc.write_text(
            f"//127.0.0.1:{port}/:_auth={basic}\n"
            f"//127.0.0.1:{port}/:always-auth=true\n"
            f"registry={registry}\n",
            encoding="utf-8",
        )
        npm_env = os.environ.copy()
        npm_env.update(
            {
                "NPM_CONFIG_USERCONFIG": str(npmrc),
                "NPM_CONFIG_CACHE": str(run_dir / "npm-client-cache-first"),
                "NPM_CONFIG_AUDIT": "false",
                "NPM_CONFIG_FUND": "false",
            }
        )
        _run(
            [
                npm,
                "publish",
                str(package_dir),
                "--registry",
                registry,
                "--userconfig",
                str(npmrc),
            ],
            env=npm_env,
        )
        _stop(process)
        process = _spawn(command, log_path)
        _wait_http(f"{registry}-/ping", process, log_path)
        offline_dir = run_dir / "npm-offline-download"
        offline_dir.mkdir()
        npm_env["NPM_CONFIG_CACHE"] = str(run_dir / "npm-client-cache-empty")
        packed = _run(
            [
                npm,
                "pack",
                f"{PACKAGE_NAME}@{PACKAGE_VERSION}",
                "--registry",
                registry,
                "--pack-destination",
                str(offline_dir),
                "--userconfig",
                str(npmrc),
            ],
            env=npm_env,
        )
        artifact = offline_dir / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.tgz"
        if not artifact.is_file():
            raise RuntimeError(f"npm offline artifact is missing; npm output: {packed}")
        return {
            "engine": "verdaccio",
            "publish": "ok",
            "restart": "ok",
            "offline_download": "ok",
            "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        }
    finally:
        _stop(process)


def _devpi_command(name: str) -> str:
    executable = shutil.which(name)
    if executable:
        return executable
    windows = PROJECT_ROOT / ".venv" / "Scripts" / f"{name}.exe"
    if windows.is_file():
        return str(windows)
    raise RuntimeError(f"{name} is not installed")


def _exercise_devpi(run_dir: Path) -> dict[str, object]:
    devpi_init = _devpi_command("devpi-init")
    devpi_server = _devpi_command("devpi-server")
    devpi = _devpi_command("devpi")
    port = _port()
    base_url = f"http://127.0.0.1:{port}"
    server_dir = run_dir / "data" / "pypi" / "server"
    client_dir = run_dir / "devpi-client"
    root_password = secrets.token_urlsafe(24)
    _run(
        [
            devpi_init,
            "--serverdir",
            str(server_dir),
            "--no-root-pypi",
            "--root-passwd",
            root_password,
        ]
    )
    log_path = run_dir / "devpi.log"
    command = [
        devpi_server,
        "--serverdir",
        str(server_dir),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ]
    process: subprocess.Popen[bytes] | None = None
    try:
        process = _spawn(command, log_path)
        _wait_http(f"{base_url}/+status", process, log_path)
        client = [devpi, "--clientdir", str(client_dir)]
        _run([*client, "use", base_url])
        _run([*client, "login", "root", f"--password={root_password}"])
        _run([*client, "index", "-c", "e2e", "bases="])
        _run([*client, "use", "root/e2e"])
        wheel = _create_wheel(run_dir)
        _run([*client, "upload", str(wheel)])
        _stop(process)
        process = _spawn(command, log_path)
        _wait_http(f"{base_url}/+status", process, log_path)
        download_dir = run_dir / "pypi-offline-download"
        download_dir.mkdir()
        pip = [sys.executable, "-m", "pip"]
        _run(
            [
                *pip,
                "download",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--no-deps",
                "--trusted-host",
                "127.0.0.1",
                "--index-url",
                f"{base_url}/root/e2e/+simple/",
                "--dest",
                str(download_dir),
                f"{PACKAGE_NAME}=={PACKAGE_VERSION}",
            ]
        )
        downloaded = next(download_dir.glob("*.whl"), None)
        if downloaded is None:
            raise RuntimeError("pip offline artifact is missing")
        return {
            "engine": "devpi",
            "upload": "ok",
            "restart": "ok",
            "offline_download": "ok",
            "artifact_sha256": hashlib.sha256(downloaded.read_bytes()).hexdigest(),
        }
    finally:
        _stop(process)


def _catalog_result(run_dir: Path) -> dict[str, object]:
    source = PROJECT_ROOT / "apps" / "control-plane" / "src"
    sys.path.insert(0, str(source))
    from mrk_control_plane.catalog import PackageCatalog

    results = PackageCatalog(run_dir / "data").search(PACKAGE_NAME, limit=20)
    ecosystems = {str(item["ecosystem"]) for item in results}
    if ecosystems != {"npm", "pypi"}:
        raise RuntimeError(f"catalog did not discover both ecosystems: {results}")
    return {"catalog": "ok", "ecosystems": sorted(ecosystems)}


def main() -> None:
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    run_dir = (WORK_ROOT / uuid.uuid4().hex).resolve()
    if run_dir.parent != WORK_ROOT:
        raise RuntimeError("unsafe E2E workspace path")
    run_dir.mkdir(mode=0o700)
    keep = os.environ.get("MRK_E2E_KEEP_WORKDIR") == "1"
    try:
        result = {
            "verdaccio": _exercise_verdaccio(run_dir),
            "devpi": _exercise_devpi(run_dir),
            "control_plane": _catalog_result(run_dir),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
    except Exception:
        keep = True
        print(f"E2E workspace retained for diagnosis: {run_dir}", file=sys.stderr)
        raise
    finally:
        if not keep:
            with contextlib.suppress(OSError):
                shutil.rmtree(run_dir)


if __name__ == "__main__":
    main()
