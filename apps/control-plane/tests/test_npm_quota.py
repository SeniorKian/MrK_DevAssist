"""Pre-publish npm size quota (docs/43 §0.1): the Verdaccio plugin and its wiring.

* ``verdaccio_runtime`` loads ``verdaccio-mrk-quota`` and fails closed without it.
* The plugin logic runs under node (skipped without node).
* A real Verdaccio publish is refused before storage (skipped unless Verdaccio's
  node_modules are found: ``MRK_TEST_VERDACCIO_DIR`` or ``deploy/verdaccio``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from mrk_control_plane.verdaccio_runtime import build_runtime_config

REPO = Path(__file__).resolve().parents[3]
PLUGINS = REPO / "deploy" / "verdaccio" / "plugins"
NODE = shutil.which("node")


def _tenancy(data_dir: Path, quota: int | None) -> None:
    config = data_dir / "npm" / "config"
    config.mkdir(parents=True, exist_ok=True)
    (config / "tenancy.json").write_text(json.dumps({"scopes": [{
        "scope": "@acme", "users": ["pk-acme-1"], "publish": True, "quota_bytes": quota}]}))


def test_runtime_config_loads_the_quota_plugin(tmp_path: Path,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_NPM_PLUGINS_DIR", str(PLUGINS))
    _tenancy(tmp_path, 1000)
    config = build_runtime_config(tmp_path)[0].read_text()
    assert f"plugins: {json.dumps(str(PLUGINS))}" in config
    assert "middlewares:\n  mrk-quota:\n    tenancy_file:" in config
    assert '"@acme/*":\n    access: pk-acme-1\n    publish: pk-acme-1' in config


def test_runtime_config_fails_closed_without_the_plugin(tmp_path: Path,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_NPM_PLUGINS_DIR", str(tmp_path / "missing"))
    _tenancy(tmp_path, 1000)
    config = build_runtime_config(tmp_path)[0].read_text()
    assert "middlewares:" not in config
    assert '"@acme/*":\n    access: pk-acme-1\n    publish: mrk-quarantine-none' in config
    _tenancy(tmp_path, None)  # no limit: nothing to enforce, publishing stays on
    config = build_runtime_config(tmp_path)[0].read_text()
    assert '"@acme/*":\n    access: pk-acme-1\n    publish: pk-acme-1' in config


HARNESS = r"""
const plugin = require(process.argv[2]);
const [tenancyFile, storage] = process.argv.slice(3);
const quota = plugin.createQuota({ tenancyFile, storage });
function run(req) {
  return new Promise((resolve) => {
    const res = { listeners: {}, statusCode: 200, body: null,
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; resolve({ status: this.statusCode, body }); },
      on(name, fn) { this.listeners[name] = fn; } };
    quota.handle({ headers: {}, ...req }, res, () => resolve({ status: "next", res }));
  });
}
const tgz = (n) => ({ data: Buffer.alloc(n, 7).toString("base64") });
(async () => {
  const out = {};
  out.get = (await run({ method: "GET", path: "/@acme%2flib" })).status;
  out.otherScope = (await run({ method: "PUT", path: "/@other%2flib",
    body: { _attachments: { a: tgz(5000) } } })).status;
  out.fits = (await run({ method: "PUT", path: "/@acme%2flib",
    body: { _attachments: { a: tgz(300) } } }));
  out.fits.res.listeners.finish();
  out.fits = out.fits.status;
  out.tooBig = await run({ method: "PUT", path: "/@acme%2flib",
    body: { _attachments: { a: tgz(700) } } });
  out.noTarball = (await run({ method: "PUT", path: "/@acme%2flib/-rev/3-abc",
    body: { versions: {} } })).status;
  const held = await run({ method: "PUT", path: "/@acme/lib",
    body: { _attachments: { a: tgz(300) } } });
  out.parallel = (await run({ method: "PUT", path: "/@acme%2flib",
    body: { _attachments: { a: tgz(400) } } })).status;
  const alone = await run({ method: "PUT", path: "/@acme%2flib",
    body: { _attachments: { a: tgz(300) } } });
  out.alone = alone.status;
  alone.res.listeners.finish();
  held.res.listeners.close();
  out.released = (await run({ method: "PUT", path: "/@acme%2flib",
    body: { _attachments: { a: tgz(400) } } })).status;
  out.raw = (await run({ method: "PUT", path: "/@acme%2flib/-/lib-1.0.0.tgz",
    headers: { "content-length": "900" }, body: Buffer.alloc(0) })).status;
  console.log(JSON.stringify(out));
})();
"""


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_plugin_refuses_over_quota_before_storage(tmp_path: Path) -> None:
    storage = tmp_path / "storage"
    (storage / "@acme" / "lib").mkdir(parents=True)
    (storage / "@acme" / "lib" / "lib-0.9.0.tgz").write_bytes(b"x" * 400)
    tenancy = tmp_path / "tenancy.json"
    tenancy.write_text(json.dumps({"scopes": [{"scope": "@acme", "quota_bytes": 1000},
                                              {"scope": "@other", "quota_bytes": None}]}))
    script = tmp_path / "harness.js"
    script.write_text(HARNESS)
    result = subprocess.run(  # noqa: S603 - fixed arguments
        [str(NODE), str(script), str(PLUGINS / "verdaccio-mrk-quota"), str(tenancy),
         str(storage)], capture_output=True, text=True, timeout=60, check=True)
    out = json.loads(result.stdout)
    assert out["get"] == "next" and out["otherScope"] == "next"
    assert out["fits"] == "next"  # 400 + 300 <= 1000
    assert out["tooBig"]["status"] == 413  # 400 + 700 > 1000
    body = out["tooBig"]["body"]
    assert body["code"] == "quota_exceeded" and body["error"].startswith("quota_exceeded:")
    assert body["used"] == 400 and body["limit"] == 1000
    assert out["noTarball"] == "next"  # unpublish/deprecate never blocked
    assert out["parallel"] == 413  # 400 + 300 in flight + 400 > 1000
    assert out["alone"] == "next"  # 400 + 300 in flight + 300 == 1000 fits
    assert out["released"] == "next"  # the held publish finished: 400 + 400 fits
    assert out["raw"] == 413  # raw tarball upload: Content-Length counts


# ----------------------------------------------------------------------------- real Verdaccio


def _verdaccio_bin() -> Path | None:
    candidates = [os.environ.get("MRK_TEST_VERDACCIO_DIR", ""), str(REPO / "deploy" / "verdaccio"),
                  str(REPO.parents[2] / "deploy" / "verdaccio")]
    for candidate in candidates:
        if candidate:
            script = Path(candidate) / "node_modules" / "verdaccio" / "bin" / "verdaccio"
            if script.is_file():
                return script
    return None


VERDACCIO = _verdaccio_bin()


@pytest.fixture
def verdaccio(tmp_path: Path) -> Iterator[dict[str, object]]:
    assert NODE is not None and VERDACCIO is not None
    storage, tenancy = tmp_path / "storage", tmp_path / "tenancy.json"
    storage.mkdir()
    secret = "pk-acme-secret"  # noqa: S105 - test-only
    digest = base64.b64encode(hashlib.sha1(secret.encode()).digest()).decode()  # noqa: S324
    (tmp_path / "htpasswd").write_text(f"pk-acme-1:{{SHA}}{digest}\n")
    tenancy.write_text(json.dumps({"scopes": [{"scope": "@acme", "quota_bytes": 6000}]}))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config = tmp_path / "config.yaml"
    config.write_text("\n".join([
        f"storage: {json.dumps(str(storage))}",
        f"plugins: {json.dumps(str(PLUGINS))}",
        "middlewares:", "  mrk-quota:", f"    tenancy_file: {json.dumps(str(tenancy))}",
        f"    storage_dir: {json.dumps(str(storage))}",
        "auth:", "  htpasswd:", f"    file: {json.dumps(str(tmp_path / 'htpasswd'))}",
        "    max_users: -1",
        "uplinks: {}", "packages:", "  '@acme/*':", "    access: pk-acme-1",
        "    publish: pk-acme-1", "    unpublish: pk-acme-1",
        "web:", "  enable: false", f"listen: 127.0.0.1:{port}",
        "log:", "  type: stdout", "  format: json", "  level: info", ""]))
    log = (tmp_path / "verdaccio.log").open("w")
    process = subprocess.Popen(  # noqa: S603 - fixed arguments
        [str(NODE), str(VERDACCIO), "--config", str(config)], stdout=log,
        stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                if httpx.get(f"{base}/-/ping", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if process.poll() is not None or time.monotonic() > deadline:
                log.flush()
                pytest.fail("Verdaccio did not start:\n"
                            + (tmp_path / "verdaccio.log").read_text()[-2000:])
            time.sleep(0.3)
        yield {"base": base, "storage": storage, "auth": ("pk-acme-1", secret),
               "log": tmp_path / "verdaccio.log"}
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
        log.close()


def _publish(base: str, auth: tuple[str, str], version: str, size: int) -> httpx.Response:
    tarball = os.urandom(size)
    name = "@acme/lib"
    filename = f"lib-{version}.tgz"
    body = {
        "_id": name, "name": name, "dist-tags": {"latest": version},
        "versions": {version: {
            "name": name, "version": version, "_id": f"{name}@{version}",
            "dist": {"shasum": hashlib.sha1(tarball).hexdigest(),  # noqa: S324
                     "tarball": f"{base}/{name}/-/{filename}"}}},
        "_attachments": {filename: {"content_type": "application/octet-stream",
                                    "data": base64.b64encode(tarball).decode(),
                                    "length": size}},
    }
    return httpx.put(f"{base}/@acme%2flib", json=body, auth=auth, timeout=30)


@pytest.mark.skipif(NODE is None or VERDACCIO is None,
                    reason="Verdaccio is not installed (npm ci in deploy/verdaccio)")
def test_real_verdaccio_publish_over_quota_is_refused(verdaccio: dict[str, object]) -> None:
    base, auth = str(verdaccio["base"]), verdaccio["auth"]
    assert isinstance(auth, tuple)
    log = Path(str(verdaccio["log"])).read_text()
    assert "verdaccio-mrk-quota" in log, log[-2000:]
    first = _publish(base, auth, "1.0.0", 2000)
    assert first.status_code in (200, 201), first.text
    storage = Path(str(verdaccio["storage"])) / "@acme"
    used = sum(path.stat().st_size for path in storage.rglob("*") if path.is_file())
    refused = _publish(base, auth, "2.0.0", 5000)
    assert refused.status_code == 413, refused.text
    assert refused.json()["error"].startswith("quota_exceeded:")
    assert not (storage / "lib" / "lib-2.0.0.tgz").exists()
    assert sum(path.stat().st_size for path in storage.rglob("*") if path.is_file()) == used
    fits = _publish(base, auth, "1.1.0", 500)
    assert fits.status_code in (200, 201), fits.text
