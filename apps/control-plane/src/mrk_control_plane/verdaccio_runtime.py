from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path

from .secret_store import SecretStore
from .upstream_store import UpstreamStore

VERDACCIO_BINARY = "/opt/verdaccio/node_modules/.bin/verdaccio"


def _yaml_scalar(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def build_runtime_config(data_dir: Path) -> tuple[Path, dict[str, str]]:
    store = UpstreamStore(data_dir)
    now = int(time.time())
    upstreams = [
        item
        for item in store.raw_list()
        if item.get("ecosystem") == "npm"
        and item.get("enabled") is True
        and (item.get("blocked_until") is None or int(item["blocked_until"]) <= now)
    ]
    if not upstreams and not store.offline("npm"):
        raise RuntimeError("no enabled npm upstream is configured")

    environment = dict(os.environ)
    secret_store = SecretStore(data_dir)
    uplink_names: list[str] = []
    lines = [
        "storage: /data/npm/storage",
        "",
        "auth:",
        "  htpasswd:",
        "    file: /data/npm/auth/htpasswd",
        "    max_users: -1",
        "",
        "uplinks:",
    ]
    if store.offline("npm"):
        lines.append("  {}")
    else:
        for item in upstreams:
            identifier = str(item["id"])
            name = f"mrk_{identifier}"
            uplink_names.append(name)
            lines.extend(
                [
                    f"  {name}:",
                    f"    url: {_yaml_scalar(str(item['url']))}",
                    f"    timeout: {int(item['timeout_seconds'])}s",
                    "    maxage: 5m",
                    "    fail_timeout: 2m",
                    "    max_fails: 1",
                    "    cache: true",
                    "    strict_ssl: true",
                ]
            )
            if item.get("credential_ref"):
                if item.get("credential_type") != "bearer":
                    raise RuntimeError("npm upstream credentials must use bearer tokens")
                value = secret_store.get(str(item["credential_ref"]))
                token = value.get("token")
                if not token:
                    raise RuntimeError("npm upstream bearer token is unavailable")
                env_name = f"MRK_NPM_UPLINK_TOKEN_{identifier.upper()}"
                environment[env_name] = token
                lines.extend(
                    [
                        "    auth:",
                        "      type: bearer",
                        f"      token_env: {env_name}",
                    ]
                )

    proxy = " ".join(uplink_names)
    lines.extend(
        [
            "",
            "packages:",
            "  '@*/*':",
            "    access: $all",
            "    publish: $authenticated",
            "    unpublish: $authenticated",
        ]
    )
    if proxy:
        lines.append(f"    proxy: {proxy}")
    lines.extend(
        [
            "  '**':",
            "    access: $all",
            "    publish: $authenticated",
            "    unpublish: $authenticated",
        ]
    )
    if proxy:
        lines.append(f"    proxy: {proxy}")
    lines.extend(
        [
            "",
            "web:",
            "  enable: false",
            "",
            "security:",
            "  api:",
            "    legacy: false",
            "",
            "server:",
            "  keepAliveTimeout: 60",
            "",
            "listen: 0.0.0.0:4873",
            "",
            "log:",
            "  type: stdout",
            "  format: json",
            "  level: info",
            "",
        ]
    )
    target = data_dir / "npm" / "config" / "generated.yaml"
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_text("\n".join(lines), encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, target)
    return target, environment


def run() -> None:
    data_dir = Path(os.getenv("MRK_DATA_DIR", "/data")).resolve()
    UpstreamStore(data_dir).ensure_defaults(
        os.getenv("MRK_PYPI_PRIMARY_UPSTREAM", "https://pypi.org/simple/"),
        os.getenv(
            "MRK_PYPI_FALLBACK_UPSTREAM",
            "https://package-mirror.liara.ir/repository/pypi/simple/",
        ),
        os.getenv("MRK_NPM_PRIMARY_UPSTREAM", "https://registry.npmjs.org/"),
        os.getenv(
            "MRK_NPM_FALLBACK_UPSTREAM",
            "https://package-mirror.liara.ir/repository/npm/",
        ),
    )
    config, environment = build_runtime_config(data_dir)
    os.execve(  # noqa: S606 - intentional PID handoff to the pinned engine binary
        VERDACCIO_BINARY,
        [VERDACCIO_BINARY, "--config", str(config)],
        environment,
    )


if __name__ == "__main__":
    run()
