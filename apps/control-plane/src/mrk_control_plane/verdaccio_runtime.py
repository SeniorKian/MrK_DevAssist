from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path

from .config import apply_startup_overrides
from .netresolve import NetworkSettingsStore
from .outbound import HTTP_PROXY_TYPES, OutboundError, resolve_route
from .package_policy import quarantined_names
from .secret_store import SecretStore
from .upstream_store import UpstreamStore

LOGGER = logging.getLogger(__name__)

VERDACCIO_BINARY = "/opt/verdaccio/node_modules/.bin/verdaccio"
# docs/43 §0.1: pre-publish size quota for workspace scopes (deploy/verdaccio/plugins).
QUOTA_PLUGIN = "verdaccio-mrk-quota"


def plugins_dir() -> Path:
    return Path(os.getenv("MRK_NPM_PLUGINS_DIR", "/opt/verdaccio/plugins"))


def quota_plugin_available() -> bool:
    return (plugins_dir() / QUOTA_PLUGIN / "index.js").is_file()


QUARANTINE_GROUP = "mrk-quarantine-none"
_UPSTREAM_ID = re.compile(r"^[A-Za-z0-9]{1,64}$")


def _is_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def _yaml_scalar(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _proxy_lines(
    item: dict[str, object], network: NetworkSettingsStore, secret_store: SecretStore
) -> list[str]:
    """Per-uplink http(s) proxy for Verdaccio.

    Verdaccio reads proxies only from its config file (or one global env var for
    all uplinks), so credentials end up in generated.yaml, which is mode 0600
    and regenerated on every start. SOCKS is not supported by Verdaccio; such an
    uplink is skipped (never silently connected directly).
    """
    reference = item.get("proxy_id")
    if not reference:
        return []
    route = resolve_route(network, secret_store, str(reference))
    if route is None:  # pragma: no cover - a reference always resolves or raises
        return []
    if route.profile.type not in HTTP_PROXY_TYPES:
        raise OutboundError(
            "proxy_type_unsupported_for_npm", "Verdaccio supports HTTP(S) proxies only"
        )
    lines = [
        f"    http_proxy: {_yaml_scalar(route.url)}",
        f"    https_proxy: {_yaml_scalar(route.url)}",
    ]
    # Verdaccio matches no_proxy by host-name suffix only; IP/CIDR entries are dropped.
    names = [pattern for pattern in route.profile.no_proxy if not _is_network(pattern)]
    if names:
        lines.append(f"    no_proxy: {_yaml_scalar(','.join(names))}")
    return lines


def _uplink_block(
    item: dict[str, object],
    secret_store: SecretStore,
    network: NetworkSettingsStore | None = None,
) -> tuple[list[str], str | None, str | None]:
    identifier = str(item["id"])
    if _UPSTREAM_ID.fullmatch(identifier) is None:
        # The id becomes a YAML key and an environment variable name.
        raise ValueError("npm upstream id is not a safe identifier")
    name = f"mrk_{identifier}"
    block = [
        f"  {name}:",
        f"    url: {_yaml_scalar(str(item['url']))}",
        f"    timeout: {int(str(item['timeout_seconds']))}s",
        "    maxage: 5m",
        "    fail_timeout: 2m",
        "    max_fails: 1",
        "    cache: true",
        "    strict_ssl: true",
    ]
    if network is not None:
        block.extend(_proxy_lines(item, network, secret_store))
    elif item.get("proxy_id"):
        raise OutboundError("proxy_unavailable", "network settings are unavailable")
    if not item.get("credential_ref"):
        return block, None, None
    if item.get("credential_type") != "bearer":
        raise RuntimeError("npm upstream credentials must use bearer tokens")
    value = secret_store.get(str(item["credential_ref"]))
    token = value.get("token")
    if not token:
        raise RuntimeError("npm upstream bearer token is unavailable")
    env_name = f"MRK_NPM_UPLINK_TOKEN_{identifier.upper()}"
    block.extend(["    auth:", "      type: bearer", f"      token_env: {env_name}"])
    return block, env_name, token


def _listen_host() -> str:
    """MRK_NPM_LISTEN_HOST (0.0.0.0 in the container, 127.0.0.1 natively)."""
    raw = os.environ.get("MRK_NPM_LISTEN_HOST", "").strip() or "0.0.0.0"  # noqa: S104
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        LOGGER.warning("MRK_NPM_LISTEN_HOST %r is not an IP address; using 0.0.0.0", raw)
        return "0.0.0.0"  # noqa: S104
    return f"[{address}]" if address.version == 6 else str(address)


_SCOPE = re.compile(r"^@[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$")
_USER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MANAGED_USER_PREFIX = "pk-"


def _tenancy_rules(data_dir: Path) -> tuple[list[dict[str, object]], str]:
    """«My space» npm scopes (docs/43) and who may publish outside them.

    Without workspace scopes nothing changes ($authenticated). With them, workspace
    token users must not publish elsewhere, so the generic rules name the other
    htpasswd users (or nobody).
    """
    try:
        payload = json.loads((data_dir / "npm" / "config" / "tenancy.json").read_text("utf-8"))
    except (OSError, ValueError):
        return [], "$authenticated"
    scopes: list[dict[str, object]] = []
    for item in payload.get("scopes") or [] if isinstance(payload, dict) else []:
        if not isinstance(item, dict) or not _SCOPE.fullmatch(str(item.get("scope", ""))):
            continue
        users = [user for user in item.get("users") or [] if isinstance(user, str)
                 and _USER.fullmatch(user) and user.startswith(MANAGED_USER_PREFIX)]
        quota = item.get("quota_bytes")
        scopes.append({"scope": item["scope"], "users": users,
                       "publish": item.get("publish", True) is True,
                       "quota_bytes": quota if isinstance(quota, int)
                       and not isinstance(quota, bool) and quota >= 0 else None})
    if not scopes:
        return [], "$authenticated"
    others: list[str] = []
    try:
        for line in (data_dir / "npm" / "auth" / "htpasswd").read_text("utf-8").splitlines():
            user = line.split(":", 1)[0].strip()
            if user and _USER.fullmatch(user) and not user.startswith(MANAGED_USER_PREFIX):
                others.append(user)
    except OSError:
        pass
    return scopes, " ".join(others) or QUARANTINE_GROUP


def _quota_plugin_lines(data_dir: Path, container: bool = False) -> list[str]:
    if not (container or quota_plugin_available()):
        return []
    # For the mrk-npm container (docs/44) the paths are the container's own view.
    tenancy_file = (
        "/data/npm/config/tenancy.json" if container
        else str(data_dir / "npm" / "config" / "tenancy.json")
    )
    plugins = "/opt/verdaccio/plugins" if container else str(plugins_dir())
    return [
        f"plugins: {_yaml_scalar(plugins)}",
        "middlewares:",
        "  mrk-quota:",
        f"    tenancy_file: {_yaml_scalar(tenancy_file)}",
        "    storage_dir: /data/npm/storage",
        "",
    ]


def build_runtime_config(
    data_dir: Path, *, container: bool = False
) -> tuple[Path, dict[str, str]]:
    """Render generated.yaml. ``container``: written by the panel for mrk-npm (docs/44)."""
    store = UpstreamStore(data_dir)
    now = int(time.time())
    upstreams = [
        item
        for item in store.raw_list()
        if item.get("ecosystem") == "npm"
        and item.get("enabled") is True
        and (item.get("blocked_until") is None or int(item["blocked_until"]) <= now)
    ]
    # With no usable upstream, serve from cache instead of exiting: an exit
    # would burn supervisor's retries and take the whole npm registry down.
    cache_only = store.offline("npm") or not upstreams
    if cache_only and not store.offline("npm"):
        LOGGER.warning("no usable npm upstream; Verdaccio starts in cache-only mode")

    environment = dict(os.environ)
    secret_store = SecretStore(data_dir)
    network = NetworkSettingsStore(data_dir)
    uplink_names: list[str] = []
    lines = [
        "storage: /data/npm/storage",
        "",
        *_quota_plugin_lines(data_dir, container),
        "auth:",
        "  htpasswd:",
        "    file: /data/npm/auth/htpasswd",
        "    max_users: -1",
        "",
        "uplinks:",
    ]
    uplink_lines: list[str] = []
    if not cache_only:
        for item in upstreams:
            try:
                block, env_name, token = _uplink_block(item, secret_store, network)
            except (KeyError, ValueError, RuntimeError):
                # One broken credential must not stop Verdaccio: the exit would
                # go FATAL and the FATAL listener would stop the whole container.
                LOGGER.exception(
                    "skipping npm uplink with unusable configuration",
                    extra={"upstream_id": str(item.get("id", ""))},
                )
                continue
            uplink_names.append(block[0].strip().rstrip(":"))
            uplink_lines.extend(block)
            if env_name is not None and token is not None:
                environment[env_name] = token
    if uplink_lines:
        lines.extend(uplink_lines)
    else:
        if not cache_only:
            LOGGER.warning("no npm uplink could be configured; Verdaccio starts cache-only")
        lines.append("  {}")

    proxy = " ".join(uplink_names)
    lines.extend(["", "packages:"])
    for package in sorted(quarantined_names(data_dir, "npm")):
        # Quarantined names come first so they win over the wildcard rules:
        # nobody may read them and nothing is fetched from an uplink.
        lines.extend(
            [
                f"  {_yaml_scalar(package)}:",
                f"    access: {QUARANTINE_GROUP}",
                f"    publish: {QUARANTINE_GROUP}",
                f"    unpublish: {QUARANTINE_GROUP}",
            ]
        )
    scopes, generic_publish = _tenancy_rules(data_dir)
    quota_plugin = container or quota_plugin_available()
    for scope in scopes:
        if scope["quota_bytes"] is not None and not quota_plugin:
            # Fail closed: without the quota plugin a single publish could pass the limit.
            LOGGER.error("npm quota plugin missing; publishing to %s is off", scope["scope"])
            scope["publish"] = False
        # docs/43: a workspace's private scope, before the generic rules. Only its
        # token users may read or publish; never fetched from an uplink.
        users = " ".join(scope["users"]) or QUARANTINE_GROUP
        lines.extend(
            [
                f"  {_yaml_scalar(scope['scope'] + '/*')}:",
                f"    access: {users}",
                f"    publish: {users if scope['publish'] else QUARANTINE_GROUP}",
                f"    unpublish: {users}",
            ]
        )
    lines.extend(
        [
            "  '@*/*':",
            "    access: $all",
            f"    publish: {generic_publish}",
            f"    unpublish: {generic_publish}",
        ]
    )
    if proxy:
        lines.append(f"    proxy: {proxy}")
    lines.extend(
        [
            "  '**':",
            "    access: $all",
            f"    publish: {generic_publish}",
            f"    unpublish: {generic_publish}",
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
            f"listen: {_listen_host()}:4873",
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
    apply_startup_overrides()  # panel overrides; explicit env still wins
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
