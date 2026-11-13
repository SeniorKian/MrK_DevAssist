"""The DevAssist block inside a Dokploy service's env text (docs/48, layer C).

Pure functions, no I/O. The block sits at the end of the env so its values win
over the same names set earlier (Dokploy parses the text with dotenv semantics:
a later line replaces an earlier one).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

BEGIN = "# >>> DevAssist build mirrors (managed, change it in DevAssist) >>>"
END = "# <<< DevAssist build mirrors <<<"
MAX_ENV_BYTES = 256 * 1024
_KEY = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=")

# Dokploy build types whose builder passes the application env into the build.
ENV_BUILD_TYPES = frozenset({"nixpacks", "railpack", "heroku_buildpacks", "paketo_buildpacks"})
ECOSYSTEMS = ("npm", "pypi")


def _lines(env: str | None) -> list[str]:
    return (env or "").replace("\r\n", "\n").split("\n")


def split_block(env: str | None) -> tuple[list[str], list[str] | None]:
    """(lines outside the block, lines inside it or None when there is no block)."""
    outside: list[str] = []
    inside: list[str] | None = None
    in_block = False
    for line in _lines(env):
        stripped = line.strip()
        if stripped == BEGIN:
            in_block, inside = True, inside if inside is not None else []
            continue
        if stripped == END and in_block:
            in_block = False
            continue
        (inside if in_block and inside is not None else outside).append(line)
    return outside, inside


def keys_of(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in lines:
        match = _KEY.match(line)
        if match and not line.lstrip().startswith("#"):
            values[match.group(1)] = line.split("=", 1)[1].strip()
    return values


def strip_block(env: str | None) -> str:
    outside, _inside = split_block(env)
    while outside and outside[-1].strip() == "":
        outside.pop()
    return "\n".join(outside)


def apply_block(env: str | None, values: dict[str, str]) -> str:
    base = strip_block(env)
    block = [BEGIN, *(f"{key}={value}" for key, value in values.items()), END]
    return (base + "\n\n" if base else "") + "\n".join(block)


def wanted_values(
    npm_url: str | None, pypi_url: str | None, ecosystems: list[str] | tuple[str, ...]
) -> dict[str, str]:
    """The variables for the chosen ecosystems and mirror addresses."""
    values: dict[str, str] = {}
    if "npm" in ecosystems and npm_url:
        values["NPM_CONFIG_REGISTRY"] = npm_url
        values["YARN_NPM_REGISTRY_SERVER"] = npm_url
        host = urlsplit(npm_url)
        if host.scheme == "http" and host.hostname:
            # Yarn 2+ refuses a plain-HTTP registry unless its host is listed.
            values["YARN_UNSAFE_HTTP_WHITELIST"] = host.hostname
    if "pypi" in ecosystems and pypi_url:
        values["PIP_INDEX_URL"] = pypi_url
        values["UV_DEFAULT_INDEX"] = pypi_url
        host = urlsplit(pypi_url)
        if host.scheme == "http" and host.hostname:
            # Plain HTTP: pip and uv refuse it unless the host is marked trusted.
            values["PIP_TRUSTED_HOST"] = host.hostname
            values["UV_INSECURE_HOST"] = host.hostname
    return values


def eligibility(raw: dict[str, Any], service_type: str) -> tuple[bool, str | None]:
    """Can layer C reach this service's build? (eligible, reason when not)."""
    if service_type == "compose":
        return False, "compose_build"
    if service_type != "application":
        return False, "not_buildable"
    if str(raw.get("sourceType") or "") == "docker":
        return False, "no_build"
    build_type = str(raw.get("buildType") or "")
    if build_type in ENV_BUILD_TYPES:
        return True, None
    if build_type in {"dockerfile", "static"}:
        return False, "dockerfile_build"
    return False, "unknown_build_type"


def env_state(env: str | None, wanted: dict[str, str]) -> dict[str, Any]:
    """applied / outdated / missing, plus names also set outside the block."""
    outside, inside = split_block(env)
    current = keys_of(inside) if inside is not None else None
    shadowed = sorted(set(keys_of(outside)) & set(wanted))
    if current is None:
        state = "missing"
    elif current == wanted:
        state = "applied"
    else:
        state = "outdated"
    return {"state": state, "overridden": shadowed, "current": current or {}}
