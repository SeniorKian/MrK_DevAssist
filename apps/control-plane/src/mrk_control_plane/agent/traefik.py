"""Traefik dynamic-config file for MRK domains (docs/35 §2, routing mode ``traefik_file``).

The agent owns exactly one file, ``<dynamic dir>/mrk-domains.yml``, in Dokploy's
Traefik file-provider directory (``/etc/dokploy/traefik/dynamic`` on the host,
watched by Traefik). It never reads, lists or touches any other file there
(Dokploy keeps ``acme.json`` and its own router files in the same folder).

The caller (control plane) never sends YAML. It sends a small structured JSON
document; this module validates every field against fixed rules and renders
the file itself. The rendered file is JSON, which is valid YAML 1.2 and is what
Traefik's YAML parser reads, so no YAML library or escaping rules are involved.

Payload::

    {"target_host": "mrk-mirror",
     "entrypoints": {"web": "web", "websecure": "websecure"},
     "cert_resolver": "letsencrypt",
     "redirect_middleware": "redirect-to-https@file",
     "services": [{"service": "panel", "hosts": ["mrk.example.com"], "https": true}]}

Ports are fixed per service (panel 8080, npm 4873, pypi 3141, s3 9000). The fifth
id, ``dns-doh`` (docs/40 §5: plain DoH of the DNS engine, which runs on the host
network), may carry its own ``target_host`` (an IPv4 address) and ``port``
(1024..65535, default 8053); no other service may.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any

FILE_NAME = "mrk-domains.yml"
SERVICE_PORTS: dict[str, int] = {"panel": 8080, "npm": 4873, "pypi": 3141, "s3": 9000,
                                 "dns-doh": 8053}
OWN_TARGET_SERVICES = frozenset({"dns-doh"})
MAX_HOSTS = 200
MAX_FILE_BYTES = 256 * 1024
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOST_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})+$")
TARGET_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
MIDDLEWARE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}(@[a-z]{1,16})?$")
HEADER = (
    "# Managed by MRK DevAssist (Host Agent). Do not edit: the panel rewrites this file.\n"
    "# JSON is valid YAML; Traefik reads it as a dynamic configuration.\n"
)


class TraefikPayloadError(ValueError):
    pass


def resolve_dir() -> Path | None:
    """The opt-in dynamic directory (``MRK_AGENT_TRAEFIK_DYNAMIC_DIR``), or None."""
    raw = os.getenv("MRK_AGENT_TRAEFIK_DYNAMIC_DIR", "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        return None
    return path


def _ipv4(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(ipaddress.IPv4Address(value)) == value
    except ValueError:
        return False


def _name(value: Any, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise TraefikPayloadError(f"invalid {field}")
    return value


def validate_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise TraefikPayloadError("payload must be an object")
    unknown = set(payload) - {
        "target_host",
        "entrypoints",
        "cert_resolver",
        "redirect_middleware",
        "services",
    }
    if unknown:
        raise TraefikPayloadError("unknown field")
    target = _name(payload.get("target_host"), "target_host", TARGET_RE)
    entrypoints = payload.get("entrypoints") or {}
    if not isinstance(entrypoints, dict) or set(entrypoints) - {"web", "websecure"}:
        raise TraefikPayloadError("invalid entrypoints")
    web = _name(entrypoints.get("web", "web"), "entrypoints.web", NAME_RE)
    websecure = _name(entrypoints.get("websecure", "websecure"), "entrypoints.websecure", NAME_RE)
    resolver = _name(payload.get("cert_resolver", "letsencrypt"), "cert_resolver", NAME_RE)
    redirect = payload.get("redirect_middleware")
    if redirect is not None:
        redirect = _name(redirect, "redirect_middleware", MIDDLEWARE_RE)
    services = payload.get("services")
    if not isinstance(services, list) or len(services) > len(SERVICE_PORTS):
        raise TraefikPayloadError("invalid services")
    seen_services: set[str] = set()
    seen_hosts: set[str] = set()
    clean: list[dict[str, Any]] = []
    for item in services:
        if not isinstance(item, dict) or set(item) - {
            "service", "hosts", "https", "target_host", "port"
        }:
            raise TraefikPayloadError("invalid service entry")
        service = item.get("service")
        if service not in SERVICE_PORTS or service in seen_services:
            raise TraefikPayloadError("invalid service id")
        own_target = item.get("target_host")
        own_port = item.get("port")
        if service not in OWN_TARGET_SERVICES and (own_target is not None or own_port is not None):
            raise TraefikPayloadError("invalid service entry")
        if own_target is not None and not _ipv4(own_target):
            raise TraefikPayloadError("invalid target_host")
        if own_port is not None and (
            isinstance(own_port, bool) or not isinstance(own_port, int)
            or not 1024 <= own_port <= 65535
        ):
            raise TraefikPayloadError("invalid port")
        seen_services.add(service)
        hosts = item.get("hosts")
        if not isinstance(hosts, list) or not hosts or len(hosts) > MAX_HOSTS:
            raise TraefikPayloadError("invalid hosts")
        normalized: list[str] = []
        for host in hosts:
            if not isinstance(host, str) or not HOST_RE.fullmatch(host) or host in seen_hosts:
                raise TraefikPayloadError("invalid host")
            seen_hosts.add(host)
            normalized.append(host)
        https = item.get("https", True)
        if not isinstance(https, bool):
            raise TraefikPayloadError("invalid https flag")
        entry: dict[str, Any] = {"service": service, "hosts": normalized, "https": https}
        if service in OWN_TARGET_SERVICES:
            entry["target_host"] = own_target
            entry["port"] = own_port or SERVICE_PORTS[service]
        clean.append(entry)
    return {
        "target_host": target,
        "web": web,
        "websecure": websecure,
        "cert_resolver": resolver,
        "redirect_middleware": redirect,
        "services": clean,
    }


def _rule(hosts: list[str]) -> str:
    return " || ".join(f"Host(`{host}`)" for host in hosts)


def render(payload: Any) -> str:
    """Validate the structured payload and return the file text (JSON-as-YAML)."""
    data = validate_payload(payload)
    routers: dict[str, Any] = {}
    services: dict[str, Any] = {}
    middlewares: dict[str, Any] = {}
    for item in data["services"]:
        service = item["service"]
        backend = f"mrk-{service}"
        services[backend] = {
            "loadBalancer": {
                "servers": [{"url": f"http://{item.get('target_host') or data['target_host']}:"
                                    f"{item.get('port') or SERVICE_PORTS[service]}"}],
                "passHostHeader": True,
            }
        }
        # PyPI: one router per host so devpi builds links for the host it was
        # reached on (X-Outside-Url wins over --outside-url in devpi).
        groups: list[tuple[str, list[str], list[str]]] = []
        if service == "pypi":
            for index, host in enumerate(item["hosts"]):
                scheme = "https" if item["https"] else "http"
                header = f"mrk-pypi-outside-{index}"
                middlewares[header] = {
                    "headers": {"customRequestHeaders": {"X-Outside-Url": f"{scheme}://{host}"}}
                }
                groups.append((f"mrk-pypi-{index}", [host], [header]))
        else:
            groups.append((backend, item["hosts"], []))
        for name, hosts, extra in groups:
            rule = _rule(hosts)
            if item["https"]:
                secure: dict[str, Any] = {
                    "rule": rule,
                    "entryPoints": [data["websecure"]],
                    "service": backend,
                    "tls": {"certResolver": data["cert_resolver"]},
                }
                if extra:
                    secure["middlewares"] = list(extra)
                routers[f"{name}-websecure"] = secure
                plain: dict[str, Any] = {
                    "rule": rule,
                    "entryPoints": [data["web"]],
                    "service": backend,
                }
                if data["redirect_middleware"]:
                    plain["middlewares"] = [data["redirect_middleware"]]
                elif extra:
                    plain["middlewares"] = list(extra)
                routers[f"{name}-web"] = plain
            else:
                router: dict[str, Any] = {
                    "rule": rule,
                    "entryPoints": [data["web"]],
                    "service": backend,
                }
                if extra:
                    router["middlewares"] = list(extra)
                routers[f"{name}-web"] = router
    document: dict[str, Any] = {"http": {"routers": routers, "services": services}}
    if middlewares:
        document["http"]["middlewares"] = middlewares
    text = HEADER + json.dumps(document, indent=2, sort_keys=True) + "\n"
    if len(text.encode()) > MAX_FILE_BYTES:
        raise TraefikPayloadError("configuration too large")
    # Round-trip check: the body must parse back to exactly what was rendered.
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    if json.loads(body) != document:  # pragma: no cover - defensive
        raise TraefikPayloadError("render check failed")
    return text


def target_path(directory: Path) -> Path:
    return directory / FILE_NAME


def status(directory: Path | None) -> dict[str, Any]:
    if directory is None:
        return {"configured": False, "writable": False, "file_present": False}
    present = False
    writable = False
    try:
        present = target_path(directory).is_file()
        writable = directory.is_dir() and os.access(directory, os.W_OK)
    except OSError:
        pass
    return {"configured": True, "writable": writable, "file_present": present}


def write(directory: Path, text: str) -> None:
    """Atomically replace only ``mrk-domains.yml`` (same-directory temp + rename)."""
    if not directory.is_dir() or directory.is_symlink():
        raise OSError("dynamic directory is not available")
    target = target_path(directory)
    if target.is_symlink():
        raise OSError("refusing to replace a symlink")
    # A dot-prefixed temp name without the .yml suffix is ignored by Traefik.
    temporary = directory / f".mrk-domains.{secrets.token_hex(6)}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def delete(directory: Path) -> bool:
    target = target_path(directory)
    if target.is_symlink():
        raise OSError("refusing to remove a symlink")
    if not target.exists():
        return False
    target.unlink()
    return True
