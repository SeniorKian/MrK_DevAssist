"""Docker/OCI image registry (Zot) added from the add-service wizard (docs/46).

Zot runs in its own container (``mrk-registry``). It is both a private registry
(push/pull with users the panel creates) and an on-demand mirror of Docker Hub,
ghcr.io, quay.io and registry.k8s.io, each with an ordered list of upstream URLs
that Zot tries in turn (so a domestic mirror can back up Docker Hub).

The panel owns the configuration. It writes ``config.json`` and ``htpasswd``
into the volume it shares with Zot (``mrk-registry-config``: ``<data>/registry``
here, ``/etc/zot`` there, read-only). Zot watches both files and reloads them,
so settings and users change without a restart.

The panel itself talks to Zot as the admin user ``mrk-panel`` (random password,
kept in the SecretStore) for status, the image list and tags.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from ..module_context import ModuleContext

STATE_FILE = "registry.json"
PANEL_USER = "mrk-panel"
PANEL_SECRET_REF = "registry-panel"  # noqa: S105 - SecretStore reference, not a secret
DEFAULT_URL = "http://mrk-registry:5000"
CONTAINER_CONFIG_DIR = "/etc/zot"
_USER = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_UPSTREAM_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
_DESTINATION = re.compile(r"^/(?:[a-z0-9][a-z0-9._-]{0,62}(?:/[a-z0-9][a-z0-9._-]{0,62})*)?$")
_REPO = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$")
MAX_UPSTREAMS = 12
MAX_URLS = 6
MAX_USERS = 200

# Docker Hub is last: its destination is the registry root, which is what
# Docker's "registry-mirrors" setting expects, and every other mirror has a
# more specific prefix.
DEFAULT_UPSTREAMS: tuple[dict[str, Any], ...] = (
    {"id": "ghcr.io", "name": "GitHub Container Registry", "destination": "/ghcr.io",
     "urls": ["https://ghcr.io"], "enabled": True},
    {"id": "quay.io", "name": "Quay", "destination": "/quay.io",
     "urls": ["https://quay.io"], "enabled": True},
    {"id": "registry.k8s.io", "name": "Kubernetes", "destination": "/registry.k8s.io",
     "urls": ["https://registry.k8s.io"], "enabled": True},
    {"id": "docker.io", "name": "Docker Hub", "destination": "/",
     "urls": ["https://registry-1.docker.io", "https://mirror.gcr.io"], "enabled": True},
)

# Tests replace this with a factory returning e.g. httpx.MockTransport(fake_zot).
TRANSPORT_FACTORY: Any = None
ACTIVE_SERVICE: RegistryService | None = None


class RegistryError(Exception):
    def __init__(self, code: str, status_code: int, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.extra = extra


def _hash(password: str) -> str:
    import bcrypt  # bcrypt is the only htpasswd hash Zot accepts

    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("ascii")


def _atomic_write(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def validate_settings(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RegistryError("validation_error", 422, "settings must be an object")
    anonymous = payload.get("anonymous_pull", False)
    if not isinstance(anonymous, bool):
        raise RegistryError("validation_error", 422, "anonymous_pull must be true or false",
                            fields=[{"field": "anonymous_pull", "reason_code": "invalid"}])
    raw = payload.get("upstreams", [])
    if not isinstance(raw, list) or len(raw) > MAX_UPSTREAMS:
        raise RegistryError("validation_error", 422, "upstreams must be a short list",
                            fields=[{"field": "upstreams", "reason_code": "invalid"}])
    upstreams: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_destinations: set[str] = set()
    for index, item in enumerate(raw):
        field = f"upstreams.{index}"
        if not isinstance(item, dict):
            raise RegistryError("validation_error", 422, "invalid upstream",
                                fields=[{"field": field, "reason_code": "invalid"}])
        upstream_id = str(item.get("id", "")).strip().lower()
        destination = str(item.get("destination", "")).strip()
        name = str(item.get("name", upstream_id)).strip()[:80] or upstream_id
        urls = item.get("urls")
        if not _UPSTREAM_ID.match(upstream_id) or upstream_id in seen_ids:
            raise RegistryError("validation_error", 422, "invalid or duplicate upstream id",
                                fields=[{"field": f"{field}.id", "reason_code": "invalid"}])
        if not _DESTINATION.match(destination) or destination in seen_destinations:
            raise RegistryError(
                "validation_error", 422, "invalid or duplicate destination",
                fields=[{"field": f"{field}.destination", "reason_code": "invalid"}])
        if not isinstance(urls, list) or not 1 <= len(urls) <= MAX_URLS:
            raise RegistryError("validation_error", 422, "each upstream needs 1-6 URLs",
                                fields=[{"field": f"{field}.urls", "reason_code": "invalid"}])
        clean_urls = []
        for url in urls:
            text = str(url).strip().rstrip("/")
            parts = urlsplit(text)
            if (parts.scheme != "https" or not parts.hostname or parts.username
                    or parts.password or parts.query or parts.fragment
                    or parts.path not in {"", "/"} or any(ch.isspace() for ch in text)):
                raise RegistryError("validation_error", 422, "upstream URLs must be https://host",
                                    fields=[{"field": f"{field}.urls", "reason_code": "invalid"}])
            clean_urls.append(text)
        seen_ids.add(upstream_id)
        seen_destinations.add(destination)
        upstreams.append({"id": upstream_id, "name": name, "destination": destination,
                          "urls": clean_urls, "enabled": item.get("enabled", True) is True})
    # The root mirror goes last so the specific prefixes are matched first.
    upstreams.sort(key=lambda entry: entry["destination"] == "/")
    return {"anonymous_pull": anonymous, "upstreams": upstreams}


def render_config(settings: dict[str, Any], users: list[dict[str, Any]]) -> dict[str, Any]:
    """Zot's config.json (paths are the Zot container's own view)."""
    pushers = sorted(user["name"] for user in users if user.get("access") == "push")
    pullers = sorted(user["name"] for user in users if user.get("access") == "pull")
    policies = []
    if pushers:
        policies.append({"users": pushers, "actions": ["read", "create", "update"]})
    if pullers:
        policies.append({"users": pullers, "actions": ["read"]})
    repository: dict[str, Any] = {"policies": policies, "defaultPolicy": []}
    if settings.get("anonymous_pull"):
        repository["anonymousPolicy"] = ["read"]
    registries = [
        {
            "urls": upstream["urls"],
            "onDemand": True,
            "tlsVerify": True,
            "maxRetries": 3,
            "retryDelay": "30s",
            "content": [{"prefix": "**", "destination": upstream["destination"]}],
        }
        for upstream in settings.get("upstreams", [])
        if upstream.get("enabled")
    ]
    config: dict[str, Any] = {
        "distSpecVersion": "1.1.1",
        "storage": {
            "rootDirectory": "/var/lib/registry",
            "dedupe": True,
            "gc": True,
            "gcDelay": "1h",
            "gcInterval": "24h",
        },
        "http": {
            "address": "0.0.0.0",  # noqa: S104 - inside its container; published by Compose
            "port": "5000",
            "realm": "MrK DevAssist",
            "compat": ["docker2s2"],
            "auth": {
                "htpasswd": {"path": f"{CONTAINER_CONFIG_DIR}/htpasswd"},
                "failDelay": 1,
            },
            "accessControl": {
                "repositories": {"**": repository},
                "adminPolicy": {
                    "users": [PANEL_USER],
                    "actions": ["read", "create", "update", "delete"],
                },
            },
        },
        "log": {"level": "info"},
        "extensions": {
            "search": {"enable": True},
            "ui": {"enable": True},
        },
    }
    if registries:
        config["extensions"]["sync"] = {"enable": True, "registries": registries}
    return config


class RegistryService:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state_path = ctx.data_dir / "control-plane" / STATE_FILE
        self.config_dir = ctx.data_dir / "registry"
        self.lock = threading.Lock()

    # ------------------------------------------------------------------ state
    def _read(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        payload.setdefault("settings", {"anonymous_pull": False,
                                        "upstreams": [dict(item) for item in DEFAULT_UPSTREAMS]})
        payload.setdefault("users", [])
        return payload

    def _write(self, payload: dict[str, Any]) -> None:
        _atomic_write(self.state_path, json.dumps(payload, sort_keys=True) + "\n", 0o600)

    def connected(self) -> dict[str, Any] | None:
        remote = self._read().get("remote")
        return remote if isinstance(remote, dict) and remote.get("url") else None

    def panel_password(self) -> str:
        try:
            return self.ctx.secret_store.get(PANEL_SECRET_REF)["password"]
        except (KeyError, ValueError):
            password = secrets.token_urlsafe(32)
            self.ctx.secret_store.replace(PANEL_SECRET_REF, {"password": password})
            return password

    # ------------------------------------------------------------------ files
    def write_files(self) -> None:
        """Render config.json and htpasswd into the shared folder (Zot reloads them)."""
        with self.lock:
            state = self._read()
            lines = [f"{PANEL_USER}:{_hash(self.panel_password())}"]
            for user in state["users"]:
                if isinstance(user.get("hash"), str):
                    lines.append(f"{user['name']}:{user['hash']}")
            # htpasswd first: config.json names its users, and Zot reloads each file.
            _atomic_write(self.config_dir / "htpasswd", "\n".join(lines) + "\n", 0o644)
            config = render_config(state["settings"], state["users"])
            _atomic_write(self.config_dir / "config.json",
                          json.dumps(config, indent=2, sort_keys=True) + "\n", 0o644)

    def connect(self, url: str) -> None:
        parts = urlsplit(url.strip())
        if (parts.scheme not in {"http", "https"} or not parts.hostname
                or parts.path not in {"", "/"}):
            raise RegistryError("invalid_url", 422, "Use http://host:port",
                                fields=[{"field": "url", "reason_code": "invalid"}])
        with self.lock:
            state = self._read()
            state["remote"] = {"url": url.strip().rstrip("/"), "connected_at": int(time.time())}
            self._write(state)
        self.write_files()

    # ------------------------------------------------------------------ settings/users
    def get_settings(self) -> dict[str, Any]:
        return self._read()["settings"]

    def put_settings(self, payload: Any) -> dict[str, Any]:
        settings = validate_settings(payload)
        with self.lock:
            state = self._read()
            state["settings"] = settings
            self._write(state)
        self.write_files()
        return settings

    def list_users(self) -> list[dict[str, Any]]:
        return [{"name": user["name"], "access": user["access"],
                 "created_at": user.get("created_at")} for user in self._read()["users"]]

    def create_user(self, name: str, access: str) -> dict[str, Any]:
        name = name.strip().lower()
        if not _USER.match(name) or name == PANEL_USER:
            raise RegistryError("validation_error", 422, "invalid user name",
                                fields=[{"field": "name", "reason_code": "invalid"}])
        if access not in {"pull", "push"}:
            raise RegistryError("validation_error", 422, "access must be pull or push",
                                fields=[{"field": "access", "reason_code": "invalid"}])
        password = secrets.token_urlsafe(24)
        with self.lock:
            state = self._read()
            if any(user["name"] == name for user in state["users"]):
                raise RegistryError("user_exists", 409, "A user with this name exists",
                                    fields=[{"field": "name", "reason_code": "duplicate"}])
            if len(state["users"]) >= MAX_USERS:
                raise RegistryError("too_many_users", 409, "Too many registry users")
            state["users"].append({"name": name, "access": access, "hash": _hash(password),
                                   "created_at": int(time.time())})
            self._write(state)
        self.write_files()
        return {"name": name, "access": access, "password": password}

    def delete_user(self, name: str) -> None:
        with self.lock:
            state = self._read()
            remaining = [user for user in state["users"] if user["name"] != name]
            if len(remaining) == len(state["users"]):
                raise RegistryError("user_not_found", 404, "No such registry user")
            state["users"] = remaining
            self._write(state)
        self.write_files()

    # ------------------------------------------------------------------ Zot API
    def _client(self) -> httpx.AsyncClient:
        transport = TRANSPORT_FACTORY() if TRANSPORT_FACTORY is not None else None
        return httpx.AsyncClient(
            transport=transport, timeout=10.0, trust_env=False, follow_redirects=False,
            auth=(PANEL_USER, self.panel_password()),
        )

    async def _get(self, path: str) -> httpx.Response:
        remote = self.connected()
        if remote is None:
            raise RegistryError("registry_not_connected", 409, "The registry is not added yet")
        async with self._client() as client:
            try:
                return await client.get(f"{remote['url']}{path}")
            except httpx.HTTPError as exc:
                raise RegistryError("registry_unreachable", 503,
                                    "The registry does not answer") from exc

    async def reachable(self) -> bool:
        try:
            response = await self._get("/v2/")
        except RegistryError:
            return False
        return response.status_code == 200

    async def repositories(self) -> list[dict[str, Any]]:
        response = await self._get("/v2/_catalog?n=1000")
        if response.status_code != 200:
            raise RegistryError("registry_error", 502, f"Registry answered {response.status_code}")
        names = response.json().get("repositories") or []
        return [{"name": str(name), "tags": None} for name in names if isinstance(name, str)]

    async def tags(self, name: str) -> dict[str, Any]:
        if not _REPO.match(name) or len(name) > 255:
            raise RegistryError("validation_error", 422, "invalid image name")
        path = "/".join(quote(part, safe="") for part in name.split("/"))
        response = await self._get(f"/v2/{path}/tags/list")
        if response.status_code == 404:
            raise RegistryError("image_not_found", 404, "No such image")
        if response.status_code != 200:
            raise RegistryError("registry_error", 502, f"Registry answered {response.status_code}")
        return {"name": name, "tags": sorted(response.json().get("tags") or [])}

    def endpoint(self) -> str | None:
        """host:port clients use: the wizard's public address, else the local port."""
        try:
            state = json.loads((self.ctx.data_dir / "control-plane" / "install.json")
                               .read_text(encoding="utf-8"))
            env = (state.get("registry") or {}).get("env") or {}
        except (OSError, ValueError, AttributeError):
            env = {}
        public = str(env.get("MRK_REGISTRY_PUBLIC") or "").strip()
        if public:
            return public
        return f"localhost:{env.get('MRK_REGISTRY_PORT') or 5000}" if self.connected() else None


class SettingsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    anonymous_pull: bool = False
    upstreams: list[dict[str, Any]] = Field(default_factory=list, max_length=MAX_UPSTREAMS)


class UserBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=32)
    access: str = Field(pattern=r"^(pull|push)$")


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = RegistryService(ctx)
    ACTIVE_SERVICE = service
    router = APIRouter(prefix="/api/v1/registry", tags=["registry"])

    def failure(exc: RegistryError):
        return ctx.error_payload(exc.code, exc.message, exc.status_code, **exc.extra)  # type: ignore[call-arg]

    def writer(request: Request):
        principal = ctx.require_principal(request, "registry:write")
        ctx.require_csrf(request, principal)
        return principal

    @router.get("/status")
    async def registry_status(request: Request):
        ctx.require_principal(request, "registry:read")
        remote = service.connected()
        return {
            "connected": remote is not None,
            "reachable": await service.reachable() if remote else False,
            "url": remote["url"] if remote else None,
            "public_url": None,
            "endpoint": service.endpoint(),
        }

    @router.get("/settings")
    async def registry_settings(request: Request):
        ctx.require_principal(request, "registry:read")
        return await asyncio.to_thread(service.get_settings)

    @router.put("/settings")
    async def registry_put_settings(request: Request, body: SettingsBody):
        principal = writer(request)
        try:
            result = await asyncio.to_thread(service.put_settings, body.model_dump())
        except RegistryError as exc:
            return failure(exc)
        await asyncio.to_thread(ctx.audit, principal.user_id, "registry.settings.update",
                                "registry", "settings")
        return result

    @router.get("/repos")
    async def registry_repos(request: Request):
        ctx.require_principal(request, "registry:read")
        try:
            return {"items": await service.repositories()}
        except RegistryError as exc:
            return failure(exc)

    @router.get("/repos/{name:path}/tags")
    async def registry_tags(name: str, request: Request):
        ctx.require_principal(request, "registry:read")
        try:
            return await service.tags(name)
        except RegistryError as exc:
            return failure(exc)

    @router.get("/users")
    async def registry_users(request: Request):
        ctx.require_principal(request, "registry:read")
        return {"items": await asyncio.to_thread(service.list_users)}

    @router.post("/users", status_code=201)
    async def registry_create_user(request: Request, body: UserBody):
        principal = writer(request)
        try:
            result = await asyncio.to_thread(service.create_user, body.name, body.access)
        except RegistryError as exc:
            return failure(exc)
        await asyncio.to_thread(ctx.audit, principal.user_id, "registry.user.create",
                                "registry_user", result["name"])
        return result

    @router.delete("/users/{name}")
    async def registry_delete_user(name: str, request: Request):
        principal = writer(request)
        try:
            await asyncio.to_thread(service.delete_user, name)
        except RegistryError as exc:
            return failure(exc)
        await asyncio.to_thread(ctx.audit, principal.user_id, "registry.user.delete",
                                "registry_user", name)
        return {"ok": True}

    @router.get("/help")
    async def registry_help(request: Request):
        ctx.require_principal(request, "registry:read")
        endpoint = service.endpoint() or "registry.example.com"
        return {
            "endpoint": endpoint,
            "docker_login": f"docker login {endpoint}",
            "daemon_mirror_json": json.dumps(
                {"registry-mirrors": [f"https://{endpoint}"]}, indent=2),
            "examples": [
                {"title_fa": "دریافت ایمیج Docker Hub از راه آینه",
                 "title_en": "Pull a Docker Hub image through the mirror",
                 "command": f"docker pull {endpoint}/library/nginx:alpine"},
                {"title_fa": "دریافت ایمیج از ghcr.io",
                 "title_en": "Pull an image from ghcr.io",
                 "command": f"docker pull {endpoint}/ghcr.io/home-assistant/home-assistant:stable"},
                {"title_fa": "فرستادن ایمیج خصوصی",
                 "title_en": "Push a private image",
                 "command": (f"docker tag my-app:1.0 {endpoint}/team/my-app:1.0 && "
                             f"docker push {endpoint}/team/my-app:1.0")},
            ],
        }

    ctx.routers.append(router)
