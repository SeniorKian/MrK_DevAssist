"""«My space» private packages (docs/43 §3): npm scope ``@<slug>`` and devpi ``<slug>/dev``.

npm (Verdaccio): every publish token is an htpasswd user ``pk-<slug>-<hex>`` (SHA1 of a
random 256-bit token — fine for random secrets). ``npm/config/tenancy.json`` lists each
workspace scope with its users; ``verdaccio_runtime`` turns it into a package rule
``'@<slug>/*'`` (access/publish only those users, no uplink) before the generic rules,
and narrows the generic publish rules to non-workspace users.

PyPI (devpi): the control plane acts as devpi ``root`` (``--restrict-modify root``): it
creates user ``<slug>`` with index ``<slug>/dev`` (bases ``root/pypi``) and one devpi
user ``<slug>-t<hex>`` per token, listed in the index ``acl_upload``.

Size quotas (``npm_bytes``/``pypi_bytes``) are checked after the fact: once a workspace is
at or over its limit, publishing is switched off for it until it deletes versions.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ..catalog import PYPI_NAME, normalize_pypi
from ..models import ServiceDomain
from ..process_control import reload_verdaccio_best_effort
from ..tenancy import TenancyError, WorkspaceContext, not_found

if TYPE_CHECKING:
    from .tenancy import MySpace

LOGGER = logging.getLogger(__name__)
ECOSYSTEMS = ("npm", "pypi")
MANAGED_PREFIX = "pk-"
_NPM_PACKAGE = re.compile(r"^[a-z0-9-~][a-z0-9-._~]{0,200}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_!-]{0,63}$")
_TOKEN_NAME = re.compile(r"^.{3,80}$")
MAX_TOKENS = 20

# Replaced in tests: the transport used to reach devpi.
TRANSPORT_FACTORY: Callable[[], httpx.AsyncBaseTransport | None] = lambda: None  # noqa: E731
# Replaced in tests: Verdaccio reload after a config change.
RELOAD_NPM: Callable[[], bool] = reload_verdaccio_best_effort


def npm_hash(token: str) -> str:
    return "{SHA}" + base64.b64encode(hashlib.sha1(token.encode()).digest()).decode()  # noqa: S324


def _dir_bytes(path: Path) -> int:
    total = 0
    if not path.is_dir():
        return 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                continue
    return total


class DevpiAdmin:
    """Minimal devpi REST client acting as ``root``."""

    def __init__(self, base_url: str, password_file: Path) -> None:
        self.base_url = base_url.rstrip("/")
        self.password_file = password_file

    async def _client(self) -> httpx.AsyncClient:
        transport = TRANSPORT_FACTORY()
        return httpx.AsyncClient(base_url=self.base_url, transport=transport, timeout=30.0,
                                 headers={"Accept": "application/json"})

    async def _auth(self, client: httpx.AsyncClient) -> dict[str, str]:
        try:
            password = self.password_file.read_text(encoding="utf-8").strip()
        except OSError:
            raise TenancyError("pypi_unavailable", 503,
                               "The PyPI registry is not available") from None
        response = await client.post("/+login", json={"user": "root", "password": password})
        if response.status_code != 200:
            raise TenancyError("pypi_unavailable", 503, "The PyPI registry refused the login")
        token = (response.json().get("result") or {}).get("password", "")
        value = base64.b64encode(f"root:{token}".encode()).decode()
        return {"X-Devpi-Auth": value, "Content-Type": "application/json"}

    async def call(self, method: str, path: str, body: Any = None, *,
                   ok: tuple[int, ...] = (200, 201)) -> httpx.Response:
        try:
            async with await self._client() as client:
                headers = await self._auth(client)
                response = await client.request(
                    method, path, headers=headers,
                    content=None if body is None else json.dumps(body))
        except httpx.HTTPError:
            raise TenancyError("pypi_unavailable", 503,
                               "The PyPI registry is not available") from None
        if response.status_code not in ok:
            raise TenancyError("pypi_error", 502, "The PyPI registry rejected the change",
                               upstream_status=response.status_code)
        return response

    async def ensure_index(self, slug: str, users: list[str]) -> None:
        await self.call("PUT", f"/{slug}", {"password": secrets.token_urlsafe(24), "email": ""},
                        ok=(200, 201, 409))
        await self.call("PUT", f"/{slug}/dev", {
            "type": "stage", "bases": ["root/pypi"], "volatile": True, "acl_upload": users,
        }, ok=(200, 201, 409))
        await self.set_upload(slug, users)

    async def set_upload(self, slug: str, users: list[str]) -> None:
        await self.call("PATCH", f"/{slug}/dev", {"acl_upload": users})

    async def create_user(self, name: str, password: str) -> None:
        await self.call("PUT", f"/{name}", {"password": password, "email": ""})

    async def delete_user(self, name: str) -> None:
        await self.call("DELETE", f"/{name}", ok=(200, 201, 404))

    async def projects(self, slug: str) -> list[dict[str, Any]]:
        try:
            async with await self._client() as client:
                response = await client.get(f"/{slug}/dev")
                if response.status_code != 200:
                    return []
                names = (response.json().get("result") or {}).get("projects") or []
                items = []
                for name in sorted(names)[:500]:
                    detail = await client.get(f"/{slug}/dev/{quote(name, safe='')}")
                    versions = (detail.json().get("result") or {}) \
                        if detail.status_code == 200 else {}
                    items.append({"name": name, "versions": sorted(versions)})
                return items
        except (httpx.HTTPError, ValueError):
            return []

    async def delete_version(self, slug: str, name: str, version: str) -> None:
        await self.call("DELETE", f"/{slug}/dev/{quote(name, safe='')}/{quote(version, safe='')}",
                        ok=(200, 201, 404))


def register_routes(space: MySpace, router: APIRouter) -> None:
    store = space.store
    ctx = space.ctx
    data_dir = ctx.data_dir
    npm_root = data_dir / "npm"
    lock = asyncio.Lock()

    def devpi() -> DevpiAdmin:
        auth_dir = Path(os.getenv("MRK_PYPI_AUTH_DIR", "/data/pypi/auth"))
        password_file = os.getenv("MRK_PYPI_ROOT_PASSWORD_FILE") or os.getenv(
            "MRK_DEVPI_ROOT_PASSWORD_FILE") or str(auth_dir / "root-password")
        settings = ctx.settings
        return DevpiAdmin(f"http://{settings.pypi_health_host}:{settings.pypi_health_port}",
                          Path(password_file))

    def pypi_files(slug: str) -> Path:
        return Path(os.getenv("MRK_PYPI_SERVER_DIR", "/data/pypi/server")) / "+files" / slug \
            / "dev"

    def public_url(service_id: str) -> str | None:
        with ctx.database.session() as db:
            rows = db.execute(select(ServiceDomain.host, ServiceDomain.https,
                                     ServiceDomain.primary)
                              .where(ServiceDomain.service_id == service_id)).all()
        if not rows:
            return None
        host, https, _primary = sorted(rows, key=lambda row: not row[2])[0]
        return f"{'https' if https else 'http'}://{host}/"

    # ---------------------------------------------------------------- npm files
    def npm_scope_dir(slug: str) -> Path:
        return npm_root / "storage" / f"@{slug}"

    def npm_packages(slug: str) -> list[dict[str, Any]]:
        root = npm_scope_dir(slug)
        items: list[dict[str, Any]] = []
        if not root.is_dir():
            return items
        for package in sorted(root.iterdir()):
            manifest = package / "package.json"
            if not manifest.is_file():
                continue
            try:
                versions = sorted((json.loads(manifest.read_text("utf-8")).get("versions")
                                   or {}).keys())
            except (OSError, ValueError):
                versions = []
            items.append({"name": f"@{slug}/{package.name}", "versions": versions,
                          "bytes": _dir_bytes(package)})
        return items

    def write_npm_config() -> None:
        """htpasswd (managed users) + tenancy.json from every workspace's npm scope."""
        owners = store.all_owned(("npm_scope",))
        managed: list[str] = []
        scopes: list[dict[str, Any]] = []
        for owner in owners:
            tokens = owner["meta"].get("tokens") or []
            for token in tokens:
                managed.append(f"{token['username']}:{token['hash']}")
            scopes.append({"scope": owner["resource_id"],
                           "users": [token["username"] for token in tokens],
                           "publish": bool(owner["meta"].get("publish", True))})
        htpasswd = npm_root / "auth" / "htpasswd"
        htpasswd.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        kept = []
        if htpasswd.is_file():
            kept = [line for line in htpasswd.read_text("utf-8").splitlines()
                    if line.strip() and not line.startswith(MANAGED_PREFIX)]
        _atomic(htpasswd, "\n".join([*kept, *managed]) + "\n")
        target = npm_root / "config" / "tenancy.json"
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _atomic(target, json.dumps({"scopes": scopes}, indent=1))

    # ---------------------------------------------------------------- helpers
    def owner_row(wctx: WorkspaceContext, ecosystem: str) -> dict[str, Any] | None:
        kind, rid = resource(wctx, ecosystem)
        if store.owner_of(kind, rid) != wctx.workspace_id:
            return None
        return store.require_owned(wctx, kind, rid)

    def resource(wctx: WorkspaceContext, ecosystem: str) -> tuple[str, str]:
        if ecosystem == "npm":
            return "npm_scope", f"@{wctx.slug}"
        return "pypi_index", f"{wctx.slug}/dev"

    async def usage_bytes(slug: str, ecosystem: str) -> int:
        if ecosystem == "npm":
            return await asyncio.to_thread(_dir_bytes, npm_scope_dir(slug))
        return await asyncio.to_thread(_dir_bytes, pypi_files(slug))

    async def sync_publish(wctx: WorkspaceContext, ecosystem: str) -> bool:
        """Turn publishing off at/over the size quota, back on below it."""
        owner = await asyncio.to_thread(owner_row, wctx, ecosystem)
        limit = wctx.limits["quotas"].get(f"{ecosystem}_bytes")
        used = await usage_bytes(wctx.slug, ecosystem)
        allowed = limit is None or used < int(limit)
        if owner is None:
            return allowed
        if bool(owner["meta"].get("publish", True)) != allowed:
            await asyncio.to_thread(store.set_meta, owner["kind"], owner["resource_id"],
                                    {"publish": allowed})
            if ecosystem == "npm":
                await asyncio.to_thread(write_npm_config)
                await asyncio.to_thread(RELOAD_NPM)
            else:
                users = [token["username"] for token in owner["meta"].get("tokens") or []]
                await devpi().set_upload(wctx.slug, users if allowed else [])
        return allowed

    async def run(request: Request, work: Callable[..., Awaitable[Any]], *, scope: str,
                  write: bool = False, feature: str | None = None) -> Any:
        try:
            wctx = await space.context(request, write=write)
            wctx.need(scope, feature=feature)
            body = await space.body(request) if write else None
            return await work(wctx, body)
        except TenancyError as exc:
            return space.fail(exc)

    # ---------------------------------------------------------------- routes
    @router.get("/packages", response_model=None)
    async def packages(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            features = wctx.limits["features"]
            npm: dict[str, Any] = {"enabled": features["npm"], "scope": f"@{wctx.slug}",
                                   "registry_url": await asyncio.to_thread(public_url, "npm"),
                                   "publish_allowed": False, "usage_bytes": 0, "packages": []}
            pypi: dict[str, Any] = {"enabled": features["pypi"], "index": f"{wctx.slug}/dev",
                                    "index_url": None, "publish_allowed": False,
                                    "usage_bytes": 0, "packages": []}
            base = await asyncio.to_thread(public_url, "pypi")
            if base:
                pypi["index_url"] = f"{base}{wctx.slug}/dev/+simple/"
            if features["npm"]:
                npm["packages"] = await asyncio.to_thread(npm_packages, wctx.slug)
                npm["usage_bytes"] = sum(item["bytes"] for item in npm["packages"])
                npm["publish_allowed"] = await sync_publish(wctx, "npm") \
                    if wctx.status == "active" else False
            if features["pypi"]:
                if await asyncio.to_thread(owner_row, wctx, "pypi") is not None:
                    pypi["packages"] = await devpi().projects(wctx.slug)
                pypi["usage_bytes"] = await usage_bytes(wctx.slug, "pypi")
                pypi["publish_allowed"] = await sync_publish(wctx, "pypi") \
                    if wctx.status == "active" else False
            return {"npm": npm, "pypi": pypi}

        return await run(request, work, scope="my.packages:read")

    @router.get("/packages/tokens", response_model=None)
    async def list_tokens(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            items = []
            for ecosystem in ECOSYSTEMS:
                owner = await asyncio.to_thread(owner_row, wctx, ecosystem)
                for token in (owner or {"meta": {}})["meta"].get("tokens") or []:
                    items.append({"id": token["id"], "ecosystem": ecosystem,
                                  "name": token["name"], "username": token["username"],
                                  "created_at": token["created_at"]})
            return {"items": items}

        return await run(request, work, scope="my.packages:read")

    @router.post("/packages/tokens", status_code=201, response_model=None)
    async def create_token(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any) -> Any:
            if not isinstance(body, dict) or set(body) - {"ecosystem", "name"}:
                raise TenancyError("invalid_request", 422, "Send {ecosystem, name}",
                                   fields=[{"field": "body", "reason_code": "invalid"}])
            ecosystem = body.get("ecosystem")
            if ecosystem not in ECOSYSTEMS:
                raise TenancyError("invalid_request", 422, "npm or pypi", fields=[
                    {"field": "ecosystem", "reason_code": "invalid_choice"}])
            wctx.feature(ecosystem)
            name = body.get("name")
            if not isinstance(name, str) or not _TOKEN_NAME.fullmatch(name.strip()):
                raise TenancyError("invalid_request", 422, "A name of 3-80 characters",
                                   fields=[{"field": "name", "reason_code": "too_short"}])
            kind, rid = resource(wctx, ecosystem)
            if ecosystem == "npm" and await asyncio.to_thread(
                    lambda: store.owner_of(kind, rid) is None
                    and npm_scope_dir(wctx.slug).exists()):
                # Cached public packages already use this scope: never shadow them.
                raise TenancyError("scope_unavailable", 409,
                                   "This npm scope is already used by public packages")
            secret = f"pk_{secrets.token_urlsafe(32)}"
            token_id = f"pt_{secrets.token_hex(6)}"
            username = f"{MANAGED_PREFIX}{wctx.slug}-{secrets.token_hex(3)}" \
                if ecosystem == "npm" else f"{wctx.slug}-t{secrets.token_hex(3)}"
            async with lock:
                if store.owner_of(kind, rid) is None:
                    await asyncio.to_thread(store.claim, wctx, kind, rid,
                                            meta={"tokens": [], "publish": True})
                owner = await asyncio.to_thread(store.require_owned, wctx, kind, rid)
                tokens = list(owner["meta"].get("tokens") or [])
                if len(tokens) >= MAX_TOKENS:
                    raise TenancyError("quota_exceeded", 409, "Too many publish tokens",
                                       quota="package_tokens", limit=MAX_TOKENS,
                                       used=len(tokens))
                entry = {"id": token_id, "name": name.strip(), "username": username,
                         "created_at": int(time.time()), "created_by": wctx.user_id}
                if ecosystem == "npm":
                    entry["hash"] = npm_hash(secret)
                tokens.append(entry)
                if ecosystem == "pypi":
                    await devpi().create_user(username, secret)
                    await devpi().ensure_index(wctx.slug, [t["username"] for t in tokens])
                await asyncio.to_thread(store.set_meta, kind, rid, {"tokens": tokens})
                if ecosystem == "npm":
                    await asyncio.to_thread(write_npm_config)
                    await asyncio.to_thread(RELOAD_NPM)
                await sync_publish(wctx, ecosystem)
            await space.audit(wctx, "my.packages.token.create", kind, f"{rid}:{token_id}")
            if ecosystem == "npm":
                registry = await asyncio.to_thread(public_url, "npm") or "https://npm.example/"
                host = registry.split("://", 1)[-1]
                auth = base64.b64encode(f"{username}:{secret}".encode()).decode()
                setup = {"npmrc": f"@{wctx.slug}:registry={registry}\n//{host}:_auth={auth}\n"}
            else:
                base = await asyncio.to_thread(public_url, "pypi") or "https://pypi.example/"
                setup = {"pypirc": (f"[distutils]\nindex-servers = {wctx.slug}\n\n"
                                    f"[{wctx.slug}]\nrepository = {base}{wctx.slug}/dev/\n"
                                    f"username = {username}\npassword = {secret}\n")}
            return JSONResponse(status_code=201, content={
                "id": token_id, "ecosystem": ecosystem, "name": entry["name"],
                "username": username, "token": secret, "setup": setup})

        return await run(request, work, scope="my.packages:write", write=True)

    @router.delete("/packages/tokens/{token_id}", response_model=None)
    async def delete_token(token_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            async with lock:
                for ecosystem in ECOSYSTEMS:
                    owner = await asyncio.to_thread(owner_row, wctx, ecosystem)
                    if owner is None:
                        continue
                    tokens = owner["meta"].get("tokens") or []
                    found = next((item for item in tokens if item["id"] == token_id), None)
                    if found is None:
                        continue
                    remaining = [item for item in tokens if item["id"] != token_id]
                    await asyncio.to_thread(store.set_meta, owner["kind"],
                                            owner["resource_id"], {"tokens": remaining})
                    if ecosystem == "npm":
                        await asyncio.to_thread(write_npm_config)
                        await asyncio.to_thread(RELOAD_NPM)
                    else:
                        allowed = bool(owner["meta"].get("publish", True))
                        await devpi().set_upload(
                            wctx.slug, [t["username"] for t in remaining] if allowed else [])
                        await devpi().delete_user(found["username"])
                    await space.audit(wctx, "my.packages.token.revoke", owner["kind"],
                                      f"{owner['resource_id']}:{token_id}")
                    return {"revoked": token_id}
            raise not_found()

        return await run(request, work, scope="my.packages:write", write=True)

    @router.delete("/packages/{ecosystem}/{name:path}/versions/{version}", response_model=None)
    async def delete_version(ecosystem: str, name: str, version: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            if ecosystem not in ECOSYSTEMS or not _VERSION.fullmatch(version):
                raise not_found()
            if ecosystem == "npm":
                prefix = f"@{wctx.slug}/"
                package = name[len(prefix):] if name.startswith(prefix) else ""
                if not _NPM_PACKAGE.fullmatch(package):
                    raise not_found()
                wctx.need("my.packages:write", feature="npm")
                removed = await asyncio.to_thread(_npm_unpublish,
                                                  npm_scope_dir(wctx.slug) / package,
                                                  package, version)
                if not removed:
                    raise not_found()
            else:
                if not PYPI_NAME.fullmatch(name):
                    raise not_found()
                wctx.need("my.packages:write", feature="pypi")
                if await asyncio.to_thread(owner_row, wctx, "pypi") is None:
                    raise not_found()
                await devpi().delete_version(wctx.slug, normalize_pypi(name), version)
            await space.audit(wctx, "my.packages.version.delete", f"{ecosystem}_package",
                              f"{name}@{version}")
            await sync_publish(wctx, ecosystem)
            return {"deleted": f"{name}@{version}"}

        # Ownership (the name's scope) is checked inside, before the scope check.
        return await run(request, work, scope="my.packages:read", write=True)

    # ---------------------------------------------------------------- usage / cleanup
    async def usage(workspace_id: str) -> dict[str, Any]:
        row = await asyncio.to_thread(store.workspace_row, workspace_id)
        npm_used = await usage_bytes(row["slug"], "npm") \
            if row["limits"]["features"]["npm"] else 0
        pypi_used = await usage_bytes(row["slug"], "pypi") \
            if row["limits"]["features"]["pypi"] else 0
        return {"npm_bytes": npm_used, "pypi_bytes": pypi_used}

    async def cleanup_npm(item: dict[str, Any]) -> None:
        await asyncio.to_thread(store.set_meta, "npm_scope", item["resource_id"], {"tokens": []})
        scope_dir = npm_root / "storage" / item["resource_id"]
        if scope_dir.is_dir() and item["resource_id"].startswith("@"):
            await asyncio.to_thread(shutil.rmtree, scope_dir, True)
        await asyncio.to_thread(store.release, "npm_scope", item["resource_id"])
        await asyncio.to_thread(write_npm_config)
        await asyncio.to_thread(RELOAD_NPM)

    async def cleanup_pypi(item: dict[str, Any]) -> None:
        slug = item["resource_id"].split("/", 1)[0]
        for token in item["meta"].get("tokens") or []:
            await devpi().delete_user(token["username"])
        await devpi().delete_user(slug)

    space.usage_providers.append(usage)
    space.cleanup["npm_scope"] = cleanup_npm
    space.cleanup["pypi_index"] = cleanup_pypi


def _atomic(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def _npm_unpublish(package_dir: Path, package: str, version: str) -> bool:
    """Remove one version from Verdaccio's local storage (manifest + tarball)."""
    manifest = package_dir / "package.json"
    if not manifest.is_file():
        return False
    data = json.loads(manifest.read_text("utf-8"))
    versions = data.get("versions") or {}
    if version not in versions:
        return False
    versions.pop(version)
    (data.get("time") or {}).pop(version, None)
    tags = data.get("dist-tags") or {}
    for tag, value in list(tags.items()):
        if value == version:
            tags.pop(tag)
    if versions and "latest" not in tags:
        tags["latest"] = sorted(versions)[-1]
    tarball = package_dir / f"{package}-{version}.tgz"
    tarball.unlink(missing_ok=True)
    (data.get("_attachments") or {}).pop(f"{package}-{version}.tgz", None)
    if not versions:
        shutil.rmtree(package_dir, ignore_errors=True)
        return True
    _atomic(manifest, json.dumps(data))
    return True
