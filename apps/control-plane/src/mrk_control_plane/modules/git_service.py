"""Git service (Gitea) added from the add-service wizard (docs/46).

Gitea runs in its own stack (``mrk-git``) with its own SQLite database in its
own volume: it depends on nothing else. A one-shot ``mrk-git-init`` creates the
admin user ``mrk-panel`` with the password from the wizard's ``.env``. When the
operator connects the service, the panel uses that password once to create an
API token, keeps only the token (SecretStore) and manages Gitea through its API:
repositories, mirrors of GitHub/GitLab repositories, users and organizations.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from ..auth import FieldError
from ..credential_policy import check_password
from ..module_context import ModuleContext

STATE_FILE = "git.json"
ADMIN_USER = "mrk-panel"
TOKEN_SCOPES = ["write:admin", "write:organization", "write:repository", "write:user",
                "write:misc", "write:issue"]
DEFAULT_URL = "http://mrk-git:3000"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_LOGIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,38}$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}$")
_INTERVAL = re.compile(r"^(?:0|(?:[0-9]{1,3}h)?(?:[0-9]{1,2}m)?)$")  # "0" = manual sync only
MAX_BODY = 4 * 1024 * 1024
GITEA_MIN_PASSWORD = 8  # Gitea's default MIN_PASSWORD_LENGTH
GITEA_MAX_PASSWORD = 255

# Tests replace this with a factory returning e.g. httpx.MockTransport(fake_gitea).
TRANSPORT_FACTORY: Any = None
ACTIVE_SERVICE: GitService | None = None


class GitError(Exception):
    def __init__(self, code: str, status_code: int, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.extra = extra


def _client(**kwargs: Any) -> httpx.AsyncClient:
    transport = TRANSPORT_FACTORY() if TRANSPORT_FACTORY is not None else None
    return httpx.AsyncClient(transport=transport, timeout=20.0, trust_env=False,
                             follow_redirects=False, **kwargs)


def _validate_base(url: str) -> str:
    text = url.strip().rstrip("/")
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username \
            or parts.password or parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise GitError("invalid_url", 422, "Use http://host:port",
                       fields=[{"field": "url", "reason_code": "invalid"}])
    return text


def validate_source_url(url: str) -> str:
    """Mirror sources: public https Git hosts only (no credentials in the URL)."""
    text = url.strip()
    parts = urlsplit(text)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password \
            or parts.query or parts.fragment or len(text) > 500 or any(c.isspace() for c in text):
        raise GitError("validation_error", 422, "The source must be an https:// repository URL",
                       fields=[{"field": "source_url", "reason_code": "invalid"}])
    host = parts.hostname.lower()
    if host in {"localhost"} or host.endswith((".local", ".internal")):
        raise GitError("validation_error", 422, "The source must be a public Git host",
                       fields=[{"field": "source_url", "reason_code": "invalid"}])
    import ipaddress

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return text
    if not address.is_global:
        raise GitError("validation_error", 422, "The source must be a public Git host",
                       fields=[{"field": "source_url", "reason_code": "invalid"}])
    return text


def _repo(item: dict[str, Any]) -> dict[str, Any]:
    owner = item.get("owner") or {}
    return {
        "id": item.get("id"),
        "full_name": item.get("full_name"),
        "owner": owner.get("login") or owner.get("username"),
        "name": item.get("name"),
        "private": bool(item.get("private")),
        "mirror": bool(item.get("mirror")),
        "description": item.get("description") or "",
        "clone_http": item.get("clone_url"),
        "clone_ssh": item.get("ssh_url"),
        "html_url": item.get("html_url"),
        "updated_at": item.get("updated_at"),
        "size_kb": item.get("size"),
    }


def _user(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "login": item.get("login") or item.get("username"),
        "email": item.get("email"),
        "full_name": item.get("full_name") or "",
        "admin": bool(item.get("is_admin")),
        "active": bool(item.get("active", True)) and not item.get("prohibit_login", False),
        "created": item.get("created"),
    }


class GitService:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state_path: Path = ctx.data_dir / "control-plane" / STATE_FILE

    # ------------------------------------------------------------------ state
    def _read(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _write(self, payload: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(f".{STATE_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_bytes((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
        temporary.chmod(0o600)
        os.replace(temporary, self.state_path)

    def connected(self) -> dict[str, Any] | None:
        state = self._read()
        return state if state.get("url") and state.get("token_ref") else None

    def _token(self) -> str:
        state = self.connected()
        if state is None:
            raise GitError("git_not_connected", 409, "The Git service is not added yet")
        try:
            return self.ctx.secret_store.get(state["token_ref"])["token"]
        except (KeyError, ValueError) as exc:
            raise GitError("git_not_connected", 409, "Connect the Git service again") from exc

    def public_url(self) -> str | None:
        try:
            state = json.loads((self.ctx.data_dir / "control-plane" / "install.json")
                               .read_text(encoding="utf-8"))
            env = (state.get("git") or {}).get("env") or {}
        except (OSError, ValueError, AttributeError):
            return None
        value = str(env.get("MRK_GIT_ROOT_URL") or "").strip()
        return value or None

    # ------------------------------------------------------------------ connect
    async def connect(self, url: str, password: str) -> dict[str, Any]:
        """Create an API token with the bootstrap admin password; keep only the token."""
        base = _validate_base(url)
        name = f"mrk-panel-{int(time.time())}"
        async with _client(auth=(ADMIN_USER, password)) as client:
            try:
                response = await client.post(
                    f"{base}/api/v1/users/{ADMIN_USER}/tokens",
                    json={"name": name, "scopes": TOKEN_SCOPES},
                )
            except httpx.HTTPError as exc:
                raise GitError("git_unreachable", 503, "The Git service does not answer") from exc
        if response.status_code in {401, 403}:
            raise GitError("git_auth_failed", 409,
                           "The admin password does not match; deploy the latest files again")
        if response.status_code != 201:
            raise GitError("git_error", 502, f"Gitea answered {response.status_code}")
        token = response.json().get("sha1")
        if not isinstance(token, str) or not token:
            raise GitError("git_error", 502, "Gitea returned no token")
        state = self._read()
        reference, _ = self.ctx.secret_store.replace(
            state.get("token_ref") if isinstance(state.get("token_ref"), str) else None,
            {"token": token},
        )
        state.update({"url": base, "token_ref": reference, "token_name": name,
                      "connected_at": int(time.time())})
        self._write(state)
        return state

    # ------------------------------------------------------------------ API
    async def call(self, method: str, path: str, *, json_body: Any = None,
                   params: dict[str, Any] | None = None, ok: tuple[int, ...] = (200,)) -> Any:
        state = self.connected()
        if state is None:
            raise GitError("git_not_connected", 409, "The Git service is not added yet")
        headers = {"Authorization": f"token {self._token()}", "Accept": "application/json"}
        async with _client() as client:
            try:
                response = await client.request(method, f"{state['url']}/api/v1{path}",
                                                json=json_body, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise GitError("git_unreachable", 503, "The Git service does not answer") from exc
        if response.status_code not in ok:
            message = ""
            try:
                body = response.json()
                message = str(body.get("message") or "")[:300] if isinstance(body, dict) else ""
            except ValueError:
                pass
            code = {401: "git_auth_failed", 403: "git_forbidden", 404: "git_not_found",
                    409: "git_conflict", 422: "git_rejected"}.get(response.status_code, "git_error")
            status = 502 if code == "git_error" else (
                404 if code == "git_not_found" else 409 if code != "git_rejected" else 422)
            raise GitError(code, status, message or f"Gitea answered {response.status_code}")
        if len(response.content) > MAX_BODY:
            raise GitError("git_error", 502, "Gitea answer is too large")
        return response.json() if response.content else None

    async def status(self) -> dict[str, Any]:
        state = self.connected()
        version = None
        reachable = False
        if state is not None:
            try:
                payload = await self.call("GET", "/version")
                version = payload.get("version") if isinstance(payload, dict) else None
                reachable = True
            except GitError:
                reachable = False
        return {"connected": state is not None, "reachable": reachable, "version": version,
                "url": state["url"] if state else None, "public_url": self.public_url(),
                "admin_user": ADMIN_USER}

    async def repos(self, query: str, page: int) -> dict[str, Any]:
        payload = await self.call("GET", "/repos/search",
                                  params={"q": query[:100], "page": max(1, page), "limit": 50,
                                          "sort": "updated", "order": "desc"})
        items = payload.get("data") if isinstance(payload, dict) else payload
        return {"items": [_repo(item) for item in items or []],
                "total": len(items or [])}

    def _owner(self, owner: str | None) -> str:
        owner = (owner or ADMIN_USER).strip()
        if not _LOGIN.match(owner):
            raise GitError("validation_error", 422, "invalid owner",
                           fields=[{"field": "owner", "reason_code": "invalid"}])
        return owner

    async def _owner_path(self, owner: str) -> str:
        """POST target for a new repo: the admin's own, an organization, or another user."""
        if owner == ADMIN_USER:
            return "/user/repos"
        try:
            await self.call("GET", f"/orgs/{quote(owner, safe='')}")
            return f"/orgs/{quote(owner, safe='')}/repos"
        except GitError as exc:
            if exc.code != "git_not_found":
                raise
        return f"/admin/users/{quote(owner, safe='')}/repos"

    async def create_repo(self, owner: str | None, name: str, private: bool,
                          description: str) -> dict[str, Any]:
        if not _NAME.match(name):
            raise GitError("validation_error", 422, "invalid repository name",
                           fields=[{"field": "name", "reason_code": "invalid"}])
        path = await self._owner_path(self._owner(owner))
        payload = await self.call("POST", path, ok=(201,), json_body={
            "name": name, "private": private, "description": description[:500],
            "auto_init": True, "default_branch": "main"})
        return _repo(payload)

    async def mirror(self, source_url: str, owner: str | None, name: str, private: bool,
                     interval: str | None, auth_username: str | None,
                     auth_token: str | None) -> dict[str, Any]:
        source = validate_source_url(source_url)
        if not _NAME.match(name):
            raise GitError("validation_error", 422, "invalid repository name",
                           fields=[{"field": "name", "reason_code": "invalid"}])
        if interval and not _INTERVAL.match(interval):
            raise GitError("validation_error", 422, "interval looks like 8h or 30m",
                           fields=[{"field": "interval", "reason_code": "invalid"}])
        body: dict[str, Any] = {
            "clone_addr": source, "repo_name": name, "repo_owner": self._owner(owner),
            "mirror": True, "private": private, "service": "git",
            "mirror_interval": interval or "8h",
        }
        if auth_username:
            body["auth_username"] = auth_username[:100]
        if auth_token:
            body["auth_token"] = auth_token[:500]
        payload = await self.call("POST", "/repos/migrate", json_body=body, ok=(201,))
        return _repo(payload)

    async def sync(self, owner: str, name: str) -> None:
        await self.call("POST", f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
                        "/mirror-sync", ok=(200,))

    async def delete_repo(self, owner: str, name: str) -> None:
        await self.call("DELETE", f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}",
                        ok=(204,))

    async def users(self) -> list[dict[str, Any]]:
        payload = await self.call("GET", "/admin/users", params={"limit": 100})
        return [_user(item) for item in payload or []]

    @staticmethod
    def _password(password: str | None) -> str:
        """The operator's own password (checked) or a generated one."""
        if password is None or password == "":
            return secrets.token_urlsafe(18)
        try:
            return check_password(password, min_length=GITEA_MIN_PASSWORD,
                                  max_length=GITEA_MAX_PASSWORD)
        except FieldError as exc:
            raise GitError(exc.code, 422, exc.message, fields=exc.fields) from None

    async def set_password(self, login: str, password: str | None,
                           must_change: bool = True) -> dict[str, Any]:
        """Give a Gitea user a new password (the operator's own or a generated one)."""
        if not _LOGIN.match(login) or login == ADMIN_USER:
            raise GitError("validation_error", 422, "invalid user name",
                           fields=[{"field": "login", "reason_code": "invalid"}])
        password = self._password(password)
        await self.call("PATCH", f"/admin/users/{quote(login, safe='')}", json_body={
            "login_name": login, "source_id": 0, "password": password,
            "must_change_password": must_change})
        return {"login": login, "password": password, "must_change_password": must_change}

    async def create_user(self, login: str, email: str, full_name: str,
                          admin: bool, password: str | None = None,
                          must_change: bool = True) -> dict[str, Any]:
        if not _LOGIN.match(login) or login == ADMIN_USER:
            raise GitError("validation_error", 422, "invalid user name",
                           fields=[{"field": "login", "reason_code": "invalid"}])
        if not _EMAIL.match(email):
            raise GitError("validation_error", 422, "invalid email",
                           fields=[{"field": "email", "reason_code": "invalid"}])
        password = self._password(password)
        payload = await self.call("POST", "/admin/users", ok=(201,), json_body={
            "username": login, "email": email, "full_name": full_name[:100],
            "password": password, "must_change_password": must_change, "send_notify": False,
            "visibility": "private"})
        if admin:
            await self.call("PATCH", f"/admin/users/{quote(login, safe='')}",
                            json_body={"admin": True, "login_name": login, "source_id": 0})
            payload["is_admin"] = True
        return {"user": _user(payload), "password": password}

    async def orgs(self) -> list[dict[str, Any]]:
        payload = await self.call("GET", "/admin/orgs", params={"limit": 100})
        return [{"id": item.get("id"), "name": item.get("username") or item.get("name"),
                 "full_name": item.get("full_name") or ""} for item in payload or []]

    async def create_org(self, name: str, full_name: str) -> dict[str, Any]:
        if not _LOGIN.match(name):
            raise GitError("validation_error", 422, "invalid organization name",
                           fields=[{"field": "name", "reason_code": "invalid"}])
        payload = await self.call("POST", "/orgs", ok=(201,), json_body={
            "username": name, "full_name": full_name[:100], "visibility": "private"})
        return {"id": payload.get("id"), "name": payload.get("username") or name,
                "full_name": payload.get("full_name") or ""}


class RepoBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: str | None = Field(default=None, max_length=40)
    name: str = Field(min_length=1, max_length=100)
    private: bool = True
    description: str = Field(default="", max_length=500)


class MirrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_url: str = Field(min_length=8, max_length=500)
    owner: str | None = Field(default=None, max_length=40)
    name: str = Field(min_length=1, max_length=100)
    private: bool = True
    interval: str | None = Field(default=None, max_length=10)
    auth_username: str | None = Field(default=None, max_length=100)
    auth_token: str | None = Field(default=None, max_length=500)


class ConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation: str = Field(max_length=200)


class UserBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    login: str = Field(min_length=1, max_length=39)
    email: str = Field(min_length=3, max_length=255)
    full_name: str = Field(default="", max_length=100)
    admin: bool = False
    # Optional: the operator's own password; omitted or empty = generated.
    password: str | None = Field(default=None, max_length=GITEA_MAX_PASSWORD)
    must_change_password: bool = True


class PasswordBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str | None = Field(default=None, max_length=GITEA_MAX_PASSWORD)
    must_change_password: bool = True


class OrgBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=39)
    full_name: str = Field(default="", max_length=100)


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = GitService(ctx)
    ACTIVE_SERVICE = service
    router = APIRouter(prefix="/api/v1/git", tags=["git"])

    def failure(exc: GitError):
        return ctx.error_payload(exc.code, exc.message, exc.status_code, **exc.extra)  # type: ignore[call-arg]

    def writer(request: Request):
        principal = ctx.require_principal(request, "git:write")
        ctx.require_csrf(request, principal)
        return principal

    async def audit(principal: Any, action: str, object_id: str, result: str = "success"):
        await asyncio.to_thread(ctx.audit, principal.user_id, action, "git", object_id, result)

    @router.get("/status")
    async def git_status(request: Request):
        ctx.require_principal(request, "git:read")
        return await service.status()

    @router.get("/repos")
    async def git_repos(request: Request, q: str = "", page: int = 1):
        ctx.require_principal(request, "git:read")
        try:
            return await service.repos(q, page)
        except GitError as exc:
            return failure(exc)

    @router.post("/repos", status_code=201)
    async def git_create_repo(request: Request, body: RepoBody):
        principal = writer(request)
        try:
            repo = await service.create_repo(body.owner, body.name, body.private,
                                             body.description)
        except GitError as exc:
            await audit(principal, "git.repo.create", body.name, "failure")
            return failure(exc)
        await audit(principal, "git.repo.create", str(repo.get("full_name")))
        return repo

    @router.post("/mirrors", status_code=201)
    async def git_mirror(request: Request, body: MirrorBody):
        principal = writer(request)
        try:
            repo = await service.mirror(body.source_url, body.owner, body.name, body.private,
                                        body.interval, body.auth_username, body.auth_token)
        except GitError as exc:
            await audit(principal, "git.mirror.create", body.name, "failure")
            return failure(exc)
        await audit(principal, "git.mirror.create", str(repo.get("full_name")))
        return repo

    @router.post("/repos/{owner}/{name}/sync")
    async def git_sync(owner: str, name: str, request: Request):
        principal = writer(request)
        try:
            await service.sync(owner, name)
        except GitError as exc:
            return failure(exc)
        await audit(principal, "git.mirror.sync", f"{owner}/{name}")
        return {"ok": True}

    @router.delete("/repos/{owner}/{name}")
    async def git_delete_repo(owner: str, name: str, request: Request, body: ConfirmBody):
        principal = writer(request)
        if body.confirmation != f"{owner}/{name}":
            return ctx.error_payload("confirmation_required", f'Type "{owner}/{name}" to confirm',
                                     422)
        try:
            await service.delete_repo(owner, name)
        except GitError as exc:
            await audit(principal, "git.repo.delete", f"{owner}/{name}", "failure")
            return failure(exc)
        await audit(principal, "git.repo.delete", f"{owner}/{name}")
        return {"ok": True}

    @router.get("/users")
    async def git_users(request: Request):
        ctx.require_principal(request, "git:read")
        try:
            return {"items": await service.users()}
        except GitError as exc:
            return failure(exc)

    @router.post("/users", status_code=201)
    async def git_create_user(request: Request, body: UserBody):
        principal = writer(request)
        try:
            result = await service.create_user(body.login, body.email, body.full_name, body.admin,
                                               body.password, body.must_change_password)
        except GitError as exc:
            await audit(principal, "git.user.create", body.login, "failure")
            return failure(exc)
        await audit(principal, "git.user.create", body.login)
        return result

    @router.post("/users/{login}/password")
    async def git_user_password(login: str, request: Request, body: PasswordBody | None = None):
        principal = writer(request)
        try:
            result = await service.set_password(
                login, body.password if body else None,
                body.must_change_password if body else True)
        except GitError as exc:
            await audit(principal, "git.user.password", login, "failure")
            return failure(exc)
        # The password is in this response only; the audit names the user, never the value.
        await audit(principal, "git.user.password", login)
        return result

    @router.get("/orgs")
    async def git_orgs(request: Request):
        ctx.require_principal(request, "git:read")
        try:
            return {"items": await service.orgs()}
        except GitError as exc:
            return failure(exc)

    @router.post("/orgs", status_code=201)
    async def git_create_org(request: Request, body: OrgBody):
        principal = writer(request)
        try:
            result = await service.create_org(body.name, body.full_name)
        except GitError as exc:
            return failure(exc)
        await audit(principal, "git.org.create", body.name)
        return result

    ctx.routers.append(router)
