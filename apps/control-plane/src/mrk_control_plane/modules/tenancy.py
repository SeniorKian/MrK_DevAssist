"""«My space» panel API (docs/43 §2–§3): admin area and the user's own area.

* ``/api/v1/admin/...`` (``tenancy:admin``): plans, workspaces, ownership, «view as»,
  pending sign-ups and the tenancy settings.
* ``/api/v1/my/...``: the signed-in person's workspaces, members, invites, API keys and
  activity; DNS (``my_dns``), file space (``my_s3``) and packages (``my_packages``)
  add their routes through :class:`MySpace`.

All isolation lives in :mod:`mrk_control_plane.tenancy`; this module only maps HTTP to it.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..module_context import ModuleContext
from ..tenancy import (
    RESOURCE_KINDS,
    TenancyError,
    TenancyStore,
    WorkspaceContext,
    not_found,
)

LOGGER = logging.getLogger(__name__)
MAX_BODY_BYTES = 64 * 1024
PASSWORD_CHANGE_REQUIRED = "password_change_required"  # noqa: S105 - an error code

ACTIVE_SERVICE: TenancyStore | None = None
# The /api/v1/my router of the last registered app (the isolation test walks it).
MY_ROUTER: APIRouter | None = None

UsageProvider = Callable[[str], Awaitable[dict[str, Any]]]
CleanupHook = Callable[[dict[str, Any]], Awaitable[None]]


class MySpace:
    """Shared request plumbing for every ``/my`` route (one place, one order of checks)."""

    def __init__(self, ctx: ModuleContext, store: TenancyStore) -> None:
        self.ctx = ctx
        self.store = store
        self.usage_providers: list[UsageProvider] = []
        self.cleanup: dict[str, CleanupHook] = {}
        self.after_quota_change: list[Callable[[], Awaitable[None]]] = []

    def fail(self, exc: TenancyError) -> JSONResponse:
        extra = {key: value for key, value in exc.extra.items() if value is not None}
        return self.ctx.error_payload(  # type: ignore[call-arg]
            exc.code, exc.message, exc.status_code, fields=exc.fields, **extra
        )

    async def context(self, request: Request, *, write: bool = False,
                      path_ws: str | None = None) -> WorkspaceContext:
        principal = self.ctx.require_principal(request, None)
        if principal.must_change_password:
            raise StarletteHTTPException(status_code=403, detail=PASSWORD_CHANGE_REQUIRED)
        if write:
            self.ctx.require_csrf(request, principal)
        wctx = await asyncio.to_thread(
            self.store.resolve, principal,
            requested=path_ws if path_ws is not None else request.headers.get("x-workspace"),
            view_as_token=request.headers.get("x-view-as"),
            client_ip=request.client.host if request.client else None,
        )
        if wctx.view_as is not None:
            # docs/43 §2: every request of a «view as» session is on the record.
            await self.audit(wctx, "tenancy.view_as.request", "http",
                             f"{request.method} {request.url.path}")
        return wctx

    async def audit(self, wctx: WorkspaceContext, action: str, object_type: str,
                    object_id: str | None, result: str = "success") -> None:
        await asyncio.to_thread(self.store.audit, wctx, action, object_type, object_id, result)

    async def body(self, request: Request) -> Any:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise TenancyError("request_too_large", 413, "The request is too large")
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            raise TenancyError("validation_error", 422, "Invalid JSON body",
                               fields=[{"field": "body", "reason_code": "invalid_json"}]) from None

    async def usage(self, workspace_id: str) -> dict[str, Any]:
        usage: dict[str, Any] = await asyncio.to_thread(self.store.db_usage, workspace_id)
        usage.update({"s3_bytes": None, "s3_objects": None, "npm_bytes": 0, "pypi_bytes": 0})
        for provider in self.usage_providers:
            try:
                usage.update(await provider(workspace_id))
            except Exception:  # noqa: BLE001 - usage is informational; never break a page
                LOGGER.exception("usage provider failed")
        return usage

    async def remove_resources(self, workspace_id: str, mode: str) -> int:
        """``delete``: remove every resource; ``transfer``: hand them to the system."""
        items: list[dict[str, Any]] = []
        for kind in RESOURCE_KINDS:
            items.extend(await asyncio.to_thread(self.store.owned, kind, workspace_id))
        if mode == "delete":
            # Domains and keys before buckets, buckets before nothing else depends on them.
            order = {"bucket_domain": 0, "s3_identity": 1, "s3_bucket": 2, "dns_zone": 3,
                     "npm_scope": 4, "pypi_index": 5}
            for item in sorted(items, key=lambda entry: order.get(entry["kind"], 9)):
                hook = self.cleanup.get(item["kind"])
                if hook is not None:
                    try:
                        await hook(item)
                    except Exception:  # noqa: BLE001 - continue; the owner row goes anyway
                        LOGGER.exception("cleanup of %s %s failed", item["kind"],
                                         item["resource_id"])
                await asyncio.to_thread(self.store.release, item["kind"], item["resource_id"])
        return len(items)

    async def quota_changed(self) -> None:
        for hook in self.after_quota_change:
            try:
                await hook()
            except Exception:  # noqa: BLE001
                LOGGER.exception("quota change hook failed")


def _workspace_view(item: dict[str, Any], usage: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item["id"], "slug": item["slug"], "name": item["name"], "kind": item["kind"],
        "status": item["status"], "role": item.get("role"), "plan": item["plan"],
        "limits": item["limits"], "usage": usage, "created_at": item["created_at"],
    }


def _admin_view(item: dict[str, Any], usage: dict[str, Any]) -> dict[str, Any]:
    view = _workspace_view(item, usage)
    view.pop("role", None)
    return {**view, "plan_id": item["plan_id"], "quota_overrides": item["quota_overrides"],
            "owner": item["owner"], "members_count": item["members_count"]}


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE, MY_ROUTER
    store = TenancyStore(ctx.database, ctx.auth_store)
    ACTIVE_SERVICE = store
    space = MySpace(ctx, store)
    admin = APIRouter(prefix="/api/v1/admin", include_in_schema=False)
    my = APIRouter(prefix="/api/v1/my", include_in_schema=False)
    MY_ROUTER = my

    # ---------------------------------------------------------------- helpers
    async def admin_call(request: Request, work: Callable[..., Awaitable[Any]], *,
                         write: bool = False, permission: str = "tenancy:admin") -> Any:
        principal = ctx.require_principal(request, permission)
        if write:
            ctx.require_csrf(request, principal)
        try:
            body = await space.body(request) if write else None
            return await work(principal, body)
        except TenancyError as exc:
            return space.fail(exc)

    async def my_call(request: Request, work: Callable[..., Awaitable[Any]], *,
                      write: bool = False, path_ws: str | None = None) -> Any:
        try:
            wctx = await space.context(request, write=write, path_ws=path_ws)
            body = await space.body(request) if write else None
            return await work(wctx, body)
        except TenancyError as exc:
            return space.fail(exc)

    # ================================================================ admin area
    @admin.get("/tenancy/settings", response_model=None)
    async def tenancy_settings(request: Request) -> Any:
        async def work(_principal: Any, _body: Any) -> Any:
            return await asyncio.to_thread(store.get_settings)

        return await admin_call(request, work)

    @admin.put("/tenancy/settings", response_model=None)
    async def put_tenancy_settings(request: Request) -> Any:
        async def work(principal: Any, body: Any) -> Any:
            return await asyncio.to_thread(store.put_settings, body, principal.user_id)

        return await admin_call(request, work, write=True)

    @admin.get("/plans", response_model=None)
    async def list_plans(request: Request) -> Any:
        async def work(_principal: Any, _body: Any) -> Any:
            return {"items": await asyncio.to_thread(store.list_plans)}

        return await admin_call(request, work)

    @admin.post("/plans", status_code=201, response_model=None)
    async def create_plan(request: Request) -> Any:
        async def work(principal: Any, body: Any) -> Any:
            return await asyncio.to_thread(store.create_plan, body, principal.user_id)

        return await admin_call(request, work, write=True)

    @admin.put("/plans/{plan_id}", response_model=None)
    async def update_plan(plan_id: str, request: Request) -> Any:
        async def work(principal: Any, body: Any) -> Any:
            result = await asyncio.to_thread(store.update_plan, plan_id, body, principal.user_id)
            await space.quota_changed()
            return result

        return await admin_call(request, work, write=True)

    @admin.delete("/plans/{plan_id}", response_model=None)
    async def delete_plan(plan_id: str, request: Request) -> Any:
        async def work(principal: Any, _body: Any) -> Any:
            return await asyncio.to_thread(store.delete_plan, plan_id, principal.user_id)

        return await admin_call(request, work, write=True)

    @admin.get("/workspaces", response_model=None)
    async def list_workspaces(request: Request, query: str | None = Query(None, max_length=100),
                              status: str | None = Query(None, max_length=16)) -> Any:
        async def work(_principal: Any, _body: Any) -> Any:
            items = await asyncio.to_thread(store.list_workspaces, query, status)
            return {"items": [_admin_view(item, await space.usage(item["id"]))
                              for item in items]}

        return await admin_call(request, work)

    @admin.get("/workspaces/{workspace_id}", response_model=None)
    async def workspace_detail(workspace_id: str, request: Request) -> Any:
        async def work(_principal: Any, _body: Any) -> Any:
            item = await asyncio.to_thread(store.workspace_row, workspace_id)
            members = await asyncio.to_thread(store.list_members, workspace_id)
            resources = await asyncio.to_thread(store.list_ownership, None, workspace_id)
            return {**_admin_view(item, await space.usage(workspace_id)), "members": members,
                    "resources": [{key: value for key, value in entry.items()
                                   if key not in {"workspace_id", "workspace_slug"}}
                                  for entry in resources]}

        return await admin_call(request, work)

    @admin.patch("/workspaces/{workspace_id}", response_model=None)
    async def patch_workspace(workspace_id: str, request: Request) -> Any:
        async def work(principal: Any, body: Any) -> Any:
            item = await asyncio.to_thread(store.admin_update, workspace_id, body,
                                           principal.user_id)
            await space.quota_changed()
            return _admin_view(item, await space.usage(workspace_id))

        return await admin_call(request, work, write=True)

    @admin.delete("/workspaces/{workspace_id}", response_model=None)
    async def delete_workspace(workspace_id: str, request: Request,
                               confirmation: str = Query("", max_length=64),
                               mode: str = Query("delete", max_length=16)) -> Any:
        async def work(principal: Any, _body: Any) -> Any:
            item = await asyncio.to_thread(store.workspace_row, workspace_id)
            if mode not in {"delete", "transfer"}:
                raise TenancyError("invalid_request", 422, "mode is delete or transfer",
                                   fields=[{"field": "mode", "reason_code": "invalid_choice"}])
            if confirmation != item["slug"]:
                raise TenancyError("confirmation_mismatch", 422, "Type the workspace name",
                                   fields=[{"field": "confirmation", "reason_code": "incorrect"}],
                                   expected_confirmation=item["slug"])
            async with store.alock(workspace_id):
                count = await space.remove_resources(workspace_id, mode)
                await asyncio.to_thread(store.delete_workspace_row, workspace_id,
                                        principal.user_id)
            await space.quota_changed()
            key = "removed" if mode == "delete" else "transferred"
            return {"deleted": True, "mode": mode, "resources": {key: count}}

        return await admin_call(request, work, write=True)

    @admin.get("/ownership", response_model=None)
    async def ownership(request: Request, kind: str | None = Query(None, max_length=24),
                        workspace_id: str | None = Query(None, max_length=16)) -> Any:
        async def work(_principal: Any, _body: Any) -> Any:
            return {"items": await asyncio.to_thread(store.list_ownership, kind, workspace_id)}

        return await admin_call(request, work)

    @admin.post("/ownership/transfer", response_model=None)
    async def transfer(request: Request) -> Any:
        async def work(principal: Any, body: Any) -> Any:
            if not isinstance(body, dict):
                raise TenancyError("invalid_request", 422, "The request must be an object")
            result = await asyncio.to_thread(
                store.transfer, body.get("kind"), body.get("resource_id"),
                body.get("workspace_id"), principal.user_id)
            await space.quota_changed()
            return result

        return await admin_call(request, work, write=True)

    @admin.post("/workspaces/{workspace_id}/view-as", status_code=201, response_model=None)
    async def view_as(workspace_id: str, request: Request) -> Any:
        principal = ctx.require_principal(request, "tenancy:admin")
        ctx.require_csrf(request, principal)
        try:
            if principal.session_id is None:
                raise TenancyError("forbidden", 403, "«View as» needs a signed-in admin",
                                   required="session")
            body = await space.body(request)
            write = body.get("write", False) if isinstance(body, dict) else False
            if not isinstance(write, bool):
                raise TenancyError("invalid_request", 422, "write must be true or false",
                                   fields=[{"field": "write", "reason_code": "invalid_type"}])
            if write and not principal.allows("tenancy:impersonate_write"):
                raise StarletteHTTPException(status_code=403)
            return await asyncio.to_thread(store.start_view_as, principal, workspace_id, write)
        except TenancyError as exc:
            return space.fail(exc)

    @admin.delete("/view-as", response_model=None)
    async def end_view_as(request: Request) -> Any:
        principal = ctx.require_principal(request, "tenancy:admin")
        ctx.require_csrf(request, principal)
        ended = await asyncio.to_thread(store.end_view_as, principal,
                                        request.headers.get("x-view-as"))
        return {"ended": ended}

    @admin.get("/signups", response_model=None)
    async def signups(request: Request, status: str | None = Query("pending", max_length=16)
                      ) -> Any:
        async def work(_principal: Any, _body: Any) -> Any:
            return {"items": await asyncio.to_thread(store.list_signups, status or None)}

        return await admin_call(request, work, permission="tenancy:admin")

    @admin.post("/signups/{signup_id}/approve", response_model=None)
    async def approve(signup_id: str, request: Request) -> Any:
        async def work(principal: Any, body: Any) -> Any:
            plan_id = body.get("plan_id") if isinstance(body, dict) else None
            return await asyncio.to_thread(store.decide_signup, signup_id, True,
                                           principal.user_id, plan_id)

        return await admin_call(request, work, write=True)

    @admin.post("/signups/{signup_id}/reject", response_model=None)
    async def reject(signup_id: str, request: Request) -> Any:
        async def work(principal: Any, _body: Any) -> Any:
            return await asyncio.to_thread(store.decide_signup, signup_id, False,
                                           principal.user_id)

        return await admin_call(request, work, write=True)

    # ================================================================ my space
    async def workspaces_for(wctx: WorkspaceContext) -> list[dict[str, Any]]:
        if wctx.view_as is not None or wctx.via_token:
            item = await asyncio.to_thread(store.workspace_row, wctx.workspace_id)
            items = [{**item, "role": wctx.role}]
        else:
            items = await asyncio.to_thread(store.memberships, wctx.user_id)
        return [_workspace_view(item, await space.usage(item["id"])) for item in items]

    @my.get("/me", response_model=None)
    async def me(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            principal = wctx.principal
            return {
                "user": {"id": principal.user_id, "username": principal.username,
                         "display_name": principal.display_name, "email": principal.email,
                         "role": principal.role},
                "workspaces": await workspaces_for(wctx),
                "current": wctx.workspace_id,
                "view_as": None if wctx.view_as is None else {
                    "workspace_id": wctx.workspace_id, "write": wctx.view_as["write"],
                    "expires_at": wctx.view_as["expires_at"],
                    "admin_user_id": wctx.view_as["admin_user_id"]},
            }

        return await my_call(request, work)

    @my.get("/activity", response_model=None)
    async def activity(request: Request, before_id: int | None = Query(None, ge=1),
                       limit: int = Query(50, ge=1, le=200)) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            items = await asyncio.to_thread(store.activity, wctx.workspace_id, before_id, limit)
            return {"items": items,
                    "next_before_id": items[-1]["id"] if len(items) == limit else None}

        return await my_call(request, work)

    @my.post("/workspaces", status_code=201, response_model=None)
    async def create_workspace(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any) -> Any:
            wctx.need_session()
            if not isinstance(body, dict):
                raise TenancyError("invalid_request", 422, "The request must be an object")
            unknown = sorted(set(body) - {"name", "slug"})
            if unknown:
                raise TenancyError("invalid_request", 422, "Unknown fields", fields=[
                    {"field": key, "reason_code": "unknown_field"} for key in unknown])
            workspace_id = await asyncio.to_thread(store.create_team, wctx.user_id,
                                                   body.get("name"), body.get("slug"))
            item = await asyncio.to_thread(store.workspace_row, workspace_id)
            return _workspace_view({**item, "role": "owner"}, await space.usage(workspace_id))

        return await my_call(request, work, write=True)

    @my.patch("/workspaces/{workspace_id}", response_model=None)
    async def rename_workspace(workspace_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any) -> Any:
            wctx.need("my.workspace:admin")
            wctx.need_session()
            if not isinstance(body, dict) or set(body) - {"name"}:
                raise TenancyError("invalid_request", 422, "Only the name can change",
                                   fields=[{"field": "body", "reason_code": "unknown_field"}])
            await asyncio.to_thread(store.rename, wctx.workspace_id, body.get("name"),
                                    wctx.user_id)
            item = await asyncio.to_thread(store.workspace_row, wctx.workspace_id)
            return _workspace_view({**item, "role": wctx.role},
                                   await space.usage(wctx.workspace_id))

        return await my_call(request, work, write=True, path_ws=workspace_id)

    @my.delete("/workspaces/{workspace_id}", response_model=None)
    async def delete_my_workspace(workspace_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any) -> Any:
            wctx.need("my.workspace:owner")
            wctx.need_session()
            if wctx.kind != "team":
                raise TenancyError("personal_workspace", 409,
                                   "Your personal workspace cannot be deleted")
            confirmation = body.get("confirmation") if isinstance(body, dict) else None
            if confirmation != wctx.slug:
                raise TenancyError("confirmation_mismatch", 422, "Type the workspace name",
                                   fields=[{"field": "confirmation", "reason_code": "incorrect"}],
                                   expected_confirmation=wctx.slug)
            async with store.alock(wctx.workspace_id):
                await space.remove_resources(wctx.workspace_id, "delete")
                await asyncio.to_thread(store.delete_workspace_row, wctx.workspace_id,
                                        wctx.user_id)
            await space.quota_changed()
            return {"deleted": True}

        return await my_call(request, work, write=True, path_ws=workspace_id)

    # ---------------------------------------------------------------- members
    @my.get("/workspaces/{workspace_id}/members", response_model=None)
    async def members(workspace_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            return {"items": await asyncio.to_thread(store.list_members, wctx.workspace_id)}

        return await my_call(request, work, path_ws=workspace_id)

    @my.post("/workspaces/{workspace_id}/members", status_code=201, response_model=None)
    async def add_member(workspace_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any) -> Any:
            wctx.need("my.workspace:admin")
            wctx.need_session()
            if not isinstance(body, dict) or set(body) - {"user", "role"}:
                raise TenancyError("invalid_request", 422, "Send {user, role}",
                                   fields=[{"field": "body", "reason_code": "invalid"}])
            return await asyncio.to_thread(store.add_member, wctx, body.get("user"),
                                           body.get("role"))

        return await my_call(request, work, write=True, path_ws=workspace_id)

    @my.patch("/workspaces/{workspace_id}/members/{user_id}", response_model=None)
    async def change_member(workspace_id: str, user_id: int, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any) -> Any:
            wctx.need("my.workspace:admin")
            wctx.need_session()
            if not isinstance(body, dict) or set(body) - {"role"}:
                raise TenancyError("invalid_request", 422, "Send {role}",
                                   fields=[{"field": "body", "reason_code": "invalid"}])
            return await asyncio.to_thread(store.change_member, wctx, user_id, body.get("role"))

        return await my_call(request, work, write=True, path_ws=workspace_id)

    @my.delete("/workspaces/{workspace_id}/members/{user_id}", response_model=None)
    async def remove_member(workspace_id: str, user_id: int, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            wctx.need_session()
            if user_id != wctx.user_id:
                wctx.need("my.workspace:admin")
            elif wctx.status == "suspended":
                wctx.need("my.workspace:admin")
            await asyncio.to_thread(store.remove_member, wctx, user_id)
            return {"removed": user_id}

        return await my_call(request, work, write=True, path_ws=workspace_id)

    # ---------------------------------------------------------------- invites
    @my.get("/workspaces/{workspace_id}/invites", response_model=None)
    async def invites(workspace_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            if not wctx.can("my.workspace:admin"):
                raise TenancyError("forbidden", 403, "Only workspace admins see invites",
                                   required="my.workspace:admin")
            return {"items": await asyncio.to_thread(store.list_invites, wctx.workspace_id)}

        return await my_call(request, work, path_ws=workspace_id)

    @my.post("/workspaces/{workspace_id}/invites", status_code=201, response_model=None)
    async def create_invite(workspace_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any) -> Any:
            wctx.need("my.workspace:admin")
            wctx.need_session()
            if not isinstance(body, dict) or set(body) - {"email", "role"}:
                raise TenancyError("invalid_request", 422, "Send {email, role}",
                                   fields=[{"field": "body", "reason_code": "invalid"}])
            return await asyncio.to_thread(store.create_invite, wctx, body.get("email"),
                                           body.get("role"))

        return await my_call(request, work, write=True, path_ws=workspace_id)

    @my.delete("/workspaces/{workspace_id}/invites/{invite_id}", response_model=None)
    async def revoke_invite(workspace_id: str, invite_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            wctx.need("my.workspace:admin")
            wctx.need_session()
            await asyncio.to_thread(store.revoke_invite, wctx, invite_id)
            return {"revoked": invite_id}

        return await my_call(request, work, write=True, path_ws=workspace_id)

    @my.post("/invites/accept", response_model=None)
    async def accept_invite(request: Request) -> Any:
        principal = ctx.require_principal(request, None)
        ctx.require_csrf(request, principal)
        try:
            if not await asyncio.to_thread(store.enabled):
                raise TenancyError("tenancy_disabled", 404, "My space is not turned on")
            if principal.session_id is None or request.headers.get("x-view-as"):
                raise not_found()
            body = await space.body(request)
            token = body.get("token") if isinstance(body, dict) else None
            return await asyncio.to_thread(store.accept_invite, principal, token)
        except TenancyError as exc:
            return space.fail(exc)

    # ---------------------------------------------------------------- API keys
    @my.get("/tokens", response_model=None)
    async def tokens(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            return {"items": await asyncio.to_thread(store.list_tokens, wctx)}

        return await my_call(request, work)

    @my.post("/tokens", status_code=201, response_model=None)
    async def create_token(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any) -> Any:
            wctx.need_session()
            if wctx.status == "suspended":
                raise TenancyError("workspace_suspended", 423,
                                   "This workspace is suspended; it is read-only")
            wctx.feature("api_tokens")
            return await asyncio.to_thread(store.create_token, wctx, body)

        return await my_call(request, work, write=True)

    @my.delete("/tokens/{token_id}", response_model=None)
    async def revoke_token(token_id: int, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any) -> Any:
            wctx.need_session()
            await asyncio.to_thread(store.revoke_token, wctx, token_id)
            return {"revoked": token_id}

        return await my_call(request, work, write=True)

    # ---------------------------------------------------------------- resources
    from . import my_dns, my_packages, my_s3

    my_dns.register_routes(space, my)
    my_s3.register_routes(space, my)
    my_packages.register_routes(space, my)

    async def start() -> None:
        await asyncio.to_thread(store.ensure_builtin_plans)

    ctx.start_hooks.append(start)
    ctx.routers.append(admin)
    ctx.routers.append(my)
