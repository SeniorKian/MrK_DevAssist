"""Notification center module (Gate 16, S5).

Channels (Telegram, Bale, email, webhook), routing rules, quiet hours, dedupe
and a persisted delivery queue with retry/backoff. Every other module reports
through ``ctx.events``; this module decides who is told and how.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import outbound
from ..module_context import SEVERITIES, Event, ModuleContext
from .notifications_engine import (
    DELIVERY_STATUSES,
    NotificationCenter,
    NotificationError,
    proxy_types_for,
)

ACTIVE_CENTER: NotificationCenter | None = None


async def _body(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise NotificationError("invalid_json", "request body must be JSON") from None


def build_router(ctx: ModuleContext, center: NotificationCenter) -> APIRouter:
    router = APIRouter(prefix="/api/v1/notifications", include_in_schema=False)

    def fail(exc: NotificationError) -> JSONResponse:
        return ctx.error_payload(exc.code, exc.message, exc.status_code)

    async def audit(
        user_id: int, action: str, object_type: str, object_id: str | None, result: str = "success"
    ) -> None:
        await asyncio.to_thread(ctx.audit, user_id, action, object_type, object_id, result)

    def writer(request: Request) -> Any:
        principal = ctx.require_principal(request, "notification:write")
        ctx.require_csrf(request, principal)
        return principal

    # ---- channels ----

    @router.get("/channels")
    async def list_channels(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "notification:read")
        return {"items": await asyncio.to_thread(center.list_channels)}

    @router.post("/channels", status_code=201, response_model=None)
    async def create_channel(request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            item = await asyncio.to_thread(center.create_channel, await _body(request))
        except NotificationError as exc:
            await audit(
                principal.user_id,
                "notification.channel.create",
                "notification_channel",
                None,
                "failure",
            )
            return fail(exc)
        await audit(
            principal.user_id, "notification.channel.create", "notification_channel", item["id"]
        )
        return item

    @router.patch("/channels/{channel_id}", response_model=None)
    async def update_channel(channel_id: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            item = await asyncio.to_thread(center.update_channel, channel_id, await _body(request))
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except NotificationError as exc:
            await audit(
                principal.user_id,
                "notification.channel.update",
                "notification_channel",
                channel_id,
                "failure",
            )
            return fail(exc)
        await audit(
            principal.user_id, "notification.channel.update", "notification_channel", channel_id
        )
        return item

    @router.delete("/channels/{channel_id}", response_model=None)
    async def delete_channel(channel_id: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            body = await _body(request)
            confirmation = body.get("confirmation") if isinstance(body, dict) else None
            item = await asyncio.to_thread(center.delete_channel, channel_id, confirmation)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except NotificationError as exc:
            return fail(exc)
        await audit(
            principal.user_id, "notification.channel.delete", "notification_channel", channel_id
        )
        return {"deleted": True, "id": item["id"]}

    @router.post("/channels/{channel_id}/test", response_model=None)
    async def test_channel(channel_id: str, request: Request) -> dict[str, Any]:
        principal = writer(request)
        try:
            result = await center.test_channel(channel_id)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        await audit(
            principal.user_id,
            "notification.channel.test",
            "notification_channel",
            channel_id,
            "success" if result.ok else "failure",
        )
        payload: dict[str, Any] = {"ok": result.ok, "latency_ms": result.latency_ms}
        if not result.ok:
            payload["error_code"] = result.error_code
        return payload

    # ---- rules ----

    @router.get("/rules")
    async def list_rules(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "notification:read")
        return {"items": await asyncio.to_thread(center.list_rules)}

    @router.post("/rules", status_code=201, response_model=None)
    async def create_rule(request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            item = await asyncio.to_thread(center.create_rule, await _body(request))
        except NotificationError as exc:
            return fail(exc)
        await audit(principal.user_id, "notification.rule.create", "notification_rule", item["id"])
        return item

    @router.patch("/rules/{rule_id}", response_model=None)
    async def update_rule(rule_id: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            item = await asyncio.to_thread(center.update_rule, rule_id, await _body(request))
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except NotificationError as exc:
            return fail(exc)
        await audit(principal.user_id, "notification.rule.update", "notification_rule", rule_id)
        return item

    @router.delete("/rules/{rule_id}", response_model=None)
    async def delete_rule(rule_id: str, request: Request) -> dict[str, Any] | Response:
        principal = writer(request)
        try:
            await asyncio.to_thread(center.delete_rule, rule_id)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        await audit(principal.user_id, "notification.rule.delete", "notification_rule", rule_id)
        return {"deleted": True, "id": rule_id}

    # ---- settings ----

    @router.get("/settings")
    async def get_settings(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "notification:read")
        return await asyncio.to_thread(center.get_settings)

    @router.put("/settings", response_model=None)
    async def put_settings(request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            value = await asyncio.to_thread(
                center.put_settings, await _body(request), principal.user_id
            )
        except NotificationError as exc:
            return fail(exc)
        await audit(
            principal.user_id,
            "notification.settings.update",
            "notification_settings",
            "notifications",
        )
        return value

    # ---- deliveries / test event ----

    @router.get("/deliveries", response_model=None)
    async def list_deliveries(
        request: Request, limit: int = 100, status: str | None = None
    ) -> dict[str, Any] | JSONResponse:
        ctx.require_principal(request, "notification:read")
        if not 1 <= limit <= 500:
            return ctx.error_payload("invalid_limit", "limit must be between 1 and 500", 422)
        if status and status not in DELIVERY_STATUSES:
            return ctx.error_payload(
                "invalid_status", f"status must be one of {', '.join(DELIVERY_STATUSES)}", 422
            )
        return {"items": await asyncio.to_thread(center.list_deliveries, limit, status or None)}

    @router.post("/test-event", response_model=None)
    async def test_event(request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            body = await _body(request)
        except NotificationError as exc:
            return fail(exc)
        severity = body.get("severity", "info") if isinstance(body, dict) else None
        if severity not in SEVERITIES:
            return ctx.error_payload(
                "invalid_severity", f"severity must be one of {', '.join(SEVERITIES)}", 422
            )
        event = Event(
            type="notification.test",
            severity=severity,
            title="DevAssist test event · رویداد آزمایشی DevAssist",
            message=f"Test event requested from the panel ({severity}).",
            module="notifications",
            # Each test is distinct so dedupe never swallows it.
            dedupe_key=f"notification.test:{secrets.token_hex(8)}",
            details={"requested_by": principal.username},
        )
        created = await asyncio.to_thread(center.ingest, event)
        await audit(
            principal.user_id, "notification.test_event", "notification_event", "notification.test"
        )
        queued = sum(1 for item in created if item["status"] in ("pending", "delayed"))
        return {"queued": queued}

    return router


def register(ctx: ModuleContext) -> None:
    global ACTIVE_CENTER
    center = NotificationCenter(ctx.database, ctx.secret_store, ctx.network_settings)
    ACTIVE_CENTER = center
    ctx.events.subscribe(center.handle_event)
    ctx.routers.append(build_router(ctx, center))
    register_outbound(ctx, center)
    ctx.start_hooks.append(center.start)
    ctx.stop_hooks.append(center.stop)


def register_outbound(ctx: ModuleContext, center: NotificationCenter) -> None:
    """Expose channels in the central "service -> proxy" table."""

    def list_entries() -> list[dict[str, Any]]:
        return [
            {
                "id": item["id"],
                "name": item["name"],
                "group": item["kind"],
                "proxy_id": (item.get("config") or {}).get("proxy_id"),
            }
            for item in center.list_channels()
        ]

    def set_proxy(channel_id: str, proxy_id: str | None) -> None:
        try:
            center.update_channel(channel_id, {"config": {"proxy_id": proxy_id}})
        except NotificationError as exc:
            raise outbound.OutboundError(exc.code, exc.message, exc.status_code) from None

    outbound.outbound_registry(ctx.data_dir).register(
        outbound.OutboundProvider(
            kind="notification_channel",
            list_entries=list_entries,
            supported_types=lambda entry: proxy_types_for(str(entry.get("group"))),
            unsupported_code="proxy_type_unsupported_for_email",
            set_proxy=set_proxy,
            read_permission="notification:read",
            write_permission="notification:write",
        )
    )
