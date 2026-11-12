"""Sign-in security API: sessions, two-step sign-in (TOTP) and single sign-on (OIDC).

* ``POST /api/v1/auth/login/mfa`` finishes a sign-in that needs the second step.
* ``/api/v1/auth/mfa/*``: the signed-in person's own two-step sign-in.
* ``/api/v1/auth/sessions``: the person's own open sessions.
* ``/api/v1/auth/mfa/policy`` and ``/api/v1/users/{id}/mfa/reset``: people management.
* ``/api/v1/auth/oidc/*``: settings (owner), start and callback of the SSO flow.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from .auth import AuthStore, FieldError, MfaChallenge, Principal
from .auth_mfa import TwoStep
from .config import Settings
from .middleware import SESSION_RENEWAL_STATE, correlation_id_context
from .oidc import (
    CALLBACK_PATH,
    STATE_COOKIE,
    STATE_COOKIE_PATH,
    STATE_TTL_SECONDS,
    OidcError,
    OidcService,
)

LOGGER = logging.getLogger(__name__)

SESSION_COOKIE = "mrk_session"
MFA_COOKIE = "mrk_mfa"
MFA_COOKIE_PATH = "/api/v1/auth/login/mfa"
MFA_METHODS = ("totp", "recovery_code")
_SAFE_CODE = re.compile(r"[^a-z0-9_]")


# ----- cookies and the session response -------------------------------------------------


def session_cookie_kwargs(settings: Settings, principal: Principal) -> dict[str, Any]:
    """Persistent until the absolute end with "keep me signed in", else a browser-session cookie."""
    max_age: int | None = None
    if principal.session_remember and principal.session_absolute_expires_at:
        max_age = max(0, principal.session_absolute_expires_at - int(time.time()))
    return {
        "max_age": max_age,
        "httponly": True,
        "secure": settings.auth_cookie_secure,
        "samesite": "strict",
        "path": "/",
    }


def set_session_cookie(
    response: Response, settings: Settings, token: str, principal: Principal
) -> None:
    response.set_cookie(SESSION_COOKIE, token, **session_cookie_kwargs(settings, principal))


def session_cookie_header(settings: Settings, token: str, principal: Principal) -> bytes:
    holder = Response()
    set_session_cookie(holder, settings, token, principal)
    for key, value in holder.raw_headers:
        if key == b"set-cookie":
            return value
    raise RuntimeError("no cookie header")


def principal_payload(principal: Principal) -> dict[str, object]:
    return {
        "id": principal.user_id,
        "username": principal.username,
        "display_name": principal.display_name,
        "email": principal.email,
        "role": principal.role,
        "permissions": sorted(principal.permissions),
        "must_change_password": principal.must_change_password,
        "mfa_enabled": principal.mfa_enabled,
        "must_enroll_mfa": principal.must_enroll_mfa,
    }


def mfa_required_payload(challenge: MfaChallenge) -> dict[str, object]:
    return {
        "status": "mfa_required",
        "mfa_required": True,
        "challenge": challenge.token,
        "expires_at": challenge.expires_at,
        "methods": list(MFA_METHODS),
    }


def session_response(
    settings: Settings,
    result: tuple[str, str, Principal] | MfaChallenge,
    *,
    status_code: int = 200,
    extra: dict[str, object] | None = None,
) -> JSONResponse:
    """The JSON + cookie answer for a sign-in, or the second-step challenge."""
    if isinstance(result, MfaChallenge):
        return JSONResponse({**mfa_required_payload(result), **(extra or {})})
    token, csrf, principal = result
    response = JSONResponse(
        {
            "user": principal_payload(principal),
            "csrf_token": csrf,
            "must_change_password": principal.must_change_password,
            **(extra or {}),
        },
        status_code=status_code,
    )
    set_session_cookie(response, settings, token, principal)
    return response


def mark_session_renewed(request: Request, settings: Settings, principal: Principal) -> None:
    """Called after authentication: re-send the cookie when the session slid forward."""
    if principal.session_id is None or not principal.session_renewed:
        return
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        setattr(request.state, SESSION_RENEWAL_STATE,
                session_cookie_header(settings, token, principal))


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def user_agent(request: Request) -> str | None:
    return request.headers.get("user-agent")


def redirect_uri_for(request: Request, settings: Settings) -> str:
    """https://<panel host>/api/v1/auth/oidc/callback (the host passed TrustedHost)."""
    scheme = request.url.scheme
    if scheme == "http" and settings.auth_cookie_secure:
        # Behind a TLS proxy that did not forward the scheme.
        scheme = "https"
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}{CALLBACK_PATH}"


# ----- request bodies ------------------------------------------------------------------


class MfaLoginRequest(BaseModel):
    challenge: str | None = Field(default=None, max_length=4096)
    code: str | None = Field(default=None, max_length=16)
    recovery_code: str | None = Field(default=None, max_length=32)
    remember: bool | None = None


class MfaStartRequest(BaseModel):
    current_password: str | None = Field(default=None, max_length=256)


class MfaCodeRequest(BaseModel):
    code: str = Field(min_length=1, max_length=16)


class MfaProofRequest(BaseModel):
    current_password: str | None = Field(default=None, max_length=256)
    code: str | None = Field(default=None, max_length=16)
    recovery_code: str | None = Field(default=None, max_length=32)


class MfaPolicyRequest(BaseModel):
    mode: Literal["off", "all", "roles"]
    roles: list[str] = Field(default_factory=list, max_length=64)


class OidcSettingsRequest(BaseModel):
    enabled: bool | None = None
    display_name: str | None = Field(default=None, max_length=60)
    issuer: str | None = Field(default=None, max_length=255)
    client_id: str | None = Field(default=None, max_length=255)
    client_secret: str | None = Field(default=None, max_length=1024)
    clear_client_secret: bool | None = None
    scopes: str | None = Field(default=None, max_length=512)
    allowed_domains: list[str] | None = Field(default=None, max_length=50)
    email_claim: str | None = Field(default=None, max_length=64)
    username_claim: str | None = Field(default=None, max_length=64)
    require_email_verified: bool | None = None
    auto_create: bool | None = None
    default_role: str | None = Field(default=None, max_length=64)
    sso_only: bool | None = None
    trust_idp_mfa: bool | None = None
    token_auth_method: Literal["client_secret_post", "client_secret_basic"] | None = None
    proxy_id: str | None = Field(default=None, max_length=64)
    allow_private_network: bool | None = None


# ----- the router ----------------------------------------------------------------------


@dataclass(slots=True)
class AuthApiDeps:
    settings: Settings
    auth_store: AuthStore
    two_step: TwoStep
    oidc: OidcService
    require_principal: Callable[..., Principal]
    require_csrf: Callable[[Request, Principal], None]
    error_payload: Callable[..., JSONResponse]
    field_error: Callable[..., JSONResponse]
    tenancy: Callable[[], Any]


def build_router(deps: AuthApiDeps) -> APIRouter:
    router = APIRouter(include_in_schema=False)
    settings = deps.settings
    auth_store = deps.auth_store
    two_step = deps.two_step
    oidc = deps.oidc

    def session_principal(request: Request, *, csrf: bool = True) -> Principal:
        principal = deps.require_principal(request)
        if principal.session_id is None:
            # App keys never manage the sign-in of the person who made them.
            raise StarletteHTTPException(status_code=403)
        if csrf:
            deps.require_csrf(request, principal)
        return principal

    # ----- second step of a sign-in ------------------------------------------------
    @router.post("/api/v1/auth/login/mfa", response_model=None)
    async def login_mfa(payload: MfaLoginRequest, request: Request) -> JSONResponse:
        challenge = payload.challenge or request.cookies.get(MFA_COOKIE)
        if not challenge:
            return deps.error_payload("mfa_challenge_invalid", "Sign in again", 401)
        code = (payload.code or "").strip() or None
        recovery = (payload.recovery_code or "").strip() or None
        try:
            token, csrf, principal, info = await asyncio.to_thread(
                two_step.complete_login, challenge, code, recovery, client_ip(request),
                correlation_id_context.get(), remember=payload.remember,
                user_agent=user_agent(request),
            )
        except FieldError as exc:
            response = deps.field_error(exc)
            if exc.code == "mfa_challenge_invalid":
                response.delete_cookie(MFA_COOKIE, path=MFA_COOKIE_PATH)
            return response
        response = session_response(
            settings, (token, csrf, principal),
            extra={"mfa_method": info["method"],
                   "recovery_codes_left": info["recovery_codes_left"]},
        )
        response.delete_cookie(MFA_COOKIE, path=MFA_COOKIE_PATH)
        return response

    # ----- my two-step sign-in -----------------------------------------------------------
    @router.get("/api/v1/auth/mfa")
    async def mfa_status(request: Request) -> dict[str, Any]:
        principal = session_principal(request, csrf=False)
        return await asyncio.to_thread(two_step.status, principal)

    @router.post("/api/v1/auth/mfa/totp/start", response_model=None)
    async def mfa_start(payload: MfaStartRequest, request: Request) -> JSONResponse:
        principal = session_principal(request)
        try:
            result = await asyncio.to_thread(
                two_step.start, principal, payload.current_password, client_ip(request),
                correlation_id_context.get(),
            )
        except FieldError as exc:
            return deps.field_error(exc)
        return JSONResponse(result)

    @router.post("/api/v1/auth/mfa/totp/confirm", response_model=None)
    async def mfa_confirm(payload: MfaCodeRequest, request: Request) -> JSONResponse:
        principal = session_principal(request)
        try:
            result = await asyncio.to_thread(
                two_step.confirm, principal, payload.code, client_ip(request),
                correlation_id_context.get(),
            )
        except FieldError as exc:
            return deps.field_error(exc)
        return JSONResponse(result)

    @router.post("/api/v1/auth/mfa/recovery-codes", response_model=None)
    async def mfa_recovery_codes(payload: MfaProofRequest, request: Request) -> JSONResponse:
        principal = session_principal(request)
        try:
            result = await asyncio.to_thread(
                two_step.regenerate_recovery_codes, principal, payload.code,
                payload.recovery_code, client_ip(request), correlation_id_context.get(),
            )
        except FieldError as exc:
            return deps.field_error(exc)
        return JSONResponse(result)

    @router.post("/api/v1/auth/mfa/disable", response_model=None)
    async def mfa_disable(payload: MfaProofRequest, request: Request) -> JSONResponse:
        principal = session_principal(request)
        try:
            result = await asyncio.to_thread(
                two_step.disable, principal, payload.current_password, payload.code,
                payload.recovery_code, client_ip(request), correlation_id_context.get(),
            )
        except FieldError as exc:
            return deps.field_error(exc)
        return JSONResponse(result)

    # ----- my sessions -------------------------------------------------------------------
    @router.get("/api/v1/auth/sessions")
    async def my_sessions(request: Request) -> dict[str, Any]:
        principal = session_principal(request, csrf=False)
        items = await asyncio.to_thread(
            auth_store.list_sessions, principal.user_id, principal.session_id
        )
        return {
            "items": items,
            "idle_seconds": auth_store.session_ttl_seconds,
            "remember_idle_seconds": auth_store.session_remember_ttl_seconds,
            "max_age_seconds": auth_store.session_max_age_seconds,
        }

    @router.delete("/api/v1/auth/sessions/{session_id}", response_model=None)
    async def end_my_session(session_id: int, request: Request) -> JSONResponse:
        principal = session_principal(request)
        if session_id == principal.session_id:
            return deps.error_payload("use_sign_out", "Sign out to end this session", 409)
        changed = await asyncio.to_thread(
            auth_store.revoke_own_session, principal, session_id, client_ip(request),
            correlation_id_context.get(),
        )
        if not changed:
            return deps.error_payload("session_not_found", "Not found", 404)
        return JSONResponse({"status": "revoked"})

    @router.post("/api/v1/auth/sessions/revoke-others", response_model=None)
    async def end_other_sessions(request: Request) -> JSONResponse:
        principal = session_principal(request)
        result = await asyncio.to_thread(
            auth_store.revoke_user_sessions, principal.user_id, principal, False,
            client_ip(request), correlation_id_context.get(),
        )
        return JSONResponse(result)

    # ----- people management ---------------------------------------------------------
    @router.get("/api/v1/auth/mfa/policy")
    async def mfa_policy(request: Request) -> dict[str, Any]:
        deps.require_principal(request, "user:read")
        return await asyncio.to_thread(auth_store.mfa_policy)

    @router.put("/api/v1/auth/mfa/policy", response_model=None)
    async def set_mfa_policy(payload: MfaPolicyRequest, request: Request) -> JSONResponse:
        principal = deps.require_principal(request, "user:write")
        deps.require_csrf(request, principal)
        try:
            value = await asyncio.to_thread(
                auth_store.set_mfa_policy, payload.mode, payload.roles, principal,
                client_ip(request), correlation_id_context.get(),
            )
        except FieldError as exc:
            return deps.field_error(exc)
        return JSONResponse(value)

    @router.post("/api/v1/users/{user_id}/mfa/reset", response_model=None)
    async def reset_user_mfa(user_id: int, request: Request) -> JSONResponse:
        principal = deps.require_principal(request, "user:write")
        deps.require_csrf(request, principal)
        try:
            result = await asyncio.to_thread(
                two_step.admin_reset, user_id, principal, client_ip(request),
                correlation_id_context.get(),
            )
        except FieldError as exc:
            return deps.field_error(exc)
        except PermissionError as exc:
            permissions = getattr(exc, "permissions", None)
            return deps.error_payload("permission_escalation", str(exc), 403,
                                      permissions=permissions)
        return JSONResponse(result)

    # ----- single sign-on ------------------------------------------------------------------
    @router.get("/api/v1/auth/oidc/settings")
    async def oidc_settings(request: Request) -> dict[str, Any]:
        deps.require_principal(request, "user:read")
        return await asyncio.to_thread(
            oidc.public_settings, redirect_uri_for(request, settings)
        )

    @router.put("/api/v1/auth/oidc/settings", response_model=None)
    async def update_oidc_settings(payload: OidcSettingsRequest, request: Request
                                   ) -> JSONResponse:
        principal = deps.require_principal(request, "user:write")
        deps.require_csrf(request, principal)
        try:
            await asyncio.to_thread(
                oidc.update_settings, payload.model_dump(exclude_unset=True), principal,
                client_ip(request), correlation_id_context.get(),
            )
        except FieldError as exc:
            return deps.field_error(exc)
        except PermissionError as exc:
            return deps.error_payload("permission_escalation", str(exc), 403,
                                      permissions=getattr(exc, "permissions", None))
        return JSONResponse(
            await asyncio.to_thread(oidc.public_settings, redirect_uri_for(request, settings))
        )

    @router.post("/api/v1/auth/oidc/test", response_model=None)
    async def test_oidc(request: Request) -> JSONResponse:
        principal = deps.require_principal(request, "user:write")
        deps.require_csrf(request, principal)
        if principal.role != "owner":
            return deps.error_payload("owner_only", "Only an owner can do this", 403)
        try:
            result = await oidc.test_connection()
        except OidcError as exc:
            return JSONResponse({"ok": False, "code": exc.code, "reason": exc.reason})
        return JSONResponse(result)

    def sso_redirect(query: str) -> RedirectResponse:
        response = RedirectResponse(f"/?{query}", status_code=303)
        response.delete_cookie(STATE_COOKIE, path=STATE_COOKIE_PATH)
        return response

    @router.get("/api/v1/auth/oidc/start", response_model=None)
    async def oidc_start(request: Request, remember: str = "1") -> RedirectResponse:
        try:
            url, sealed = await oidc.begin(
                redirect_uri_for(request, settings), remember not in {"0", "false", "no"}
            )
        except OidcError as exc:
            await asyncio.to_thread(
                auth_store.record_audit, None, "auth.oidc.start", "session", exc.reason,
                "failure", client_ip(request), correlation_id_context.get(),
            )
            return sso_redirect(f"sso_error={exc.code}")
        response = RedirectResponse(url, status_code=303)
        # Lax, not Strict: the provider sends the browser back with a cross-site redirect.
        response.set_cookie(
            STATE_COOKIE, sealed, max_age=STATE_TTL_SECONDS, httponly=True,
            secure=settings.auth_cookie_secure, samesite="lax", path=STATE_COOKIE_PATH,
        )
        return response

    @router.get("/api/v1/auth/oidc/callback", response_model=None)
    async def oidc_callback(request: Request) -> RedirectResponse:
        params = request.query_params
        source_ip = client_ip(request)
        request_id = correlation_id_context.get()
        try:
            if params.get("error"):
                reason = _SAFE_CODE.sub("", str(params.get("error")).lower())[:40]
                raise OidcError("sso_idp_error", reason or "error")
            claims, active, remember = await oidc.finish(
                request.cookies.get(STATE_COOKIE), params.get("state"), params.get("code")
            )
            result, created = await asyncio.to_thread(
                oidc.sign_in, claims, active, remember=remember, source_ip=source_ip,
                request_id=request_id, user_agent=user_agent(request),
            )
        except OidcError as exc:
            if exc.code not in {"sso_no_account", "sso_email_unverified", "sso_email_missing",
                                "sso_domain_not_allowed", "sso_account_disabled",
                                "sso_account_conflict"}:
                # Account errors are audited by sign_in itself.
                await asyncio.to_thread(
                    auth_store.record_audit, None, "auth.oidc.login", "session", exc.reason,
                    "failure", source_ip, request_id,
                )
            return sso_redirect(f"sso_error={exc.code}")
        if created:
            await ensure_personal_space(result)
        if isinstance(result, MfaChallenge):
            response = sso_redirect("sso=mfa")
            response.set_cookie(
                MFA_COOKIE, result.token, max_age=max(1, result.expires_at - int(time.time())),
                httponly=True, secure=settings.auth_cookie_secure, samesite="lax",
                path=MFA_COOKIE_PATH,
            )
            return response
        token, _csrf, principal = result
        response = sso_redirect("sso=ok")
        set_session_cookie(response, settings, token, principal)
        return response

    async def ensure_personal_space(result: tuple[str, str, Principal] | MfaChallenge) -> None:
        """docs/43: a new «my space» account gets its personal workspace, as at sign-up."""
        tenancy = deps.tenancy()
        user_id = result.user_id if isinstance(result, MfaChallenge) else result[2].user_id
        try:
            if tenancy is not None and await asyncio.to_thread(tenancy.enabled):
                await asyncio.to_thread(tenancy.ensure_personal, user_id)
        except Exception:  # noqa: BLE001 - the account works; the workspace can be made later
            LOGGER.exception("cannot prepare the personal workspace of an SSO account")

    return router
