from __future__ import annotations

import re
import uuid
from contextvars import ContextVar

from starlette.types import ASGIApp, Message, Receive, Scope, Send

correlation_id_context: ContextVar[str] = ContextVar("correlation_id", default="")
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class RequestSecurityMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied = headers.get(b"x-request-id", b"").decode("ascii", errors="ignore")
        request_id = supplied if _SAFE_REQUEST_ID.fullmatch(supplied) else str(uuid.uuid4())
        token = correlation_id_context.set(request_id)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = list(message.get("headers", []))
                response_headers.extend(
                    [
                        (b"x-request-id", request_id.encode("ascii")),
                        # Lets domain verification (docs/35 §5) recognise the panel
                        # behind a proxy; carries no version or other detail.
                        (b"x-mrk-service", b"panel"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                        (
                            b"content-security-policy",
                            b"default-src 'self'; script-src 'self'; "
                            b"style-src 'self' 'unsafe-inline'; "
                            b"img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
                            b"object-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
                            b"form-action 'self'",
                        ),
                        (b"cache-control", b"no-store"),
                    ]
                )
                message["headers"] = response_headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            correlation_id_context.reset(token)


class TrustedHostsHolder:
    """Allowed Host names = static ``MRK_TRUSTED_HOSTS`` ∪ runtime extras (panel domains).

    Extras are replaced as a whole (``set_extra``) by the services module when panel
    domains change, so no restart is needed. Same patterns as Starlette's
    TrustedHostMiddleware: exact names, ``*.example.com`` and ``*`` (any).
    """

    def __init__(self, static_hosts: tuple[str, ...] | list[str]) -> None:
        for pattern in static_hosts:
            if "*" in pattern[1:] or (
                pattern.startswith("*") and pattern != "*" and not pattern.startswith("*.")
            ):
                raise ValueError("Domain wildcard patterns must be like '*.example.com'.")
        self.static = tuple(pattern.lower() for pattern in static_hosts)
        self.extra: tuple[str, ...] = ()

    def set_extra(self, hosts: list[str] | tuple[str, ...]) -> None:
        self.extra = tuple(
            dict.fromkeys(
                host.lower() for host in hosts if host and "*" not in host and host.isascii()
            )
        )

    def allowed(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*self.static, *self.extra)))

    def allows(self, host: str) -> tuple[bool, bool]:
        """(valid, www_redirect_candidate) for a lowercase host without port."""
        found_www = False
        for pattern in self.allowed():
            if pattern == "*":
                return True, False
            if host == pattern or (pattern.startswith("*") and host.endswith(pattern[1:])):
                return True, False
            if "www." + host == pattern:
                found_www = True
        return False, found_www


class DynamicTrustedHostMiddleware:
    """Starlette's TrustedHostMiddleware, reading the allowed list on every request."""

    def __init__(self, app: ASGIApp, holder: TrustedHostsHolder, www_redirect: bool = True) -> None:
        self.app = app
        self.holder = holder
        self.www_redirect = www_redirect

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        from starlette._utils import parse_host_header
        from starlette.datastructures import URL, Headers
        from starlette.responses import PlainTextResponse, RedirectResponse, Response

        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        parsed = parse_host_header(headers.get("host"))
        if "*" in self.holder.allowed():
            await self.app(scope, receive, send)
            return
        if parsed is None:
            await PlainTextResponse("Invalid host header", status_code=400)(scope, receive, send)
            return
        valid, www = self.holder.allows(parsed.host.lower())
        if valid:
            await self.app(scope, receive, send)
            return
        response: Response
        if www and self.www_redirect:
            url = URL(scope=scope)
            response = RedirectResponse(url=str(url.replace(netloc="www." + url.netloc)))
        else:
            response = PlainTextResponse("Invalid host header", status_code=400)
        await response(scope, receive, send)


# request.state key where a route stores a refreshed session cookie (``Set-Cookie`` value).
SESSION_RENEWAL_STATE = "mrk_session_cookie"


class SessionCookieRenewalMiddleware:
    """Re-send the session cookie when the request extended a sliding session.

    Authentication runs deep inside route handlers, which do not own the response;
    they leave the new ``Set-Cookie`` value in ``request.state`` and this adds it,
    unless the response already sets that cookie (sign-in, refresh, sign-out).
    """

    def __init__(self, app: ASGIApp, cookie_name: str) -> None:
        self.app = app
        self.prefix = cookie_name.encode("ascii") + b"="

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # Created here so every copy of the scope shares this one dict.
        state = scope.setdefault("state", {})

        async def send_with_cookie(message: Message) -> None:
            if message["type"] == "http.response.start":
                value = state.get(SESSION_RENEWAL_STATE)
                if isinstance(value, bytes):
                    headers = list(message.get("headers", []))
                    if not any(
                        key.lower() == b"set-cookie" and item.startswith(self.prefix)
                        for key, item in headers
                    ):
                        headers.append((b"set-cookie", value))
                        message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_cookie)
