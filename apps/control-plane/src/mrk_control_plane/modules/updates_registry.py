"""Remote manifest digests: HEAD /v2/<repo>/manifests/<tag> with anonymous tokens.

One ``RegistryChecker`` lives for one check run: it caches bearer tokens per
(realm, service, scope) and the last ``ratelimit-*`` headers per endpoint.
Docker Hub's HEAD requests do not count against the pull quota, so the checker
never GETs a manifest from registry-1.docker.io. Errors are stable codes:
``auth_required``, ``not_found``, ``rate_limited``, ``unreachable``,
``proxy_unavailable``, ``digest_unavailable``.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

import httpx

from .. import outbound
from .updates_refs import DOCKER_HUB_API, MANIFEST_ACCEPT, ImageRef, parse_challenge
from .updates_refs import parse_rate_limit as _parse_rate_limit
from .updates_settings import Endpoint, endpoints_for, proxy_for

USER_AGENT = "MRK-UpdateCheck/1"
MAX_REDIRECTS = 3
MAX_TOKEN_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_REMOTE_DIGEST = re.compile(r"^sha(?:256:[a-f0-9]{64}|512:[a-f0-9]{128})$")


class Sender(Protocol):
    async def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        stream: bool = False,
    ) -> httpx.Response: ...


ClientFor = Callable[[str | None], Awaitable[Sender]]


@dataclass(slots=True)
class RemoteResult:
    endpoint: str
    digest: str | None = None
    media_type: str | None = None
    error_code: str | None = None
    error_detail: str | None = None
    status_code: int | None = None

    @property
    def ok(self) -> bool:
        return self.error_code is None and self.digest is not None


class CheckFailed(Exception):
    def __init__(self, code: str, detail: str | None = None, status: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail
        self.status = status


@dataclass(slots=True)
class RegistryChecker:
    settings: dict[str, Any]
    client_for: ClientFor
    clock: Callable[[], float] = time.time
    rate_limits: dict[str, dict[str, Any]] = field(default_factory=dict)
    _tokens: dict[tuple[str, str, str], tuple[str, float]] = field(default_factory=dict)
    _repo_tokens: dict[tuple[str, str], tuple[str, str, str]] = field(default_factory=dict)

    async def check(self, ref: ImageRef) -> RemoteResult:
        """Try the registry's mirrors in order (then the origin); first success wins.

        When everything fails, the first endpoint's error is reported: the mirror
        an operator configured is usually more telling than a blocked origin.
        """
        first: RemoteResult | None = None
        for endpoint in endpoints_for(ref.registry, self.settings):
            result = await self.check_endpoint(ref, endpoint)
            if result.ok:
                return result
            if first is None:
                first = result
        assert first is not None
        return first

    async def check_endpoint(self, ref: ImageRef, endpoint: Endpoint) -> RemoteResult:
        result = RemoteResult(endpoint=endpoint.label)
        try:
            client = await self.client_for(proxy_for(ref.registry, endpoint, self.settings))
            digest, media_type, status = await self._digest(client, endpoint, ref)
        except CheckFailed as exc:
            result.error_code, result.error_detail, result.status_code = (
                exc.code,
                exc.detail,
                exc.status,
            )
            return result
        except outbound.ProxyUnavailable:
            result.error_code, result.error_detail = "proxy_unavailable", "proxy_unavailable"
            return result
        except outbound.OutboundError as exc:
            result.error_code, result.error_detail = "unreachable", exc.code
            return result
        except httpx.ProxyError:
            result.error_code, result.error_detail = "proxy_unavailable", "proxy_error"
            return result
        except Exception as exc:  # never echo the message: it may contain URLs
            result.error_code, result.error_detail = "unreachable", outbound.error_code(exc)
            return result
        result.digest, result.media_type, result.status_code = digest, media_type, status
        return result

    # ----- HTTP -------------------------------------------------------------------
    async def _send(
        self,
        client: Sender,
        method: str,
        url: str,
        headers: dict[str, str],
        *,
        stream: bool = False,
    ) -> httpx.Response:
        """Send, following at most MAX_REDIRECTS redirects (Authorization dropped cross-host)."""
        current, current_headers = url, dict(headers)
        for _ in range(MAX_REDIRECTS + 1):
            response = await client.send(method, current, headers=current_headers, stream=stream)
            location = response.headers.get("location")
            if response.status_code not in (301, 302, 303, 307, 308) or not location:
                return response
            await response.aclose()
            target = urljoin(current, location)
            if urlsplit(target).hostname != urlsplit(current).hostname:
                current_headers.pop("Authorization", None)
            current = target
        raise CheckFailed("unreachable", "too_many_redirects")

    def _record_rate_limit(self, endpoint: Endpoint, response: httpx.Response) -> None:
        quota = _parse_rate_limit(response.headers)
        if quota is not None:
            self.rate_limits[endpoint.label] = {**quota, "checked_at": self.clock()}

    async def _digest(
        self, client: Sender, endpoint: Endpoint, ref: ImageRef
    ) -> tuple[str, str | None, int]:
        url = endpoint.manifest_url(ref.repository, ref.tag)
        headers = {"Accept": MANIFEST_ACCEPT, "User-Agent": USER_AGENT}
        repo = endpoint.repository(ref.repository)
        token = self._cached_repo_token(endpoint, repo)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = await self._send(client, "HEAD", url, headers)
        self._record_rate_limit(endpoint, response)
        if response.status_code == 401:
            challenge = parse_challenge(response.headers.get("www-authenticate"))
            if challenge is None or challenge[0] != "bearer" or not challenge[1].get("realm"):
                raise CheckFailed("auth_required", "credentials_required", 401)
            token = await self._token(client, endpoint, repo, challenge[1])
            headers["Authorization"] = f"Bearer {token}"
            response = await self._send(client, "HEAD", url, headers)
            self._record_rate_limit(endpoint, response)
        status = response.status_code
        if status in (401, 403):
            raise CheckFailed("auth_required", f"http_{status}", status)
        if status == 404:
            raise CheckFailed("not_found", "manifest_unknown", status)
        if status == 429:
            raise CheckFailed("rate_limited", "http_429", status)
        if status != 200:
            raise CheckFailed("unreachable", f"http_{status}", status)
        media_type = (response.headers.get("content-type") or "").split(";")[0].strip() or None
        digest = (response.headers.get("docker-content-digest") or "").strip().lower()
        if _REMOTE_DIGEST.fullmatch(digest):
            return digest, media_type, status
        if not self.settings.get("allow_get_fallback") or endpoint.netloc == DOCKER_HUB_API:
            raise CheckFailed("digest_unavailable", "no_docker_content_digest", status)
        return await self._digest_by_get(client, endpoint, url, headers)

    async def _digest_by_get(
        self, client: Sender, endpoint: Endpoint, url: str, headers: dict[str, str]
    ) -> tuple[str, str | None, int]:
        response = await self._send(client, "GET", url, headers, stream=True)
        try:
            self._record_rate_limit(endpoint, response)
            if response.status_code != 200:
                raise CheckFailed(
                    "unreachable", f"http_{response.status_code}", response.status_code
                )
            hasher = hashlib.sha256()
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_MANIFEST_BYTES:
                    raise CheckFailed("unreachable", "manifest_too_large", 200)
                hasher.update(chunk)
            header = (response.headers.get("docker-content-digest") or "").strip().lower()
            media_type = (response.headers.get("content-type") or "").split(";")[0].strip()
        finally:
            await response.aclose()
        digest = f"sha256:{hasher.hexdigest()}"
        if _REMOTE_DIGEST.fullmatch(header) and header.startswith("sha256:") and header != digest:
            raise CheckFailed("unreachable", "digest_mismatch", 200)
        return digest, media_type or None, 200

    # ----- tokens -----------------------------------------------------------------
    def _cached_repo_token(self, endpoint: Endpoint, repo: str) -> str | None:
        key = self._repo_tokens.get((endpoint.netloc, repo))
        if key is None:
            return None
        cached = self._tokens.get(key)
        if cached is None or cached[1] <= self.clock():
            return None
        return cached[0]

    async def _token(
        self, client: Sender, endpoint: Endpoint, repo: str, params: dict[str, str]
    ) -> str:
        realm = params["realm"]
        parts = urlsplit(realm)
        allowed = {"https"} if endpoint.scheme == "https" else {"https", "http"}
        if parts.scheme not in allowed or not parts.hostname:
            raise CheckFailed("auth_required", "invalid_token_realm", 401)
        service = params.get("service", "")
        scope = params.get("scope") or f"repository:{repo}:pull"
        key = (realm, service, scope)
        cached = self._tokens.get(key)
        if cached is not None and cached[1] > self.clock():
            self._repo_tokens[(endpoint.netloc, repo)] = key
            return cached[0]
        query: dict[str, str] = {"scope": scope}
        if service:
            query["service"] = service
        url = str(httpx.URL(realm).copy_merge_params(query))
        response = await self._send(
            client, "GET", url, {"User-Agent": USER_AGENT, "Accept": "application/json"},
            stream=True,
        )
        try:
            if response.status_code in (401, 403):
                raise CheckFailed("auth_required", f"token_http_{response.status_code}", 401)
            if response.status_code == 429:
                raise CheckFailed("rate_limited", "token_http_429", 429)
            if response.status_code != 200:
                raise CheckFailed(
                    "unreachable", f"token_http_{response.status_code}", response.status_code
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_TOKEN_BYTES:
                    raise CheckFailed("auth_required", "token_too_large", 401)
        finally:
            await response.aclose()
        try:
            payload = json.loads(bytes(body))
        except ValueError:
            raise CheckFailed("auth_required", "token_invalid", 401) from None
        token = payload.get("token") or payload.get("access_token") if isinstance(
            payload, dict
        ) else None
        if not isinstance(token, str) or not token or len(token) > 16384:
            raise CheckFailed("auth_required", "token_invalid", 401)
        expires_in = payload.get("expires_in")
        lifetime = expires_in if isinstance(expires_in, int) and expires_in > 0 else 60
        self._tokens[key] = (token, self.clock() + max(lifetime - 30, 10))
        self._repo_tokens[(endpoint.netloc, repo)] = key
        return token
