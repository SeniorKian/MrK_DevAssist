"""Pairing and signed HTTP calls from the control plane to ``mrk-firewall``.

Configuration comes from the panel (``data_dir/control-plane/firewall-helper.json`` +
SecretStore) or, when both MRK_FIREWALL_URL and MRK_FIREWALL_KEY_FILE are set, from
the environment (env wins, read-only in the UI). The URL is either
``unix:/run/mrk-firewall/firewall.sock`` (default deployment: Unix socket in a volume
shared only by the two containers) or ``http(s)://host:port``.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..agent.signing import KEY_BYTES, decode_key, encode_key, sign_headers
from ..components import NETWORK_FIX, is_name_resolution_error
from ..module_context import ModuleContext

CONFIG_FILE = "firewall-helper.json"
DEFAULT_URL = "unix:/run/mrk-firewall/firewall.sock"
REQUEST_TIMEOUT_SECONDS = 10.0
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_UDS = re.compile(r"^/[A-Za-z0-9._/-]{1,100}$")

# Tests replace this with a factory (url -> transport), e.g. an ASGI transport.
TRANSPORT_FACTORY: Callable[[str], httpx.AsyncBaseTransport] | None = None


class HelperError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


def validate_helper_url(value: str) -> str:
    text = value.strip()
    if text.startswith("unix:"):
        path = text[5:]
        if path.startswith("//"):
            path = path[2:]
        if not _UDS.fullmatch(path) or ".." in path.split("/"):
            raise ValueError("unix socket path must be absolute (max 100 characters)")
        return f"unix:{path}"
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise ValueError("firewall helper URL is invalid") from exc
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("firewall helper URL must be unix:/path or http(s)://host:port")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("firewall helper URL must not contain credentials")
    if parts.query or parts.fragment or parts.path not in {"", "/"} or any(
        ch.isspace() for ch in text
    ):
        raise ValueError("firewall helper URL must not contain a path, query or fragment")
    netloc = parts.hostname if ":" not in parts.hostname else f"[{parts.hostname}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    return f"{parts.scheme}://{netloc}"


class HelperClient:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.config_path = ctx.data_dir / "control-plane" / CONFIG_FILE

    # ----- configuration -------------------------------------------------
    @staticmethod
    def env_managed() -> bool:
        return bool(os.getenv("MRK_FIREWALL_URL", "").strip()
                    and os.getenv("MRK_FIREWALL_KEY_FILE", "").strip())

    def _panel(self) -> dict[str, Any] | None:
        if not self.config_path.exists():
            return None
        payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None

    def resolve(self) -> tuple[str | None, str | None, bytes | None, str | None]:
        """Return (source, url, key, error)."""
        if self.env_managed():
            url = os.getenv("MRK_FIREWALL_URL", "").strip()
            try:
                raw = Path(os.getenv("MRK_FIREWALL_KEY_FILE", "").strip()).read_bytes()
                key = raw if len(raw) == KEY_BYTES else decode_key(raw.decode("ascii"))
                return "env", validate_helper_url(url), key, None
            except (OSError, ValueError) as exc:
                return "env", url or None, None, (
                    f"environment configuration invalid: {type(exc).__name__}")
        try:
            stored = self._panel()
        except (OSError, ValueError):
            return None, None, None, None
        if not stored or not isinstance(stored.get("url"), str):
            return None, None, None, None
        key: bytes | None = None
        reference = stored.get("secret_ref")
        if isinstance(reference, str):
            try:
                key = decode_key(self.ctx.secret_store.get(reference)["key"])
            except (KeyError, ValueError):
                key = None
        return "panel", stored["url"], key, None

    def paired_at(self) -> float | None:
        """When the helper was paired: the panel file's ``updated_at`` (the add-service
        wizard pairs through it too) or, env-managed, the key file's modification time."""
        if self.env_managed():
            try:
                return Path(os.getenv("MRK_FIREWALL_KEY_FILE", "").strip()).stat().st_mtime
            except OSError:
                return None
        try:
            stored = self._panel()
        except (OSError, ValueError):
            return None
        value = (stored or {}).get("updated_at")
        return float(value) if isinstance(value, int | float) and not isinstance(
            value, bool) else None

    def save(self, url: str, key_text: str | None) -> None:
        normalized = validate_helper_url(url)
        stored = self._panel() or {}
        reference = stored.get("secret_ref") if isinstance(stored.get("secret_ref"), str) else None
        if key_text is not None:
            key = decode_key(key_text)
            reference, _ = self.ctx.secret_store.replace(reference, {"key": encode_key(key)})
        elif reference is None:
            raise HelperError("firewall_key_required", 422, "A pairing key is required")
        else:
            try:
                self.ctx.secret_store.get(reference)
            except (KeyError, ValueError) as exc:
                raise HelperError("firewall_key_required", 422,
                                  "A pairing key is required") from exc
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.config_path.with_name(f".{CONFIG_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps({"url": normalized, "secret_ref": reference,
                                         "updated_at": int(time.time())}) + "\n",
                             encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, self.config_path)

    def unpair(self) -> None:
        stored = self._panel() or {}
        reference = stored.get("secret_ref")
        if isinstance(reference, str):
            self.ctx.secret_store.delete(reference)
        self.config_path.unlink(missing_ok=True)

    # ----- calls ---------------------------------------------------------
    @staticmethod
    def _client(url: str) -> httpx.AsyncClient:
        timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS, connect=3.0)
        if TRANSPORT_FACTORY is not None:
            transport: httpx.AsyncBaseTransport | None = TRANSPORT_FACTORY(url)
        elif url.startswith("unix:"):
            transport = httpx.AsyncHTTPTransport(uds=url[5:])
        else:
            transport = None
        base_url = "http://mrk-firewall" if url.startswith("unix:") else url
        return httpx.AsyncClient(base_url=base_url, transport=transport, timeout=timeout,
                                 follow_redirects=False, trust_env=False)

    async def request(self, method: str, path: str, body: Any = None) -> Any:
        source, url, key, error = self.resolve()
        if source is None or url is None:
            raise HelperError("firewall_not_configured", 409,
                              "The firewall helper is not paired")
        if key is None:
            raise HelperError("firewall_auth_failed", 502,
                              error or "The firewall pairing key is unavailable")
        raw = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
        async with self._client(url) as client:
            request = client.build_request(
                method, path, content=raw,
                headers={"Content-Type": "application/json"} if body is not None else {},
            )
            request.headers.update(
                sign_headers(key, method, request.url.raw_path.decode("ascii"), raw))
            try:
                response = await client.send(request, stream=True)
                try:
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > _MAX_RESPONSE_BYTES:
                            raise HelperError("firewall_unreachable", 502,
                                              "The firewall helper response is too large")
                finally:
                    await response.aclose()
            except httpx.TimeoutException as exc:
                raise HelperError("firewall_timeout", 504, "The firewall helper timed out") from exc
            except httpx.HTTPError as exc:
                if not url.startswith("unix:") and is_name_resolution_error(exc):
                    raise HelperError(
                        "firewall_name_unresolved", 502,
                        f"The firewall helper's host name does not resolve; {NETWORK_FIX}",
                    ) from exc
                raise HelperError("firewall_unreachable", 502,
                                  f"The firewall helper is unreachable ({type(exc).__name__})"
                                  ) from exc
        try:
            payload = json.loads(bytes(data)) if data else None
        except ValueError:
            payload = None
        if response.status_code == 200:
            if payload is None:
                raise HelperError("firewall_unreachable", 502, "The helper returned invalid JSON")
            return payload
        code = payload.get("error") if isinstance(payload, dict) else None
        message = payload.get("message") if isinstance(payload, dict) else None
        if response.status_code == 401:
            raise HelperError("firewall_auth_failed", 502, "The helper rejected the signature")
        if response.status_code == 422:
            raise HelperError("firewall_rejected", 422,
                              f"The helper rejected the request ({code}: {message})")
        if code in {"nft_unavailable", "nft_failed"}:
            raise HelperError(code, 502, str(message or code))
        if response.status_code == 409 and code in {"rollback_required", "no_pending_change",
                                                    "token_mismatch"}:
            raise HelperError(code, 409, str(message or code))
        raise HelperError("firewall_unreachable", 502,
                          f"The helper returned HTTP {response.status_code}")
