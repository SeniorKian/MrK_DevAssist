"""Single sign-on with OpenID Connect (Google, Microsoft Entra ID, Keycloak, Authentik, ...).

Authorization code flow with PKCE (S256), ``state`` and ``nonce``. The browser
carries them in a short-lived, encrypted, HttpOnly cookie; nothing is kept in
memory between the two requests. The ID token is verified here with the
provider's published keys (JWKS, cached, refreshed once on an unknown key id):
signature (RS*/PS*/ES*, never ``none`` or HMAC), ``iss``, ``aud``/``azp``,
``exp``/``iat``/``nbf`` with a small clock skew, ``nonce`` and, when the email is
used, ``email_verified``.

Every request to the provider goes through the panel's outbound client, so the
proxy choice and the destination policy (no loopback, metadata or, unless the
owner allows it, private addresses) apply as for any other outbound call.

Accounts: an identity (issuer + subject) already linked signs in to its account;
otherwise a *verified* email that matches exactly one account links to it; when
the owner allows it, a new account is made with the chosen default role (never
owner). The client secret lives in the encrypted SecretStore.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import secrets
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select

from . import outbound
from .auth import (
    BUILTIN_ROLES,
    OIDC_SETTINGS_KEY,
    AuthStore,
    FieldError,
    MfaChallenge,
    Principal,
)
from .models import SystemSetting, User, UserIdentity
from .netresolve import resolve_host

if TYPE_CHECKING:
    from .netresolve import NetworkSettingsStore
    from .secret_store import SecretStore

LOGGER = logging.getLogger(__name__)

CLIENT_SECRET_REFERENCE = "oidc-client-secret"  # noqa: S105 - a store key, not a secret
STATE_COOKIE = "mrk_oidc"
STATE_COOKIE_PATH = "/api/v1/auth/oidc"
STATE_TTL_SECONDS = 600
CALLBACK_PATH = "/api/v1/auth/oidc/callback"
CLOCK_SKEW_SECONDS = 120
DISCOVERY_TTL_SECONDS = 3600
JWKS_TTL_SECONDS = 3600
JWKS_MIN_REFRESH_SECONDS = 30
MAX_RESPONSE_BYTES = 1024 * 1024
HTTP_TIMEOUT_SECONDS = 10.0
SSO_PASSWORD_MARKER = "!sso-only"  # noqa: S105 - not a password: no Argon2 hash matches it

ALLOWED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
)
TOKEN_AUTH_METHODS = ("client_secret_post", "client_secret_basic")
_CLAIM = re.compile(r"^[A-Za-z0-9_:.\-]{1,64}$")
_SCOPE = re.compile(r"^[A-Za-z0-9_:./\-]{1,64}$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512,
}
_CURVES: dict[str, tuple[ec.EllipticCurve, int, str]] = {
    "P-256": (ec.SECP256R1(), 32, "ES256"),
    "P-384": (ec.SECP384R1(), 48, "ES384"),
    "P-521": (ec.SECP521R1(), 66, "ES512"),
}

DEFAULT_SETTINGS: dict[str, Any] = {
    "enabled": False,
    "display_name": "",
    "issuer": "",
    "client_id": "",
    "scopes": "openid email profile",
    "allowed_domains": [],
    "email_claim": "email",
    "username_claim": "preferred_username",
    "require_email_verified": True,
    "auto_create": False,
    "default_role": "viewer",
    "sso_only": False,
    "trust_idp_mfa": False,
    "token_auth_method": "client_secret_post",
    "proxy_id": None,
    "allow_private_network": False,
}

# Tests replace these (httpx.MockTransport / a fixed resolver).
TRANSPORT_FACTORY: Callable[[], httpx.AsyncBaseTransport] | None = None
RESOLVER: outbound.Resolver | None = None


def _resolve(host: str, port: int, config: Any) -> list[str]:
    if RESOLVER is not None:
        return RESOLVER(host, port, config)
    return resolve_host(host, port, config)


class OidcError(Exception):
    """A sign-in failure with a stable code for the browser and a reason for the audit."""

    def __init__(self, code: str, reason: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.reason = reason or code


# ----- small helpers -----------------------------------------------------------------


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_\-]*", text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def normalize_issuer(value: str) -> str:
    return value.strip().rstrip("/")


def validate_https_url(value: object, field: str) -> str:
    text = str(value or "").strip()
    parsed = urlsplit(text)
    if (
        len(text) > 255 or parsed.scheme != "https" or not parsed.hostname
        or parsed.username or parsed.password or parsed.query or parsed.fragment
    ):
        raise FieldError("invalid_oidc_settings", "an https address is needed", field,
                         "invalid_url")
    return text


def settings_value(raw: object) -> dict[str, Any]:
    """Stored settings merged over the defaults (unknown keys dropped)."""
    value = dict(DEFAULT_SETTINGS)
    if isinstance(raw, dict):
        for key in DEFAULT_SETTINGS:
            if key in raw:
                value[key] = raw[key]
    value["allowed_domains"] = [
        str(item) for item in value.get("allowed_domains") or [] if isinstance(item, str)
    ]
    return value


def email_verified(claims: dict[str, Any]) -> bool:
    value = claims.get("email_verified")
    return value is True or (isinstance(value, str) and value.lower() == "true")


# ----- ID token verification -------------------------------------------------------


def public_key_for(jwk: dict[str, Any], algorithm: str) -> Any:
    """A verification key from one JWK, checked against the token's algorithm."""
    if jwk.get("use") not in (None, "sig"):
        raise OidcError("sso_token_invalid", "key_not_for_signing")
    if jwk.get("alg") not in (None, algorithm):
        raise OidcError("sso_token_invalid", "key_algorithm_mismatch")
    kty = jwk.get("kty")
    try:
        if algorithm[:2] in {"RS", "PS"}:
            if kty != "RSA":
                raise OidcError("sso_token_invalid", "key_type_mismatch")
            modulus = int.from_bytes(b64url_decode(jwk["n"]), "big")
            exponent = int.from_bytes(b64url_decode(jwk["e"]), "big")
            if modulus.bit_length() < 2048:
                raise OidcError("sso_token_invalid", "key_too_small")
            return rsa.RSAPublicNumbers(exponent, modulus).public_key()
        if kty != "EC" or jwk.get("crv") not in _CURVES:
            raise OidcError("sso_token_invalid", "key_type_mismatch")
        curve, _size, expected_alg = _CURVES[str(jwk["crv"])]
        if expected_alg != algorithm:
            raise OidcError("sso_token_invalid", "key_algorithm_mismatch")
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    except (KeyError, TypeError, ValueError) as exc:
        raise OidcError("sso_token_invalid", "bad_key") from exc


def verify_signature(key: Any, algorithm: str, signing_input: bytes, signature: bytes) -> bool:
    digest = _HASHES[algorithm[2:]]()
    try:
        if algorithm.startswith("RS"):
            key.verify(signature, signing_input, padding.PKCS1v15(), digest)
        elif algorithm.startswith("PS"):
            key.verify(
                signature, signing_input,
                padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest,
            )
        else:
            size = (key.curve.key_size + 7) // 8
            if len(signature) != 2 * size:
                return False
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
            key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(digest))
    except InvalidSignature:
        return False
    return True


def parse_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    if not isinstance(token, str) or len(token) > 16384 or token.count(".") != 2:
        raise OidcError("sso_token_invalid", "malformed")
    head, body, signature = token.split(".")
    try:
        header = json.loads(b64url_decode(head))
        claims = json.loads(b64url_decode(body))
        raw_signature = b64url_decode(signature)
    except (ValueError, UnicodeError) as exc:
        raise OidcError("sso_token_invalid", "malformed") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise OidcError("sso_token_invalid", "malformed")
    return header, claims, f"{head}.{body}".encode("ascii"), raw_signature


class UnknownKey(Exception):
    """The token names a key id the cached key set does not have."""


def verify_id_token(
    token: str,
    keys: list[dict[str, Any]],
    *,
    issuer: str,
    client_id: str,
    nonce: str,
    now: float,
    skew: int = CLOCK_SKEW_SECONDS,
) -> dict[str, Any]:
    header, claims, signing_input, signature = parse_jwt(token)
    algorithm = header.get("alg")
    if algorithm not in ALLOWED_ALGORITHMS:
        raise OidcError("sso_token_invalid", "algorithm_not_allowed")
    if header.get("crit"):
        raise OidcError("sso_token_invalid", "critical_header")
    kid = header.get("kid")
    if kid is not None:
        candidates = [item for item in keys if item.get("kid") == kid]
        if not candidates:
            raise UnknownKey(str(kid))
    else:
        family = "RSA" if algorithm[:2] in {"RS", "PS"} else "EC"
        candidates = [item for item in keys if item.get("kty") == family]
    verified = False
    for jwk in candidates:
        try:
            key = public_key_for(jwk, algorithm)
        except OidcError:
            continue
        if verify_signature(key, algorithm, signing_input, signature):
            verified = True
            break
    if not verified:
        raise OidcError("sso_token_invalid", "bad_signature")
    if claims.get("iss") != issuer:
        raise OidcError("sso_token_invalid", "wrong_issuer")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, list) or client_id not in audiences:
        raise OidcError("sso_token_invalid", "wrong_audience")
    azp = claims.get("azp")
    if (len(audiences) > 1 or azp is not None) and azp != client_id:
        raise OidcError("sso_token_invalid", "wrong_authorized_party")
    expires = claims.get("exp")
    issued = claims.get("iat")
    if not isinstance(expires, int | float) or isinstance(expires, bool) or expires + skew <= now:
        raise OidcError("sso_token_invalid", "expired")
    if not isinstance(issued, int | float) or isinstance(issued, bool) or issued - skew > now:
        raise OidcError("sso_token_invalid", "issued_in_future")
    not_before = claims.get("nbf")
    if isinstance(not_before, int | float) and not_before - skew > now:
        raise OidcError("sso_token_invalid", "not_yet_valid")
    token_nonce = claims.get("nonce")
    if not isinstance(token_nonce, str) or not secrets.compare_digest(token_nonce, nonce):
        raise OidcError("sso_token_invalid", "wrong_nonce")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not 1 <= len(subject) <= 255:
        raise OidcError("sso_token_invalid", "no_subject")
    return claims


# ----- the service ---------------------------------------------------------------------


class OidcService:
    def __init__(
        self,
        auth: AuthStore,
        secret_store: SecretStore | None,
        network: NetworkSettingsStore | None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.auth = auth
        self.secret_store = secret_store
        self.network = network
        self.clock = clock
        self._discovery: dict[str, tuple[float, dict[str, Any]]] = {}
        self._jwks: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self._fetch_lock = asyncio.Lock()

    # ----- settings -------------------------------------------------------------
    def raw_settings(self) -> dict[str, Any]:
        with self.auth.db.session() as db:
            row = db.get(SystemSetting, OIDC_SETTINGS_KEY)
            return settings_value(row.value if row is not None else None)

    def client_secret(self) -> str | None:
        if self.secret_store is None:
            return None
        try:
            return self.secret_store.get(CLIENT_SECRET_REFERENCE).get("secret") or None
        except (KeyError, ValueError):
            return None

    def public_settings(self, redirect_uri: str) -> dict[str, Any]:
        value = self.raw_settings()
        return {
            **value,
            "client_secret_set": self.client_secret() is not None,
            "redirect_uri": redirect_uri,
            "roles": [role for role in BUILTIN_ROLES if role != "owner"],
        }

    def sign_in_option(self) -> dict[str, Any]:
        """What the sign-in page may know: whether the button shows, and its label."""
        value = self.raw_settings()
        ready = bool(value["enabled"] and value["issuer"] and value["client_id"])
        return {
            "enabled": ready,
            "status": "configured" if ready else "not_configured",
            "display_name": (value["display_name"] or "SSO") if ready else None,
            "start_url": "/api/v1/auth/oidc/start" if ready else None,
            "sso_only": bool(ready and value["sso_only"]),
        }

    def update_settings(
        self,
        payload: dict[str, Any],
        actor: Principal,
        source_ip: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if actor.role != "owner":
            raise FieldError("owner_only", "only an owner can change single sign-on",
                             status_code=403)
        value = self.raw_settings()
        for key in DEFAULT_SETTINGS:
            if key in payload and payload[key] is not None:
                value[key] = payload[key]
        if "proxy_id" in payload:
            value["proxy_id"] = payload["proxy_id"]
        cleaned = self._validate(value, actor)
        secret = payload.get("client_secret")
        if isinstance(secret, str) and secret.strip():
            if len(secret) > 1024:
                raise FieldError("invalid_oidc_settings", "the client secret is too long",
                                 "client_secret", "too_long")
            if self.secret_store is None:
                raise FieldError("secret_store_unavailable", "secrets cannot be stored",
                                 status_code=503)
            self.secret_store.replace(CLIENT_SECRET_REFERENCE, {"secret": secret.strip()})
        elif payload.get("clear_client_secret") is True and self.secret_store is not None:
            self.secret_store.delete(CLIENT_SECRET_REFERENCE)
        if cleaned["enabled"] and self.client_secret() is None:
            raise FieldError("invalid_oidc_settings", "the client secret is needed",
                             "client_secret", "required")
        now = int(self.clock())
        with self.auth.db.session() as db, db.begin():
            row = db.get(SystemSetting, OIDC_SETTINGS_KEY)
            if row is None:
                db.add(SystemSetting(key=OIDC_SETTINGS_KEY, value=cleaned, updated_at=now,
                                     updated_by_user_id=actor.user_id))
            else:
                row.value = cleaned
                row.updated_at = now
                row.updated_by_user_id = actor.user_id
            self.auth._audit_db(db, actor.user_id, "auth.oidc.settings.update", "system_setting",
                                OIDC_SETTINGS_KEY, "success", source_ip, request_id)
        # A new issuer or key set takes effect at once.
        self._discovery.clear()
        self._jwks.clear()
        return cleaned

    def _validate(self, value: dict[str, Any], actor: Principal) -> dict[str, Any]:
        cleaned = dict(DEFAULT_SETTINGS)
        for key in ("enabled", "require_email_verified", "auto_create", "sso_only",
                    "trust_idp_mfa", "allow_private_network"):
            if not isinstance(value.get(key), bool):
                raise FieldError("invalid_oidc_settings", "must be true or false", key, "invalid")
            cleaned[key] = value[key]
        display = " ".join(str(value.get("display_name") or "").split())
        if len(display) > 60 or any(ord(char) < 32 for char in display):
            raise FieldError("invalid_oidc_settings", "the name is too long", "display_name",
                             "too_long", params={"max_length": 60})
        cleaned["display_name"] = display
        issuer = str(value.get("issuer") or "").strip()
        cleaned["issuer"] = (
            normalize_issuer(validate_https_url(issuer, "issuer")) if issuer else ""
        )
        client_id = str(value.get("client_id") or "").strip()
        if len(client_id) > 255 or any(ord(char) < 33 for char in client_id):
            raise FieldError("invalid_oidc_settings", "the client id is not valid", "client_id",
                             "invalid")
        cleaned["client_id"] = client_id
        scopes = str(value.get("scopes") or "").split()
        if (
            "openid" not in scopes or len(scopes) > 20
            or not all(_SCOPE.fullmatch(item) for item in scopes)
        ):
            raise FieldError("invalid_oidc_settings", "scopes must include openid", "scopes",
                             "invalid")
        cleaned["scopes"] = " ".join(dict.fromkeys(scopes))
        domains_raw = value.get("allowed_domains") or []
        if isinstance(domains_raw, str):
            domains_raw = domains_raw.replace(",", " ").split()
        if not isinstance(domains_raw, list) or len(domains_raw) > 50:
            raise FieldError("invalid_oidc_settings", "too many domains", "allowed_domains",
                             "invalid")
        domains = []
        for item in domains_raw:
            domain = str(item).strip().lower().lstrip("@")
            if not _DOMAIN.fullmatch(domain):
                raise FieldError("invalid_oidc_settings", "a domain is not valid",
                                 "allowed_domains", "invalid", params={"value": domain[:80]})
            domains.append(domain)
        cleaned["allowed_domains"] = sorted(set(domains))
        for key in ("email_claim", "username_claim"):
            claim = str(value.get(key) or "").strip()
            if not _CLAIM.fullmatch(claim):
                raise FieldError("invalid_oidc_settings", "the claim name is not valid", key,
                                 "invalid")
            cleaned[key] = claim
        method = value.get("token_auth_method")
        if method not in TOKEN_AUTH_METHODS:
            raise FieldError("invalid_oidc_settings", "unknown method", "token_auth_method",
                             "invalid")
        cleaned["token_auth_method"] = method
        role = str(value.get("default_role") or "")
        with self.auth.db.session() as db:
            if role == "owner":
                raise FieldError("invalid_oidc_settings", "new accounts never become owners",
                                 "default_role", "not_allowed")
            self.auth._check_assignable(db, role, actor.permissions)
        cleaned["default_role"] = role
        try:
            cleaned["proxy_id"] = outbound.validate_reference(value.get("proxy_id"))
        except outbound.OutboundError as exc:
            raise FieldError("invalid_oidc_settings", "unknown proxy", "proxy_id",
                             "invalid") from exc
        if cleaned["enabled"] and not (cleaned["issuer"] and cleaned["client_id"]):
            raise FieldError(
                "invalid_oidc_settings", "issuer and client id are needed",
                fields=[
                    {"field": name, "reason_code": "required"}
                    for name in ("issuer", "client_id") if not cleaned[name]
                ],
            )
        return cleaned

    # ----- talking to the provider ---------------------------------------------------
    async def _request(
        self,
        settings: dict[str, Any],
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> tuple[int, Any]:
        try:
            route = await asyncio.to_thread(
                outbound.resolve_route, self.network, self.secret_store, settings["proxy_id"]
            ) if self.network is not None else None
        except outbound.OutboundError as exc:
            raise OidcError("sso_unreachable", exc.code) from exc
        client = outbound.OutboundClient(
            self.network, route, HTTP_TIMEOUT_SECONDS,
            transport=TRANSPORT_FACTORY() if TRANSPORT_FACTORY else None,
            resolver=_resolve,
            allow_private=True if settings["allow_private_network"] else None,
        )
        try:
            response = await client.send(
                method, url, headers={"Accept": "application/json", **(headers or {})},
                content=content, stream=True,
            )
            try:
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise OidcError("sso_unreachable", "response_too_large")
                    chunks.append(chunk)
            finally:
                await response.aclose()
        except OidcError:
            raise
        except Exception as exc:  # noqa: BLE001 - never echo: messages may carry URLs
            raise OidcError("sso_unreachable", outbound.error_code(exc)) from None
        finally:
            await client.aclose()
        try:
            body = json.loads(b"".join(chunks)) if chunks else None
        except ValueError:
            body = None
        return response.status_code, body

    async def discovery(self, settings: dict[str, Any]) -> dict[str, Any]:
        issuer = normalize_issuer(settings["issuer"])
        cached = self._discovery.get(issuer)
        if cached is not None and cached[0] > time.monotonic():
            return cached[1]
        status, body = await self._request(
            settings, "GET", f"{issuer}/.well-known/openid-configuration"
        )
        if status != 200 or not isinstance(body, dict):
            raise OidcError("sso_discovery_failed", f"status_{status}")
        if normalize_issuer(str(body.get("issuer") or "")) != issuer:
            raise OidcError("sso_discovery_failed", "issuer_mismatch")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            try:
                validate_https_url(body.get(key), key)
            except FieldError as exc:
                raise OidcError("sso_discovery_failed", f"bad_{key}") from exc
        methods = body.get("code_challenge_methods_supported")
        if isinstance(methods, list) and methods and "S256" not in methods:
            raise OidcError("sso_discovery_failed", "pkce_s256_unsupported")
        document = {
            "issuer": str(body["issuer"]),
            "authorization_endpoint": str(body["authorization_endpoint"]),
            "token_endpoint": str(body["token_endpoint"]),
            "jwks_uri": str(body["jwks_uri"]),
        }
        self._discovery[issuer] = (time.monotonic() + DISCOVERY_TTL_SECONDS, document)
        return document

    async def _keys(
        self, settings: dict[str, Any], jwks_uri: str, *, refresh: bool = False
    ) -> list[dict[str, Any]]:
        async with self._fetch_lock:
            cached = self._jwks.get(jwks_uri)
            now = time.monotonic()
            if cached is not None:
                fetched, keys = cached
                fresh = now - fetched < JWKS_TTL_SECONDS
                recent = now - fetched < JWKS_MIN_REFRESH_SECONDS
                if (fresh and not refresh) or (refresh and recent):
                    return keys
            status, body = await self._request(settings, "GET", jwks_uri)
            if status != 200 or not isinstance(body, dict) or not isinstance(
                body.get("keys"), list
            ):
                raise OidcError("sso_discovery_failed", "jwks_unavailable")
            keys = [item for item in body["keys"] if isinstance(item, dict)][:50]
            self._jwks[jwks_uri] = (now, keys)
            return keys

    async def test_connection(self) -> dict[str, Any]:
        settings = self.raw_settings()
        if not settings["issuer"]:
            raise OidcError("sso_not_configured")
        document = await self.discovery({**settings})
        keys = await self._keys(settings, document["jwks_uri"], refresh=True)
        return {
            "ok": True,
            "issuer": document["issuer"],
            "authorization_endpoint": document["authorization_endpoint"],
            "token_endpoint": document["token_endpoint"],
            "keys": len(keys),
        }

    # ----- the flow ------------------------------------------------------------------
    def _state_key(self) -> bytes:
        return self.auth.signing_key("oidc-state")

    def seal_state(self, payload: dict[str, Any]) -> str:
        nonce = secrets.token_bytes(12)
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return b64url(nonce + AESGCM(self._state_key()).encrypt(nonce, data, b"mrk-oidc-state"))

    def open_state(self, value: str | None) -> dict[str, Any] | None:
        if not value or len(value) > 4096:
            return None
        try:
            raw = b64url_decode(value)
            data = AESGCM(self._state_key()).decrypt(raw[:12], raw[12:], b"mrk-oidc-state")
            payload = json.loads(data)
        except Exception:  # noqa: BLE001 - any tampering is just "invalid"
            return None
        if not isinstance(payload, dict) or not isinstance(payload.get("e"), int):
            return None
        if payload["e"] <= int(self.clock()):
            return None
        return payload

    async def begin(self, redirect_uri: str, remember: bool) -> tuple[str, str]:
        """(authorization URL, sealed state cookie value)."""
        settings = self.raw_settings()
        if not (settings["enabled"] and settings["issuer"] and settings["client_id"]):
            raise OidcError("sso_disabled")
        document = await self.discovery(settings)
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier, challenge = pkce_pair()
        query = urlencode({
            "response_type": "code",
            "client_id": settings["client_id"],
            "redirect_uri": redirect_uri,
            "scope": settings["scopes"],
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        endpoint = document["authorization_endpoint"]
        separator = "&" if urlsplit(endpoint).query else "?"
        sealed = self.seal_state({
            "s": state, "n": nonce, "v": verifier, "r": bool(remember),
            "u": redirect_uri, "i": normalize_issuer(settings["issuer"]),
            "c": settings["client_id"], "e": int(self.clock()) + STATE_TTL_SECONDS,
        })
        return f"{endpoint}{separator}{query}", sealed

    async def finish(
        self, sealed_state: str | None, state: str | None, code: str | None
    ) -> tuple[dict[str, Any], dict[str, Any], bool]:
        """Check the callback and the ID token: (claims, settings, remember)."""
        stored = self.open_state(sealed_state)
        if stored is None or not state or not isinstance(stored.get("s"), str) or (
            not secrets.compare_digest(str(stored["s"]), state)
        ):
            raise OidcError("sso_state_invalid")
        settings = self.raw_settings()
        if not settings["enabled"]:
            raise OidcError("sso_disabled")
        if (
            normalize_issuer(settings["issuer"]) != stored.get("i")
            or settings["client_id"] != stored.get("c")
        ):
            raise OidcError("sso_state_invalid", "settings_changed")
        if not code or len(code) > 4096:
            raise OidcError("sso_idp_error", "no_code")
        secret = self.client_secret()
        if secret is None:
            raise OidcError("sso_not_configured", "no_client_secret")
        document = await self.discovery(settings)
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": str(stored["u"]),
            "code_verifier": str(stored["v"]),
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if settings["token_auth_method"] == "client_secret_basic":  # noqa: S105
            from urllib.parse import quote

            pair = f"{quote(settings['client_id'], safe='')}:{quote(secret, safe='')}"
            headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode("ascii")
        else:
            form["client_id"] = settings["client_id"]
            form["client_secret"] = secret
        status, body = await self._request(
            settings, "POST", document["token_endpoint"], headers=headers,
            content=urlencode(form).encode("ascii"),
        )
        if status != 200 or not isinstance(body, dict) or not isinstance(
            body.get("id_token"), str
        ):
            error = body.get("error") if isinstance(body, dict) else None
            reason = re.sub(r"[^a-z_]", "", str(error or f"status_{status}").lower())[:40]
            raise OidcError("sso_token_exchange_failed", reason or "failed")
        token_type = body.get("token_type")
        if token_type is not None and str(token_type).lower() != "bearer":
            raise OidcError("sso_token_exchange_failed", "token_type")
        keys = await self._keys(settings, document["jwks_uri"])
        verify = {
            "issuer": document["issuer"], "client_id": settings["client_id"],
            "nonce": str(stored["n"]), "now": self.clock(),
        }
        try:
            claims = verify_id_token(body["id_token"], keys, **verify)
        except UnknownKey:
            keys = await self._keys(settings, document["jwks_uri"], refresh=True)
            try:
                claims = verify_id_token(body["id_token"], keys, **verify)
            except UnknownKey as exc:
                raise OidcError("sso_token_invalid", "unknown_key") from exc
        return claims, settings, bool(stored.get("r"))

    # ----- accounts ------------------------------------------------------------------
    def sign_in(
        self,
        claims: dict[str, Any],
        settings: dict[str, Any],
        *,
        remember: bool,
        source_ip: str | None,
        request_id: str | None,
        user_agent: str | None = None,
    ) -> tuple[tuple[str, str, Principal] | MfaChallenge, bool]:
        """Find (or make) the account and open a session; (result, account was created)."""
        try:
            return self._sign_in(claims, settings, remember=remember, source_ip=source_ip,
                                 request_id=request_id, user_agent=user_agent)
        except OidcError as exc:
            self.auth.record_audit(None, "auth.oidc.login", "session", exc.reason, "failure",
                                   source_ip, request_id)
            raise

    def _sign_in(
        self,
        claims: dict[str, Any],
        settings: dict[str, Any],
        *,
        remember: bool,
        source_ip: str | None,
        request_id: str | None,
        user_agent: str | None,
    ) -> tuple[tuple[str, str, Principal] | MfaChallenge, bool]:
        issuer = str(claims["iss"])[:255]
        subject = str(claims["sub"])
        raw_email = claims.get(settings["email_claim"])
        email = raw_email.strip().lower() if isinstance(raw_email, str) else None
        if email is not None and ("@" not in email or len(email) > 254):
            email = None
        verified = email is not None and (
            email_verified(claims) or not settings["require_email_verified"]
        )
        domains = settings["allowed_domains"]

        def require_email() -> str:
            if email is None:
                raise OidcError("sso_email_missing")
            if not verified:
                raise OidcError("sso_email_unverified")
            return email

        if domains:
            address = require_email()
            if address.rsplit("@", 1)[1] not in domains:
                raise OidcError("sso_domain_not_allowed")
        now = int(self.clock())
        created = False
        with self.auth.db.session() as db, db.begin():
            identity = db.scalar(
                select(UserIdentity).where(
                    UserIdentity.issuer == issuer, UserIdentity.subject == subject
                )
            )
            if identity is not None:
                user = db.get(User, identity.user_id)
                if user is None:
                    raise OidcError("sso_no_account")
            else:
                address = require_email()
                user = db.scalar(select(User).where(User.email == address))
                if user is not None:
                    other = db.scalar(
                        select(UserIdentity.id).where(
                            UserIdentity.user_id == user.id, UserIdentity.issuer == issuer
                        )
                    )
                    if other is not None:
                        # The account is already linked to another identity here.
                        raise OidcError("sso_account_conflict")
                elif settings["auto_create"]:
                    if self.auth._role_permissions_db(db, settings["default_role"]) is None:
                        raise OidcError("sso_no_account", "default_role_missing")
                    hint = claims.get(settings["username_claim"])
                    username = self.auth._unique_username(
                        db, hint if isinstance(hint, str) and hint.strip() else address,
                        None if isinstance(hint, str) and hint.strip() else address,
                    )
                    name = claims.get("name")
                    display_name = None
                    if isinstance(name, str):
                        try:
                            display_name = self.auth.validate_display_name(name)
                        except FieldError:
                            display_name = None
                    user = User(
                        username=username,
                        password_hash=SSO_PASSWORD_MARKER,
                        role=settings["default_role"],
                        enabled=True,
                        display_name=display_name or username,
                        email=address,
                        identity_provider="oidc",
                        mfa_enabled=False,
                        created_at=now,
                        updated_at=now,
                    )
                    db.add(user)
                    db.flush()
                    created = True
                    self.auth._audit_db(db, user.id, "auth.oidc.provision", "user",
                                        str(user.id), "success", source_ip, request_id)
                else:
                    raise OidcError("sso_no_account")
                identity = UserIdentity(
                    user_id=user.id, issuer=issuer, subject=subject, email=address,
                    created_at=now,
                )
                db.add(identity)
                db.flush()
                if not created:
                    self.auth._audit_db(db, user.id, "auth.oidc.link", "user", str(user.id),
                                        "success", source_ip, request_id)
            if not user.enabled:
                raise OidcError("sso_account_disabled")
            if self.auth._role_permissions_db(db, user.role) is None:
                raise OidcError("sso_account_disabled", "role_missing")
            identity.last_login_at = now
            if email is not None and verified:
                identity.email = email
            if user.mfa_enabled and not settings["trust_idp_mfa"]:
                self.auth._audit_db(db, user.id, "auth.oidc.login", "user", str(user.id),
                                    "mfa_required", source_ip, request_id)
                return self.auth.issue_mfa_challenge(user, remember=remember,
                                                     method="oidc"), created
            self.auth._audit_db(db, user.id, "auth.oidc.login", "user", str(user.id),
                                "success", source_ip, request_id)
            return self.auth._open_session(
                db, user, source_ip, request_id, remember=remember, method="oidc",
                user_agent=user_agent,
            ), created
