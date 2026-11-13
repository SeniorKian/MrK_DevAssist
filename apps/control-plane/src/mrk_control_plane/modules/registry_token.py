"""Token service for the image registry (docs/48): the panel signs Zot's pull/push tokens.

Zot answers Docker clients with 401 on ``/v2/`` whenever it has users, and Docker sends
no password to a registry mirror, so an htpasswd-only Zot can never be the server's
``registry-mirrors``. With a Bearer realm configured Zot instead tells Docker where to
get a token; Docker asks this endpoint (with the user's password if it has one, else
anonymously) and the panel decides:

* a registry user with the right password: the same rights as today (pull, push);
* ``mrk-panel``: everything;
* no password, from a trusted address range (the server itself, build servers):
  pull only - of the mirrors and official images, or of everything (``scope``);
* no password from elsewhere: pull of anonymous / public repositories only;
* never push or delete without a password.

Pure functions plus a small RS256 signer (``cryptography``, already a dependency).
"""

from __future__ import annotations

import base64
import datetime
import ipaddress
import json
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

SERVICE = "devassist-registry"
ISSUER = "devassist-panel"
TOKEN_TTL_SECONDS = 300
CERT_FILE = "token.crt"
CONTAINER_CERT = "/etc/zot/token.crt"
TOKEN_PATH = "/api/v1/registry/token"  # noqa: S105 - a URL path, not a secret
DEFAULT_TRUSTED_RANGES = ("127.0.0.0/8", "::1/128", "172.16.0.0/12")
SCOPES = ("mirrors", "all")
MAX_RANGES = 32
MAX_SCOPES = 32
MAX_LOG = 200
ALL_ACTIONS = ("pull", "push", "delete")
USER_ACTIONS = {"pull": ("pull",), "push": ("pull", "push")}


# ----------------------------------------------------------------------------- settings
def default_settings() -> dict[str, Any]:
    return {"enabled": False, "realm": "", "trusted_ranges": list(DEFAULT_TRUSTED_RANGES),
            "scope": "mirrors"}


def validate(payload: Any, current: dict[str, Any]) -> dict[str, Any]:
    """Merge a partial update into the current token settings and check it."""
    if not isinstance(payload, dict):
        raise ValueError("token settings must be an object")
    unknown = set(payload) - set(default_settings())
    if unknown:
        raise ValueError(f"unknown token setting: {sorted(unknown)[0]}")
    merged = {**default_settings(), **current, **payload}
    if not isinstance(merged["enabled"], bool):
        raise ValueError("enabled must be true or false")
    realm = str(merged["realm"] or "").strip()
    if realm:
        from urllib.parse import urlsplit

        parts = urlsplit(realm)
        if (parts.scheme not in {"http", "https"} or not parts.hostname or parts.username
                or parts.password or parts.query or parts.fragment or len(realm) > 300):
            raise ValueError("realm must be an http(s) address")
    merged["realm"] = realm
    ranges = merged["trusted_ranges"]
    if not isinstance(ranges, list) or len(ranges) > MAX_RANGES:
        raise ValueError("trusted_ranges must be a short list")
    clean: list[str] = []
    for item in ranges:
        try:
            network = ipaddress.ip_network(str(item).strip(), strict=False)
        except ValueError:
            raise ValueError(f"not an address range: {item}") from None
        if network.prefixlen == 0:
            raise ValueError("a range that covers every address is not allowed")
        if str(network) not in clean:
            clean.append(str(network))
    merged["trusted_ranges"] = clean
    if merged["scope"] not in SCOPES:
        raise ValueError("scope must be mirrors or all")
    return merged


def ip_trusted(ip: str | None, ranges: list[str]) -> bool:
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    for item in ranges:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


# ----------------------------------------------------------------------------- scopes
def parse_scope(text: str) -> tuple[str, str, list[str]] | None:
    """``repository:library/node:pull,push`` -> (type, name, actions); None if malformed."""
    kind, _, rest = text.partition(":")
    name, sep, actions = rest.rpartition(":")
    # "repository::pull" (no name) is what Zot asks for /v2/_catalog.
    if not kind or not sep or not actions or len(text) > 512 or (not name and kind != "repository"):
        return None
    wanted = [item for item in actions.split(",") if item]
    return kind, name, wanted


def matches(name: str, patterns: list[str]) -> bool:
    """``team/**`` = every repository under team/; other patterns are exact names."""
    for pattern in patterns:
        if pattern == "**":
            return True
        if pattern.endswith("/**") and name.startswith(pattern[:-2]):
            return True
        if name == pattern:
            return True
    return False


def mirror_patterns(upstreams: list[dict[str, Any]]) -> list[str]:
    """What «mirrors» covers: each prefixed mirror, and Docker Hub's official images."""
    patterns: list[str] = []
    for upstream in upstreams:
        if not upstream.get("enabled"):
            continue
        destination = str(upstream.get("destination", "")).strip("/")
        for pattern in ([f"{destination}/**"] if destination else ["library/**"]):
            if pattern not in patterns:
                patterns.append(pattern)
    return patterns


@dataclass
class Who:
    """The caller as the token service sees it."""

    user: str | None  # registry user name, or None (no password)
    access: str | None  # "admin" / "push" / "pull" for users
    ip: str | None
    trusted: bool


def allowed_actions(name: str, who: Who, registry: dict[str, Any],
                    token: dict[str, Any]) -> tuple[str, ...]:
    if who.access == "admin":
        return ALL_ACTIONS
    if who.access in USER_ACTIONS:
        return USER_ACTIONS[who.access]
    # No password: pull at most, never push or delete.
    if who.trusted and (token["scope"] == "all"
                        or matches(name, mirror_patterns(registry.get("upstreams") or []))):
        return ("pull",)
    if registry.get("anonymous_pull") or matches(name, registry.get("public_repositories") or []):
        return ("pull",)
    return ()


def grant(scopes: list[str], who: Who, registry: dict[str, Any],
          token: dict[str, Any]) -> list[dict[str, Any]]:
    access: list[dict[str, Any]] = []
    for text in scopes[:MAX_SCOPES]:
        parsed = parse_scope(text)
        if parsed is None:
            continue
        kind, name, wanted = parsed
        if kind == "registry" and name == "catalog":
            # Zot lists only what the token may read; harmless for anyone.
            access.append({"type": "registry", "name": "catalog", "actions": ["*"]})
            continue
        if kind != "repository":
            continue
        if not name:
            # The catalog: Zot lists only the repositories the rest of the token may read.
            if "pull" in wanted:
                access.append({"type": "repository", "name": "", "actions": ["pull"]})
            continue
        allowed = allowed_actions(name, who, registry, token)
        actions = [item for item in wanted if item in allowed]
        if "*" in wanted:
            actions = list(allowed)
        if actions:
            access.append({"type": "repository", "name": name, "actions": actions})
    return access


# ----------------------------------------------------------------------------- keys / JWT
def new_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode("ascii")


def _key(pem: str) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("token key must be RSA")
    return key


def certificate_pem(key_pem: str) -> str:
    """A self-signed certificate of the signing key: what Zot's ``bearer.cert`` reads."""
    key = _key(key_pem)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DevAssist registry tokens")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign(key_pem: str, subject: str, access: list[dict[str, Any]],
         now: float | None = None) -> tuple[str, int]:
    """(RS256 JWT, issued-at) in the Docker token format Zot verifies."""
    issued = int(now if now is not None else time.time()) - 5  # clock skew margin
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {"iss": ISSUER, "sub": subject, "aud": SERVICE, "iat": issued, "nbf": issued,
              "exp": issued + 5 + TOKEN_TTL_SECONDS, "jti": secrets.token_hex(12),
              "access": access}
    signing_input = (_b64(json.dumps(header, separators=(",", ":")).encode())
                     + "." + _b64(json.dumps(claims, separators=(",", ":")).encode()))
    signature = _key(key_pem).sign(signing_input.encode("ascii"), padding.PKCS1v15(),
                                   hashes.SHA256())
    return signing_input + "." + _b64(signature), issued


# ----------------------------------------------------------------------------- log
@dataclass
class DecisionLog:
    """The last decisions, for the health page and bug reports (no secrets)."""

    items: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=MAX_LOG))

    def add(self, who: Who, scopes: list[str], access: list[dict[str, Any]],
            result: str) -> None:
        self.items.append({
            "at": int(time.time()), "ip": who.ip, "user": who.user, "trusted": who.trusted,
            "result": result, "requested": scopes[:8],
            "granted": [f"{item['name']}:{','.join(item['actions'])}" for item in access][:8],
        })

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return list(self.items)[-limit:][::-1]
