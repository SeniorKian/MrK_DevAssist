from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.testclient import TestClient
from mrk_control_plane import auth_api
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import registry_service, registry_token

from .helpers import login_owner

UPSTREAMS = [dict(item) for item in registry_service.DEFAULT_UPSTREAMS]
REGISTRY = {"anonymous_pull": False, "public_repositories": ["team/**"], "upstreams": UPSTREAMS}
TOKEN = {**registry_token.default_settings(), "enabled": True}


def _who(ip: str | None, access: str | None = None, user: str | None = None):
    return registry_token.Who(user=user, access=access, ip=ip,
                              trusted=registry_token.ip_trusted(ip, TOKEN["trusted_ranges"]))


def _grant(who, *scopes, token=TOKEN, registry=REGISTRY):
    return {item["name"]: item["actions"]
            for item in registry_token.grant(list(scopes), who, registry, token)}


def test_decisions_by_address_and_user() -> None:
    server = _who("127.0.0.1")
    outsider = _who("203.0.113.9")
    # The server itself: pull of the mirrors and official images, never push.
    assert _grant(server, "repository:library/node:pull,push") == {"library/node": ["pull"]}
    assert _grant(server, "repository:ghcr.io/org/app:pull") == {"ghcr.io/org/app": ["pull"]}
    assert _grant(server, "repository:acme/private:pull") == {}
    assert _grant(server, "repository:acme/private:pull",
                  token={**TOKEN, "scope": "all"}) == {"acme/private": ["pull"]}
    assert _grant(_who("::ffff:172.18.0.1"), "repository:library/redis:pull") == {
        "library/redis": ["pull"]}
    # Anyone else: only public repositories (or everything with anonymous_pull).
    assert _grant(outsider, "repository:library/node:pull") == {}
    assert _grant(outsider, "repository:team/web:pull") == {"team/web": ["pull"]}
    assert _grant(outsider, "repository:x/y:pull",
                  registry={**REGISTRY, "anonymous_pull": True}) == {"x/y": ["pull"]}
    # Users keep their rights from any address.
    assert _grant(_who("203.0.113.9", "push", "ci"), "repository:acme/app:pull,push,delete") == {
        "acme/app": ["pull", "push"]}
    assert _grant(_who(None, "pull", "dev"), "repository:acme/app:push") == {}
    assert _grant(_who(None, "admin", "mrk-panel"), "repository:acme/app:*") == {
        "acme/app": ["pull", "push", "delete"]}
    assert _grant(server, "garbage", "registry::pull") == {}
    # Zot asks "repository::pull" for the catalog; it lists only what the token may read.
    assert _grant(outsider, "repository::pull") == {"": ["pull"]}


def test_settings_validation() -> None:
    merged = registry_token.validate({"trusted_ranges": ["10.1.2.3/24", "10.1.2.0/24"]}, {})
    assert merged["trusted_ranges"] == ["10.1.2.0/24"]
    for bad in ({"trusted_ranges": ["0.0.0.0/0"]}, {"trusted_ranges": ["nope"]},
                {"scope": "everything"}, {"realm": "ftp://x"}, {"other": 1}):
        with pytest.raises(ValueError):
            registry_token.validate(bad, {})


def _b64decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def test_token_is_rs256_and_verifies_with_the_certificate() -> None:
    key = registry_token.new_key_pem()
    cert = x509.load_pem_x509_certificate(registry_token.certificate_pem(key).encode())
    access = [{"type": "repository", "name": "library/node", "actions": ["pull"]}]
    token, issued = registry_token.sign(key, "", access, now=1_800_000_000)
    header, claims, signature = token.split(".")
    cert.public_key().verify(_b64decode(signature), f"{header}.{claims}".encode(),
                             padding.PKCS1v15(), hashes.SHA256())
    payload = json.loads(_b64decode(claims))
    assert json.loads(_b64decode(header))["alg"] == "RS256"
    assert payload["aud"] == registry_token.SERVICE and payload["access"] == access
    assert payload["iat"] == issued == 1_800_000_000 - 5
    assert payload["exp"] - payload["iat"] == registry_token.TOKEN_TTL_SECONDS + 5


def test_token_endpoint_settings_and_zot_config(tmp_path: Path, monkeypatch) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        off = client.get("/api/v1/registry/token?scope=repository:library/node:pull")
        assert off.status_code == 404
        # No panel domain and no address: it cannot be turned on.
        refused = client.put("/api/v1/registry/token-settings", headers=headers,
                             json={"enabled": True})
        assert refused.status_code == 409
        assert refused.json()["error"]["code"] == "registry_token_realm_missing"
        realm = "https://panel.example.com/api/v1/registry/token"
        saved = client.put("/api/v1/registry/token-settings", headers=headers,
                           json={"enabled": True, "realm": realm})
        assert saved.status_code == 200, saved.text
        assert saved.json()["effective_realm"] == realm
        folder = tmp_path / "cp" / "registry"
        config = json.loads((folder / "config.json").read_text())
        assert config["http"]["auth"]["bearer"] == {
            "realm": realm, "service": registry_token.SERVICE, "cert": "/etc/zot/token.crt"}
        assert "htpasswd" in config["http"]["auth"]  # Basic stays for the panel itself
        cert = x509.load_pem_x509_certificate((folder / "token.crt").read_bytes())

        # The registry settings page saving its own fields keeps the token settings.
        client.put("/api/v1/registry/settings", headers=headers,
                   json={"anonymous_pull": False, "upstreams": UPSTREAMS})
        assert client.get("/api/v1/registry/token-settings").json()["enabled"] is True

        monkeypatch.setattr(auth_api, "client_ip", lambda _request: "127.0.0.1")
        answer = client.get("/api/v1/registry/token", params=[
            ("service", registry_token.SERVICE), ("scope", "repository:library/node:pull,push"),
            ("scope", "repository:acme/private:pull")])
        assert answer.status_code == 200, answer.text
        token = answer.json()["token"]
        head, claims, signature = token.split(".")
        cert.public_key().verify(_b64decode(signature), f"{head}.{claims}".encode(),
                                 padding.PKCS1v15(), hashes.SHA256())
        assert json.loads(_b64decode(claims))["access"] == [
            {"type": "repository", "name": "library/node", "actions": ["pull"]}]

        created = client.post("/api/v1/registry/users", headers=headers,
                              json={"name": "ci", "access": "push"}).json()
        basic = base64.b64encode(f"ci:{created['password']}".encode()).decode()
        monkeypatch.setattr(auth_api, "client_ip", lambda _request: "203.0.113.9")
        user = client.get("/api/v1/registry/token", headers={"Authorization": f"Basic {basic}"},
                          params={"scope": "repository:acme/private:pull,push"})
        claims = json.loads(_b64decode(user.json()["token"].split(".")[1]))
        assert claims["sub"] == "ci" and claims["access"][0]["actions"] == ["pull", "push"]
        wrong = base64.b64encode(b"ci:wrong-password").decode()
        denied = client.get("/api/v1/registry/token", headers={"Authorization": f"Basic {wrong}"})
        assert denied.status_code == 401
        stranger = client.get("/api/v1/registry/token",
                              params={"scope": "repository:library/node:pull"})
        assert json.loads(_b64decode(stranger.json()["token"].split(".")[1]))["access"] == []

        log = client.get("/api/v1/registry/token-log").json()["items"]
        assert [item["result"] for item in log[:3]] == ["nothing", "bad_password", "granted"]
        assert log[-2]["ip"] == "127.0.0.1" and log[-2]["trusted"] is True
        assert created["password"] not in json.dumps(log)
