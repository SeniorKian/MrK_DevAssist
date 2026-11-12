"""Sliding sessions, "keep me signed in", two-step sign-in (TOTP) and OIDC single sign-on."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient
from mrk_control_plane import oidc as oidc_module
from mrk_control_plane import totp
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.models import Session as LoginSession
from mrk_control_plane.models import User

from .helpers import OWNER_EMAIL, OWNER_PASSWORD, login_owner

PASSWORD = "a-strong-password-123"  # noqa: S105 - test-only fixture


class Clock:
    def __init__(self) -> None:
        self.now = time.time()

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def app(tmp_path: Path):
    application = create_app(Settings.for_test(tmp_path))
    clock = Clock()
    application.state.auth_store.clock = clock
    application.state.clock = clock
    return application


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


def csrf_of(client: TestClient) -> str:
    return str(login_owner(client)["csrf_token"])


def make_user(client: TestClient, csrf: str, username: str, role: str = "viewer",
              email: str | None = None) -> int:
    response = client.post("/api/v1/users", headers={"X-CSRF-Token": csrf},
                           json={"username": username, "password": PASSWORD, "role": role})
    assert response.status_code == 201, response.text
    user_id = int(response.json()["id"])
    if email:
        auth = client.app.state.auth_store
        with auth.db.session() as db, db.begin():
            db.get(User, user_id).email = email
    return user_id


def sign_in(app, username: str, password: str = PASSWORD, remember: bool = True):
    other = TestClient(app)
    response = other.post("/api/v1/auth/login",
                          json={"username": username, "password": password, "remember": remember})
    return other, response


# ----------------------------------------------------------------------------- sessions


def test_remember_me_cookie_attributes(client: TestClient, app) -> None:
    csrf = csrf_of(client)
    make_user(client, csrf, "remy")
    _, kept = sign_in(app, "remy", remember=True)
    cookie = kept.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert "Max-Age=2592000" in cookie or "Max-Age=259199" in cookie
    _, plain = sign_in(app, "remy", remember=False)
    assert "Max-Age" not in plain.headers["set-cookie"]
    auth = app.state.auth_store
    with auth.db.session() as db:
        rows = db.query(LoginSession).order_by(LoginSession.id).all()
        assert rows[-2].idle_seconds == auth.session_remember_ttl_seconds
        assert rows[-1].idle_seconds == auth.session_ttl_seconds


def test_sliding_renewal_and_absolute_maximum(client: TestClient, app) -> None:
    csrf = csrf_of(client)
    make_user(client, csrf, "slider")
    browser, response = sign_in(app, "slider", remember=False)
    assert response.status_code == 200
    clock = app.state.clock
    auth = app.state.auth_store
    idle = auth.session_ttl_seconds
    # Active use well past the original idle window: the session keeps sliding.
    for _ in range(4):
        clock.now += idle * 0.6
        me = browser.get("/api/v1/auth/me")
        assert me.status_code == 200
        assert "mrk_session=" in me.headers.get("set-cookie", "")
    # Untouched for longer than the idle window: it ends.
    clock.now += idle + 1
    assert browser.get("/api/v1/auth/me").status_code == 401
    # A remembered session that stays active still ends at the absolute maximum.
    keeper, _ = sign_in(app, "slider", remember=True)
    start = clock.now
    for _ in range(auth.session_max_age_seconds // (3 * 86400) - 1):
        clock.now += 3 * 86400
        assert keeper.get("/api/v1/auth/me").status_code == 200
    clock.now = start + auth.session_max_age_seconds + 1
    assert keeper.get("/api/v1/auth/me").status_code == 401


def test_activity_writes_are_rate_limited_and_sessions_listed(client: TestClient, app) -> None:
    csrf = csrf_of(client)
    make_user(client, csrf, "lister")
    browser, response = sign_in(app, "lister")
    auth = app.state.auth_store
    with auth.db.session() as db:
        before = db.query(LoginSession).order_by(LoginSession.id.desc()).first().last_seen_at
    browser.get("/api/v1/auth/me")
    with auth.db.session() as db:
        assert db.query(LoginSession).order_by(LoginSession.id.desc()).first().last_seen_at \
            == before
    other, _ = sign_in(app, "lister")
    listing = browser.get("/api/v1/auth/sessions").json()
    assert len(listing["items"]) == 2 and sum(item["current"] for item in listing["items"]) == 1
    token = response.json()["csrf_token"]
    ended = browser.post("/api/v1/auth/sessions/revoke-others", headers={"X-CSRF-Token": token})
    assert ended.status_code == 200 and ended.json()["sessions"] == 1
    assert other.get("/api/v1/auth/me").status_code == 401


# ----------------------------------------------------------------------------- TOTP


def enroll(browser: TestClient, csrf: str, app) -> tuple[str, list[str]]:
    started = browser.post("/api/v1/auth/mfa/totp/start", headers={"X-CSRF-Token": csrf},
                           json={"current_password": PASSWORD})
    assert started.status_code == 200, started.text
    body = started.json()
    assert body["otpauth_uri"].startswith("otpauth://totp/MrK%20DevAssist%3A")
    secret = body["secret"]
    wrong = browser.post("/api/v1/auth/mfa/totp/confirm", headers={"X-CSRF-Token": csrf},
                         json={"code": "000000" if totp.code_at(secret, 1) != "000000" else "1"})
    assert wrong.status_code == 422
    now = app.state.clock.now
    code = totp.code_at(secret, totp.time_step(now))
    confirmed = browser.post("/api/v1/auth/mfa/totp/confirm", headers={"X-CSRF-Token": csrf},
                             json={"code": code})
    assert confirmed.status_code == 200, confirmed.text
    codes = confirmed.json()["recovery_codes"]
    assert len(codes) == 10
    return secret, codes


def test_totp_enroll_login_replay_recovery_and_lockout(client: TestClient, app) -> None:
    csrf = csrf_of(client)
    make_user(client, csrf, "tess", role="operator")
    browser, response = sign_in(app, "tess")
    user_csrf = response.json()["csrf_token"]
    secret, codes = enroll(browser, user_csrf, app)
    assert browser.get("/api/v1/auth/mfa").json()["enabled"] is True
    auth = app.state.auth_store
    with auth.db.session() as db:
        from mrk_control_plane.models import UserMfa

        stored = db.query(UserMfa).one()
        assert codes[0] not in json.dumps(stored.recovery_hashes)
    clock = app.state.clock
    clock.now += 60  # a fresh step

    # Password alone is not enough any more.
    other, first = sign_in(app, "tess")
    assert first.status_code == 200 and first.json()["status"] == "mfa_required"
    assert "set-cookie" not in first.headers
    challenge = first.json()["challenge"]
    code = totp.code_at(secret, totp.time_step(clock.now))
    done = other.post("/api/v1/auth/login/mfa", json={"challenge": challenge, "code": code})
    assert done.status_code == 200, done.text
    assert other.get("/api/v1/auth/me").status_code == 200
    # The challenge is single-use and the same code never works twice.
    again = other.post("/api/v1/auth/login/mfa", json={"challenge": challenge, "code": code})
    assert again.status_code == 401
    _, second = sign_in(app, "tess")
    replay = other.post("/api/v1/auth/login/mfa",
                        json={"challenge": second.json()["challenge"], "code": code})
    assert replay.status_code == 401 and replay.json()["error"]["code"] == "invalid_mfa_code"
    # A recovery code works once.
    _, third = sign_in(app, "tess")
    used = other.post("/api/v1/auth/login/mfa",
                      json={"challenge": third.json()["challenge"], "recovery_code": codes[0]})
    assert used.status_code == 200 and used.json()["recovery_codes_left"] == 9
    _, fourth = sign_in(app, "tess")
    reuse = other.post("/api/v1/auth/login/mfa",
                       json={"challenge": fourth.json()["challenge"], "recovery_code": codes[0]})
    assert reuse.status_code == 401
    # Wrong codes lock the second step.
    statuses = []
    for _ in range(6):
        statuses.append(other.post("/api/v1/auth/login/mfa", json={
            "challenge": fourth.json()["challenge"], "code": "999999"}).status_code)
    assert statuses[-1] == 429
    # A forged or tampered challenge is refused.
    bad = other.post("/api/v1/auth/login/mfa",
                     json={"challenge": fourth.json()["challenge"][:-2] + "xx", "code": "1"})
    assert bad.status_code == 401
    audit = client.get("/api/v1/audit-events?limit=200").json()
    text = json.dumps(audit)
    assert secret not in text and code not in text and codes[1] not in text
    assert "auth.mfa.enable" in text and "auth.login.mfa" in text


def test_disable_regenerate_admin_reset_and_policy(client: TestClient, app) -> None:
    owner_csrf = csrf_of(client)
    user_id = make_user(client, owner_csrf, "dana", role="developer")
    browser, response = sign_in(app, "dana")
    csrf = response.json()["csrf_token"]
    secret, _codes = enroll(browser, csrf, app)
    clock = app.state.clock
    clock.now += 60
    regenerated = browser.post("/api/v1/auth/mfa/recovery-codes", headers={"X-CSRF-Token": csrf},
                               json={"code": totp.code_at(secret, totp.time_step(clock.now))})
    assert regenerated.status_code == 200 and len(regenerated.json()["recovery_codes"]) == 10
    clock.now += 60
    no_password = browser.post("/api/v1/auth/mfa/disable", headers={"X-CSRF-Token": csrf},
                               json={"code": totp.code_at(secret, totp.time_step(clock.now))})
    assert no_password.status_code == 422
    # Admin reset (lost phone), audited.
    reset = client.post(f"/api/v1/users/{user_id}/mfa/reset",
                        headers={"X-CSRF-Token": owner_csrf})
    assert reset.status_code == 200 and reset.json()["was_enabled"] is True
    _, plain = sign_in(app, "dana")
    assert "user" in plain.json()

    # Policy: developers must use two-step sign-in; until enrolled only setup works.
    policy = client.put("/api/v1/auth/mfa/policy", headers={"X-CSRF-Token": owner_csrf},
                        json={"mode": "roles", "roles": ["developer"]})
    assert policy.status_code == 200, policy.text
    forced, login = sign_in(app, "dana")
    assert login.json()["user"]["must_enroll_mfa"] is True
    blocked = forced.get("/api/v1/system/status")
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "mfa_enrollment_required"
    enroll(forced, login.json()["csrf_token"], app)
    assert forced.get("/api/v1/system/status").status_code == 200
    # Required by policy: cannot be switched off by the person.
    clock.now += 60
    status = forced.get("/api/v1/auth/mfa").json()
    assert status["required"] is True
    bad = client.put("/api/v1/auth/mfa/policy", headers={"X-CSRF-Token": owner_csrf},
                     json={"mode": "roles", "roles": ["nope"]})
    assert bad.status_code == 422


# ----------------------------------------------------------------------------- OIDC

ISSUER = "https://idp.example.com"
CLIENT_ID = "devassist-panel"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class FakeIdp:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.claims: dict[str, Any] = {}
        self.nonce = ""
        self.sign_with = self.key
        self.token_requests: list[httpx.Request] = []

    def jwk(self) -> dict[str, Any]:
        numbers = self.key.public_key().public_numbers()
        return {
            "kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
            "n": b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64(numbers.e.to_bytes(3, "big")),
        }

    def id_token(self) -> str:
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "iat": now,
                  "exp": now + 300, "nonce": self.nonce, "email": "sam@corp.example",
                  "email_verified": True, "name": "Sam Doe",
                  "preferred_username": "sam"}
        claims.update(self.claims)
        claims = {key: value for key, value in claims.items() if value is not None}
        header = b64(json.dumps({"alg": "RS256", "kid": "k1", "typ": "JWT"}).encode())
        body = b64(json.dumps(claims).encode())
        signature = self.sign_with.sign(f"{header}.{body}".encode(), padding.PKCS1v15(),
                                        hashes.SHA256())
        return f"{header}.{body}.{b64(signature)}"

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert (request.headers.get("host") or request.url.host) == "idp.example.com"
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize",
                "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/jwks",
                "code_challenge_methods_supported": ["S256"],
            })
        if path == "/jwks":
            return httpx.Response(200, json={"keys": [self.jwk()]})
        if path == "/token":
            self.token_requests.append(request)
            form = parse_qs(request.content.decode())
            assert form["code"] == ["the-code"] and form["code_verifier"][0]
            assert form["client_secret"] == ["s3cret-value"]
            return httpx.Response(200, json={"id_token": self.id_token(),
                                             "access_token": "at", "token_type": "Bearer"})
        return httpx.Response(404)


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdp()
    monkeypatch.setattr(oidc_module, "TRANSPORT_FACTORY",
                        lambda: httpx.MockTransport(fake.handler))
    monkeypatch.setattr(oidc_module, "RESOLVER", lambda host, port, config: ["93.184.216.34"])
    return fake


def configure(client: TestClient, csrf: str, **extra: Any) -> httpx.Response:
    payload = {"enabled": True, "display_name": "Corp", "issuer": ISSUER,
               "client_id": CLIENT_ID, "client_secret": "s3cret-value", **extra}
    return client.put("/api/v1/auth/oidc/settings", headers={"X-CSRF-Token": csrf},
                      json=payload)


def sso(app, idp: FakeIdp, **claims: Any) -> tuple[TestClient, str]:
    browser = TestClient(app)
    start = browser.get("/api/v1/auth/oidc/start", follow_redirects=False)
    assert start.status_code == 303, start.text
    location = urlsplit(start.headers["location"])
    assert location.netloc == "idp.example.com"
    query = parse_qs(location.query)
    assert query["code_challenge_method"] == ["S256"] and query["code_challenge"][0]
    idp.nonce = query["nonce"][0]
    idp.claims = claims
    back = browser.get(
        f"/api/v1/auth/oidc/callback?code=the-code&state={query['state'][0]}",
        follow_redirects=False,
    )
    assert back.status_code == 303
    return browser, back.headers["location"]


def test_oidc_settings_and_capabilities(client: TestClient, idp: FakeIdp) -> None:
    csrf = csrf_of(client)
    assert client.get("/api/v1/auth/capabilities").json()["oidc"]["enabled"] is False
    assert configure(client, csrf, issuer="http://idp.example.com").status_code == 422
    saved = configure(client, csrf)
    assert saved.status_code == 200, saved.text
    body = saved.json()
    assert body["client_secret_set"] is True and "s3cret" not in saved.text
    assert body["redirect_uri"].endswith("/api/v1/auth/oidc/callback")
    caps = client.get("/api/v1/auth/capabilities").json()["oidc"]
    assert caps["enabled"] is True and caps["display_name"] == "Corp"
    assert configure(client, csrf, default_role="owner").status_code == 422
    tested = client.post("/api/v1/auth/oidc/test", headers={"X-CSRF-Token": csrf})
    assert tested.json()["ok"] is True


def test_oidc_login_links_by_verified_email(client: TestClient, app, idp: FakeIdp) -> None:
    csrf = csrf_of(client)
    make_user(client, csrf, "sam", email="sam@corp.example")
    assert configure(client, csrf).status_code == 200
    browser, location = sso(app, idp)
    assert location == "/?sso=ok"
    me = browser.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["user"]["username"] == "sam"
    # Linked by subject from now on, even if the email claim changes.
    browser2, location2 = sso(app, idp, email="new@corp.example")
    assert location2 == "/?sso=ok"


@pytest.mark.parametrize(
    ("claims", "code"),
    [
        ({"aud": "someone-else"}, "sso_token_invalid"),
        ({"iss": "https://evil.example.com"}, "sso_token_invalid"),
        ({"nonce": "wrong"}, "sso_token_invalid"),
        ({"exp": int(time.time()) - 3600}, "sso_token_invalid"),
        ({"email_verified": False}, "sso_email_unverified"),
        ({"email": "sam@other.example"}, "sso_domain_not_allowed"),
        ({"email": "nobody@corp.example"}, "sso_no_account"),
    ],
)
def test_oidc_rejections(client: TestClient, app, idp: FakeIdp, claims, code) -> None:
    csrf = csrf_of(client)
    make_user(client, csrf, "sam", email="sam@corp.example")
    assert configure(client, csrf, allowed_domains=["corp.example"]).status_code == 200
    browser, location = sso(app, idp, **claims)
    assert location == f"/?sso_error={code}"
    assert browser.get("/api/v1/auth/me").status_code == 401


def test_oidc_bad_signature_and_state(client: TestClient, app, idp: FakeIdp) -> None:
    csrf = csrf_of(client)
    make_user(client, csrf, "sam", email="sam@corp.example")
    assert configure(client, csrf).status_code == 200
    idp.sign_with = idp.other_key
    browser, location = sso(app, idp)
    assert location == "/?sso_error=sso_token_invalid"
    forged = TestClient(app).get("/api/v1/auth/oidc/callback?code=the-code&state=abc",
                                 follow_redirects=False)
    assert forged.headers["location"] == "/?sso_error=sso_state_invalid"
    assert browser.get("/api/v1/auth/me").status_code == 401


def test_oidc_auto_create_and_local_mfa(client: TestClient, app, idp: FakeIdp) -> None:
    csrf = csrf_of(client)
    assert configure(client, csrf).status_code == 200
    _, location = sso(app, idp, email="fresh@corp.example", sub="fresh-1")
    assert location == "/?sso_error=sso_no_account"
    assert configure(client, csrf, auto_create=True, default_role="viewer").status_code == 200
    browser, location = sso(app, idp, email="fresh@corp.example", sub="fresh-1")
    assert location == "/?sso=ok"
    user = browser.get("/api/v1/auth/me").json()["user"]
    assert user["role"] == "viewer" and user["email"] == "fresh@corp.example"
    # An SSO account cannot sign in with a password.
    _, password_try = sign_in(app, user["username"], password=PASSWORD)
    assert password_try.status_code == 401

    # Local two-step still applies after SSO unless the IdP's is trusted.
    secret, _ = enroll_sso(browser, app)
    app.state.clock.now += 60
    second, location = sso(app, idp, email="fresh@corp.example", sub="fresh-1")
    assert location == "/?sso=mfa"
    assert second.get("/api/v1/auth/me").status_code == 401
    finished = second.post("/api/v1/auth/login/mfa", json={
        "code": totp.code_at(secret, totp.time_step(app.state.clock.now))})
    assert finished.status_code == 200, finished.text
    assert second.get("/api/v1/auth/me").status_code == 200
    assert configure(client, csrf, trust_idp_mfa=True).status_code == 200
    _, location = sso(app, idp, email="fresh@corp.example", sub="fresh-1")
    assert location == "/?sso=ok"


def enroll_sso(browser: TestClient, app) -> tuple[str, list[str]]:
    csrf = browser.get("/api/v1/auth/me").json()["csrf_token"]
    started = browser.post("/api/v1/auth/mfa/totp/start", headers={"X-CSRF-Token": csrf},
                           json={})
    assert started.status_code == 200, started.text
    secret = started.json()["secret"]
    code = totp.code_at(secret, totp.time_step(app.state.clock.now))
    confirmed = browser.post("/api/v1/auth/mfa/totp/confirm", headers={"X-CSRF-Token": csrf},
                             json={"code": code})
    assert confirmed.status_code == 200, confirmed.text
    return secret, confirmed.json()["recovery_codes"]


def test_sso_only_blocks_passwords_for_non_owners(client: TestClient, app, idp) -> None:
    csrf = csrf_of(client)
    make_user(client, csrf, "pat", email="pat@corp.example")
    assert configure(client, csrf, sso_only=True).status_code == 200
    _, response = sign_in(app, "pat")
    assert response.status_code == 403 and response.json()["error"]["code"] == "sso_required"
    owner = TestClient(app).post("/api/v1/auth/login",
                                 json={"username": OWNER_EMAIL, "password": OWNER_PASSWORD})
    assert owner.status_code == 200


def test_totp_primitives() -> None:
    # RFC 6238 appendix B (SHA1, 8 digits there; the 6-digit tail must match).
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp.code_at(secret, 59 // 30) == "287082"
    assert totp.matching_step(secret, "287082", 59) == 1
    assert totp.matching_step(secret, "287082", 59, last_step=1) is None
    assert totp.unsign(b"k" * 32, "x", totp.sign(b"k" * 32, "y", {"a": 1})) is None
