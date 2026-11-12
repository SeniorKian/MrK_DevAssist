# ruff: noqa: S105, S106 - throwaway test passwords and secrets
"""Operators may choose the password of every human-facing account (or keep the suggestion).

Panel invites/resets, registry (Zot) users, Git (Gitea) users and S3 secret keys
(admin and «my space») accept an optional value; omitted, one is generated as
before. A typed value is checked, a weak one is refused, and the value never
reaches the audit log or the log output.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

import bcrypt
import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.auth import FieldError
from mrk_control_plane.config import Settings
from mrk_control_plane.credential_policy import check_password, check_secret_key
from mrk_control_plane.main import create_app
from mrk_control_plane.models import AuditEvent
from mrk_control_plane.modules import git_service, registry_service
from mrk_control_plane.modules import s3 as s3_module
from sqlalchemy import select

from .helpers import login_owner
from .test_git_registry import FakeGitea, env_value
from .test_my_space import Space, bucket, unlimited
from .test_my_space import env as env  # noqa: F401 - pytest fixture
from .test_my_space import space as space  # noqa: F401 - pytest fixture
from .test_s3_admin import client as client  # noqa: F401 - pytest fixture
from .test_s3_admin import engine as engine  # noqa: F401 - pytest fixture
from .test_s3_admin import links as links  # noqa: F401 - pytest fixture
from .test_s3_admin import make_bucket

CHOSEN = "Chosen-pass-2026"
CHOSEN_SECRET = "My-own-S3-secret-key-2026"


def audit_text(app: Any) -> str:
    with app.state.database.session() as db:
        rows = db.execute(select(AuditEvent)).scalars().all()
        return json.dumps([{column.name: getattr(row, column.name)
                            for column in AuditEvent.__table__.columns} for row in rows],
                          default=str)


def error(response: httpx.Response) -> dict[str, Any]:
    return response.json()["error"]


@pytest.fixture
def app_client(tmp_path: Path, monkeypatch):
    for name in ("MRK_PANEL_RUNTIME", "MRK_HOST_DATA_DIR"):
        monkeypatch.delenv(name, raising=False)
    settings = Settings.for_test(tmp_path / "cp")
    with TestClient(create_app(settings)) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        yield client, headers, settings


# ----------------------------------------------------------------------------- policy helpers


def test_policy_helpers() -> None:
    assert check_password(CHOSEN) == CHOSEN
    reasons = {}
    for value in ("ab1", "onlyletters", "1234567890", "tab\there-123", "x" * 300 + "1"):
        with pytest.raises(FieldError) as caught:
            check_password(value)
        assert caught.value.code == "weak_password"
        reasons[value[:5]] = caught.value.reason
    assert set(reasons.values()) == {"too_short", "missing_digit", "missing_letter",
                                     "invalid_characters", "too_long"}
    # bcrypt reads only 72 bytes: a longer (multi-byte) value is refused, not truncated.
    with pytest.raises(FieldError) as caught:
        check_password("رمز" * 20 + "a1", max_bytes=72)
    assert caught.value.reason == "too_long"
    with pytest.raises(FieldError) as caught:
        check_password("abc12", min_length=8)
    assert caught.value.fields[0]["params"]["min_length"] == 8  # type: ignore[index]

    assert check_secret_key(CHOSEN_SECRET) == CHOSEN_SECRET
    for value, reason in (("ab1", "too_short"), ("a1" * 70, "too_long"),
                          ("has space 123", "invalid_characters"),
                          ("non-ascii-é-123", "invalid_characters"),
                          ("abcdefghij", "missing_digit")):
        with pytest.raises(FieldError) as caught:
            check_secret_key(value)
        assert caught.value.code == "invalid_secret_key" and caught.value.reason == reason


# ----------------------------------------------------------------------------- panel users


def test_panel_invite_and_reset_take_a_chosen_password(app_client, caplog) -> None:
    client, headers, _settings = app_client
    caplog.set_level(logging.DEBUG)
    weak = client.post("/api/v1/users/invite", headers=headers, json={
        "display_name": "Sara Karimi", "role": "viewer", "password": "short"})
    assert weak.status_code == 422
    assert error(weak)["code"] == "weak_password"
    assert error(weak)["fields"][0] == {"field": "password", "reason_code": "too_short",
                                       "params": {"min_length": 6, "max_length": 256}}

    invited = client.post("/api/v1/users/invite", headers=headers, json={
        "display_name": "Sara Karimi", "role": "viewer", "password": CHOSEN})
    assert invited.status_code == 201, invited.text
    body = invited.json()
    assert body["one_time_password"] == CHOSEN and body["must_change_password"] is True
    username = body["user"]["username"]
    login = TestClient(client.app).post("/api/v1/auth/login",
                                        json={"username": username, "password": CHOSEN})
    assert login.status_code == 200 and login.json()["must_change_password"] is True
    user_id = body["user"]["id"]

    generated = client.post(f"/api/v1/users/{user_id}/password-reset", headers=headers,
                            json={"create_link": False})
    assert generated.status_code == 200
    assert generated.json()["one_time_password"] != CHOSEN

    bad = client.post(f"/api/v1/users/{user_id}/password-reset", headers=headers,
                      json={"password": "lettersonly"})
    assert error(bad)["code"] == "weak_password"
    assert error(bad)["fields"][0]["reason_code"] == "missing_digit"
    again = "Another-choice-77"
    reset = client.post(f"/api/v1/users/{user_id}/password-reset", headers=headers,
                        json={"password": again, "create_link": False})
    assert reset.status_code == 200 and reset.json()["one_time_password"] == again
    assert TestClient(client.app).post(
        "/api/v1/auth/login", json={"username": username, "password": again}
    ).status_code == 200
    # Omitted body still works (backward compatible).
    assert client.post(f"/api/v1/users/{user_id}/password-reset",
                       headers=headers).status_code == 200

    for value in (CHOSEN, again):
        assert value not in audit_text(client.app)
        assert value not in caplog.text


# ----------------------------------------------------------------------------- registry


def connect_registry(client: TestClient, headers: dict[str, str], monkeypatch) -> None:
    client.post("/api/v1/install/registry/bundle", headers=headers, json={})
    monkeypatch.setattr(registry_service, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(
        lambda request: httpx.Response(200, json={})))
    assert client.post("/api/v1/install/registry/connect", headers=headers,
                       json={}).json()["connection"] == "connected"


def htpasswd_hash(settings: Settings, name: str) -> bytes:
    lines = (settings.data_dir / "registry" / "htpasswd").read_text().splitlines()
    return next(line for line in lines if line.startswith(f"{name}:")).split(":", 1)[1].encode()


def test_registry_user_chosen_password_and_reset(app_client, monkeypatch, caplog) -> None:
    client, headers, settings = app_client
    caplog.set_level(logging.DEBUG)
    connect_registry(client, headers, monkeypatch)

    weak = client.post("/api/v1/registry/users", headers=headers,
                       json={"name": "ci", "access": "push", "password": "abcdefgh"})
    assert weak.status_code == 422 and error(weak)["code"] == "weak_password"
    assert error(weak)["fields"][0]["reason_code"] == "missing_digit"
    too_long = client.post("/api/v1/registry/users", headers=headers,
                           json={"name": "ci", "access": "push", "password": "a1" * 40})
    assert error(too_long)["fields"][0]["reason_code"] == "too_long"
    assert client.get("/api/v1/registry/users").json()["items"] == []

    created = client.post("/api/v1/registry/users", headers=headers,
                          json={"name": "ci", "access": "push", "password": CHOSEN})
    assert created.status_code == 201, created.text
    assert created.json()["password"] == CHOSEN
    assert bcrypt.checkpw(CHOSEN.encode(), htpasswd_hash(settings, "ci"))

    generated = client.post("/api/v1/registry/users", headers=headers,
                            json={"name": "bot", "access": "pull"}).json()
    assert len(generated["password"]) >= 24

    reset = client.post("/api/v1/registry/users/ci/password", headers=headers,
                        json={"password": "Fresh-registry-9"})
    assert reset.status_code == 200 and reset.json()["password"] == "Fresh-registry-9"
    assert bcrypt.checkpw(b"Fresh-registry-9", htpasswd_hash(settings, "ci"))
    assert not bcrypt.checkpw(CHOSEN.encode(), htpasswd_hash(settings, "ci"))
    rolled = client.post("/api/v1/registry/users/ci/password", headers=headers)
    assert rolled.status_code == 200 and len(rolled.json()["password"]) >= 24
    weak_reset = client.post("/api/v1/registry/users/ci/password", headers=headers,
                             json={"password": "x"})
    assert error(weak_reset)["code"] == "weak_password"
    missing = client.post("/api/v1/registry/users/nobody/password", headers=headers, json={})
    assert missing.status_code == 404
    assert client.post("/api/v1/registry/users/ci/password", json={}).status_code == 403  # CSRF

    state = (settings.data_dir / "control-plane" / "registry.json").read_text()
    for value in (CHOSEN, "Fresh-registry-9"):
        assert value not in state
        assert value not in audit_text(client.app)
        assert value not in caplog.text
    assert "registry.user.password" in audit_text(client.app)


# ----------------------------------------------------------------------------- git


class EditableGitea(FakeGitea):
    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "PATCH" and path.startswith("/api/v1/admin/users/"):
            body = json.loads(request.content)
            self.calls.append((request.method, path, body))
            login = path.rsplit("/", 1)[1]
            if not any(user["login"] == login for user in self.users):
                return httpx.Response(404, json={"message": "user does not exist"})
            return httpx.Response(200, json={"id": 5, "login": login})
        return super().__call__(request)


def test_git_user_chosen_password_and_reset(app_client, monkeypatch, caplog) -> None:
    client, headers, _settings = app_client
    caplog.set_level(logging.DEBUG)
    bundle = client.post("/api/v1/install/git/bundle", headers=headers, json={}).json()
    fake = EditableGitea(env_value(bundle["env"], "MRK_GIT_ADMIN_PASSWORD"))
    monkeypatch.setattr(git_service, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(fake))
    assert client.post("/api/v1/install/git/connect", headers=headers,
                       json={}).json()["connection"] == "connected"

    # Gitea needs 8 characters even when the panel policy allows 6.
    short = client.post("/api/v1/git/users", headers=headers, json={
        "login": "sara", "email": "sara@example.com", "password": "abc123"})
    assert short.status_code == 422 and error(short)["code"] == "weak_password"
    assert error(short)["fields"][0]["params"]["min_length"] == 8
    assert not any(call[0] == "POST" and call[1] == "/api/v1/admin/users"
                   for call in fake.calls)

    created = client.post("/api/v1/git/users", headers=headers, json={
        "login": "sara", "email": "sara@example.com", "password": CHOSEN,
        "must_change_password": False})
    assert created.status_code == 201, created.text
    assert created.json()["password"] == CHOSEN
    sent = next(call[2] for call in fake.calls if call[1] == "/api/v1/admin/users")
    assert sent["password"] == CHOSEN and sent["must_change_password"] is False

    generated = client.post("/api/v1/git/users", headers=headers, json={
        "login": "omid", "email": "omid@example.com"}).json()
    assert len(generated["password"]) >= 16

    reset = client.post("/api/v1/git/users/sara/password", headers=headers,
                        json={"password": "Fresh-git-pass-1"})
    assert reset.status_code == 200, reset.text
    assert reset.json() == {"login": "sara", "password": "Fresh-git-pass-1",
                            "must_change_password": True}
    patch = [call[2] for call in fake.calls if call[0] == "PATCH"][-1]
    assert patch["password"] == "Fresh-git-pass-1" and patch["must_change_password"] is True
    rolled = client.post("/api/v1/git/users/sara/password", headers=headers)
    assert rolled.status_code == 200 and len(rolled.json()["password"]) >= 16
    weak = client.post("/api/v1/git/users/sara/password", headers=headers,
                       json={"password": "12345678"})
    assert error(weak)["fields"][0]["reason_code"] == "missing_letter"
    assert client.post("/api/v1/git/users/mrk-panel/password", headers=headers,
                       json={}).status_code == 422  # never the panel's own admin
    assert client.post("/api/v1/git/users/ghost/password", headers=headers,
                       json={}).status_code == 404

    for value in (CHOSEN, "Fresh-git-pass-1"):
        assert value not in audit_text(client.app)
        assert value not in caplog.text
    assert "git.user.password" in audit_text(client.app)


# ----------------------------------------------------------------------------- S3 admin


def stored_secret(akid: str) -> str:
    store = s3_module.ACTIVE_STORE
    assert store is not None
    snapshot = store.snapshot()
    for identity in snapshot["identities"]:
        for key in identity.get("keys") or []:
            if key["access_key_id"] == akid:
                return str(store.secrets.get(key["secret_ref"])["secret_access_key"])
    raise AssertionError(akid)


def test_s3_admin_key_chosen_secret_and_reset(client, caplog) -> None:  # noqa: F811
    caplog.set_level(logging.DEBUG)
    headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
    assert make_bucket(client, headers, "backups").status_code == 201
    ident = client.post("/api/v1/s3/identities", headers=headers, json={
        "name": "ci", "policy_template": "read_only", "buckets": ["backups"]}).json()
    base = f"/api/v1/s3/identities/{ident['id']}/keys"

    bad = client.post(base, headers=headers, json={"secret_access_key": "has space 1"})
    assert bad.status_code == 422 and error(bad)["code"] == "invalid_secret_key"
    assert error(bad)["fields"][0] == {"field": "secret_access_key",
                                      "reason_code": "invalid_characters"}
    unknown = client.post(base, headers=headers, json={"access_key_id": "MRKX"})
    assert unknown.status_code == 422

    key = client.post(base, headers=headers, json={"secret_access_key": CHOSEN_SECRET})
    assert key.status_code == 201, key.text
    akid = key.json()["access_key_id"]
    assert key.json()["secret_access_key"] == CHOSEN_SECRET
    assert re.fullmatch(r"MRK[A-Z0-9]{17}", akid)
    assert stored_secret(akid) == CHOSEN_SECRET
    generated = client.post(base, headers=headers).json()
    assert len(generated["secret_access_key"]) == 40

    reset = client.post(f"{base}/{akid}/secret", headers=headers,
                        json={"secret_access_key": "Fresh-S3-secret-42"})
    assert reset.status_code == 200, reset.text
    assert reset.json()["access_key_id"] == akid
    assert reset.json()["secret_access_key"] == "Fresh-S3-secret-42"
    assert stored_secret(akid) == "Fresh-S3-secret-42"
    rolled = client.post(f"{base}/{akid}/secret", headers=headers)
    assert rolled.status_code == 200 and len(rolled.json()["secret_access_key"]) == 40
    assert stored_secret(akid) == rolled.json()["secret_access_key"]
    short = client.post(f"{base}/{akid}/secret", headers=headers,
                        json={"secret_access_key": "a1"})
    assert error(short)["fields"][0]["reason_code"] == "too_short"
    assert client.post(f"{base}/MRKNOPE/secret", headers=headers, json={}).status_code == 404

    for value in (CHOSEN_SECRET, "Fresh-S3-secret-42"):
        assert value not in audit_text(client.app)
        assert value not in caplog.text
    assert "s3.key.secret" in audit_text(client.app)


# ----------------------------------------------------------------------------- my space S3


def test_my_space_key_chosen_secret_and_reset(space: Space, caplog) -> None:  # noqa: F811
    caplog.set_level(logging.DEBUG)
    bob = space.user("bob")
    unlimited(space, bob)
    bucket(bob, "bob-files")
    weak = bob.post("/s3/keys", {"name": "ci", "access": "read_only", "buckets": ["bob-files"],
                                 "secret_access_key": "short"})
    assert weak.status_code == 422 and error(weak)["code"] == "invalid_secret_key"
    assert bob.get("/s3/keys").json()["items"] == []  # nothing reserved by a refused key

    key = bob.post("/s3/keys", {"name": "ci", "access": "read_only", "buckets": ["bob-files"],
                                "secret_access_key": CHOSEN_SECRET})
    assert key.status_code == 201, key.text
    assert key.json()["secret_access_key"] == CHOSEN_SECRET
    identity, akid = key.json()["id"], key.json()["access_key_id"]
    assert stored_secret(akid) == CHOSEN_SECRET

    reset = bob.post(f"/s3/keys/{identity}/secret", {"secret_access_key": "Fresh-S3-secret-42"})
    assert reset.status_code == 200, reset.text
    assert reset.json() == {"id": identity, "access_key_id": akid,
                            "secret_access_key": "Fresh-S3-secret-42"}
    assert stored_secret(akid) == "Fresh-S3-secret-42"
    rolled = bob.post(f"/s3/keys/{identity}/secret")
    assert rolled.status_code == 200 and len(rolled.json()["secret_access_key"]) == 40
    bad = bob.post(f"/s3/keys/{identity}/secret", {"secret_access_key": "no digits here"})
    assert bad.status_code == 422

    alice = space.user("alice")
    assert alice.post(f"/s3/keys/{identity}/secret").status_code == 404  # not hers

    for value in (CHOSEN_SECRET, "Fresh-S3-secret-42"):
        assert value not in audit_text(space.client.app)
        assert value not in caplog.text
