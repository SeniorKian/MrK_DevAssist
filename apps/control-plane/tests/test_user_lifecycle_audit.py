"""User lifecycle (delete, password reset, sign out everywhere) and audit paging."""

from __future__ import annotations

import csv
import io
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.models import AuditEvent

from .helpers import login_owner

PASSWORD = "a-strong-password-123"  # noqa: S105 - test-only fixture


@pytest.fixture
def client(tmp_path: Path):
    with TestClient(create_app(Settings.for_test(tmp_path))) as test_client:
        yield test_client


def owner_login(client: TestClient) -> tuple[str, int]:
    body = login_owner(client)
    return str(body["csrf_token"]), int(body["user"]["id"])  # type: ignore[index]


def make_user(client: TestClient, csrf: str, username: str, role: str) -> int:
    response = client.post(
        "/api/v1/users",
        headers={"X-CSRF-Token": csrf},
        json={"username": username, "password": PASSWORD, "role": role},
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def sign_in(app, username: str, password: str = PASSWORD) -> tuple[TestClient, dict]:
    other = TestClient(app)
    response = other.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return other, response.json()


def make_token(user_client: TestClient, csrf: str) -> str:
    response = user_client.post(
        "/api/v1/tokens", headers={"X-CSRF-Token": csrf},
        json={"name": "ci token", "scopes": ["audit:read"], "expires_in_seconds": 3600},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["token"])


def actions(client: TestClient) -> list[str]:
    items = client.get("/api/v1/audit-events", params={"limit": 500}).json()["items"]
    return [item["action"] for item in items]


# ----------------------------------------------------------------------------- delete


def test_delete_user_revokes_access_and_audits(client: TestClient) -> None:
    csrf, _ = owner_login(client)
    user_id = make_user(client, csrf, "leaver", "admin")
    leaver, login = sign_in(client.app, "leaver")
    token = make_token(leaver, login["csrf_token"])
    assert leaver.get("/api/v1/auth/me").status_code == 200

    # CSRF is required.
    assert client.delete(f"/api/v1/users/{user_id}").status_code == 403
    response = client.delete(f"/api/v1/users/{user_id}", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200, response.text
    assert response.json() == {"status": "deleted"}

    users = client.get("/api/v1/users").json()["items"]
    assert user_id not in [item["id"] for item in users]
    assert leaver.get("/api/v1/auth/me").status_code == 401
    bearer = TestClient(client.app)
    assert bearer.get("/api/v1/audit-events",
                      headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert "user.delete" in actions(client)
    # The username can be used again.
    make_user(client, csrf, "leaver", "viewer")
    assert client.delete("/api/v1/users/99999",
                         headers={"X-CSRF-Token": csrf}).status_code == 404


def test_delete_self_and_last_owner_are_refused(client: TestClient) -> None:
    csrf, owner_id = owner_login(client)
    response = client.delete(f"/api/v1/users/{owner_id}", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "cannot_delete_self"

    # With the second owner disabled, the first is the last enabled owner; a
    # disabled owner cannot sign in, so the store guard is exercised directly.
    second = make_user(client, csrf, "second-owner", "owner")
    patched = client.patch(f"/api/v1/users/{second}", headers={"X-CSRF-Token": csrf},
                           json={"enabled": False})
    assert patched.status_code == 200, patched.text
    from mrk_control_plane.auth import FieldError, Principal

    store = client.app.state.auth_store
    actor = Principal(second, "second-owner", "owner", frozenset({"*"}), None, "")
    with pytest.raises(FieldError) as raised:
        store.delete_user(owner_id, actor)
    assert raised.value.code == "last_owner"

    # Two enabled owners: either may delete the other.
    client.patch(f"/api/v1/users/{second}", headers={"X-CSRF-Token": csrf},
                 json={"enabled": True})
    assert client.delete(f"/api/v1/users/{second}",
                         headers={"X-CSRF-Token": csrf}).status_code == 200


def test_delete_rbac(client: TestClient) -> None:
    csrf, owner_id = owner_login(client)
    make_user(client, csrf, "boss", "admin")
    viewer_id = make_user(client, csrf, "watcher", "viewer")
    peer_id = make_user(client, csrf, "peer-admin", "admin")
    admin, login = sign_in(client.app, "boss")
    headers = {"X-CSRF-Token": login["csrf_token"]}

    # An admin cannot delete an owner.
    assert admin.delete(f"/api/v1/users/{owner_id}", headers=headers).status_code == 403
    # Viewers lack user:write.
    viewer, viewer_login = sign_in(client.app, "watcher")
    assert viewer.delete(f"/api/v1/users/{peer_id}",
                         headers={"X-CSRF-Token": viewer_login["csrf_token"]}).status_code == 403
    # An admin may delete a viewer.
    assert admin.delete(f"/api/v1/users/{viewer_id}", headers=headers).status_code == 200


# ----------------------------------------------------------------------------- password reset


def test_admin_password_reset_forces_change(client: TestClient) -> None:
    csrf, owner_id = owner_login(client)
    user_id = make_user(client, csrf, "forgetful", "operator")
    session, _ = sign_in(client.app, "forgetful")

    assert client.post(f"/api/v1/users/{user_id}/password-reset").status_code == 403
    response = client.post(f"/api/v1/users/{user_id}/password-reset",
                           headers={"X-CSRF-Token": csrf}, json={"create_link": True})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["must_change_password"] is True
    assert body["invite"]["path"].startswith("/#/invite/")
    one_time = body["one_time_password"]

    # Old sessions end, the old password stops working, the temporary one works.
    assert session.get("/api/v1/auth/me").status_code == 401
    failed = TestClient(client.app).post(
        "/api/v1/auth/login", json={"username": "forgetful", "password": PASSWORD}
    )
    assert failed.status_code == 401
    _, login = sign_in(client.app, "forgetful", one_time)
    assert login["user"]["must_change_password"] is True
    users = {item["id"]: item for item in client.get("/api/v1/users").json()["items"]}
    assert users[user_id]["must_change_password"] is True
    assert users[user_id]["invite_pending"] is True

    # The reset link works like an invite link.
    token = body["invite"]["token"]
    accepted = TestClient(client.app).post(
        f"/api/v1/auth/invite/{token}/accept",
        json={"password": "brand-new-password-456",
              "password_confirmation": "brand-new-password-456"},
    )
    assert accepted.status_code == 200, accepted.text
    assert "user.password.reset" in actions(client)

    # Not on yourself; not on an owner by an admin.
    mine = client.post(f"/api/v1/users/{owner_id}/password-reset",
                       headers={"X-CSRF-Token": csrf})
    assert mine.status_code == 409
    make_user(client, csrf, "helper", "admin")
    admin, admin_login = sign_in(client.app, "helper")
    assert admin.post(f"/api/v1/users/{owner_id}/password-reset",
                      headers={"X-CSRF-Token": admin_login["csrf_token"]}).status_code == 403


# ----------------------------------------------------------------------------- sessions


def test_revoke_sessions_and_optionally_tokens(client: TestClient) -> None:
    csrf, owner_id = owner_login(client)
    make_user(client, csrf, "roamer", "admin")
    roamer, login = sign_in(client.app, "roamer")
    token = make_token(roamer, login["csrf_token"])
    user_id = int(login["user"]["id"])
    bearer = {"Authorization": f"Bearer {token}"}
    url = f"/api/v1/users/{user_id}/sessions/revoke"

    assert client.post(url).status_code == 403  # CSRF
    response = client.post(url, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200, response.text
    assert response.json()["sessions"] >= 1 and response.json()["tokens"] == 0
    assert roamer.get("/api/v1/auth/me").status_code == 401
    assert TestClient(client.app).get("/api/v1/audit-events", headers=bearer).status_code == 200

    response = client.post(url, headers={"X-CSRF-Token": csrf}, json={"include_tokens": True})
    assert response.json()["tokens"] == 1
    assert TestClient(client.app).get("/api/v1/audit-events", headers=bearer).status_code == 401
    assert "user.sessions.revoke" in actions(client)

    # Yourself: other browsers end, this one stays.
    other_browser, _ = sign_in(client.app, "owner@example.test", "first-time-owner-password-123")
    mine = client.post(f"/api/v1/users/{owner_id}/sessions/revoke",
                       headers={"X-CSRF-Token": csrf})
    assert mine.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 200
    assert other_browser.get("/api/v1/auth/me").status_code == 401


def test_disabling_a_user_signs_them_out(client: TestClient) -> None:
    csrf, _ = owner_login(client)
    user_id = make_user(client, csrf, "paused", "viewer")
    paused, _ = sign_in(client.app, "paused")
    client.patch(f"/api/v1/users/{user_id}", headers={"X-CSRF-Token": csrf},
                 json={"enabled": False})
    assert paused.get("/api/v1/auth/me").status_code == 401


# ----------------------------------------------------------------------------- audit paging


def seed_audit(client: TestClient, count: int, action: str = "test.bulk") -> None:
    database = client.app.state.database
    now = int(time.time())
    with database.session() as db, db.begin():
        db.add_all(
            AuditEvent(actor_user_id=None, action=action, object_type="test",
                       object_id=str(index), result="success" if index % 2 else "failure",
                       occurred_at=now - count + index)
            for index in range(count)
        )


def test_audit_paging_and_filters(client: TestClient) -> None:
    owner_login(client)
    seed_audit(client, 25)
    first = client.get("/api/v1/audit-events",
                       params={"limit": 10, "action": "test.bulk"}).json()
    assert len(first["items"]) == 10 and first["next_before_id"] == first["items"][-1]["id"]
    seen = [item["id"] for item in first["items"]]
    cursor = first["next_before_id"]
    while cursor is not None:
        page = client.get("/api/v1/audit-events",
                          params={"limit": 10, "action": "test.bulk",
                                  "before_id": cursor}).json()
        seen += [item["id"] for item in page["items"]]
        cursor = page["next_before_id"]
    assert len(seen) == 25 and len(set(seen)) == 25 and seen == sorted(seen, reverse=True)

    failures = client.get("/api/v1/audit-events",
                          params={"limit": 500, "action": "test.", "result": "failure"}).json()
    assert len(failures["items"]) == 13
    assert all(item["result"] == "failure" for item in failures["items"])
    # "%" and "_" in the prefix are literal, not wildcards.
    assert client.get("/api/v1/audit-events", params={"action": "test%"}).json()["items"] == []

    window = client.get("/api/v1/audit-events", params={"limit": 500, "action": "test.bulk"})
    times = sorted(item["occurred_at"] for item in window.json()["items"])
    ranged = client.get("/api/v1/audit-events",
                        params={"limit": 500, "since": times[5], "until": times[9],
                                "action": "test.bulk"}).json()["items"]
    assert len(ranged) == 5

    _, owner_id = owner_login(client)
    mine = client.get("/api/v1/audit-events",
                      params={"limit": 500, "actor_user_id": owner_id}).json()["items"]
    assert mine and all(item["actor_user_id"] == owner_id for item in mine)

    system = client.get("/api/v1/audit-events",
                        params={"limit": 500, "actor_user_id": 0}).json()["items"]
    assert len(system) >= 25 and all(item["actor_user_id"] is None for item in system)
    several = client.get("/api/v1/audit-events",
                         params={"limit": 500, "action": "test.bulk,auth."}).json()["items"]
    assert {item["action"].split(".")[0] for item in several} == {"test", "auth"}
    not_ok = client.get("/api/v1/audit-events",
                        params={"limit": 500, "action": "test.", "result": "!success"}).json()
    assert len(not_ok["items"]) == 13

    # Backward compatible: plain call still returns items.
    assert client.get("/api/v1/audit-events").json()["items"]


def test_audit_export_streams_beyond_500_rows_with_filters(client: TestClient) -> None:
    owner_login(client)
    seed_audit(client, 1203)
    seed_audit(client, 7, action="other.thing")
    export = client.get("/api/v1/audit-events/export.csv", params={"action": "test.bulk"})
    assert export.status_code == 200
    assert "attachment" in export.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(export.text.lstrip("﻿"))))
    assert len(rows) == 1203
    assert {row["action"] for row in rows} == {"test.bulk"}
    ids = [int(row["id"]) for row in rows]
    assert len(set(ids)) == 1203

    everything = client.get("/api/v1/audit-events/export.csv")
    all_rows = list(csv.DictReader(io.StringIO(everything.text.lstrip("﻿"))))
    assert len(all_rows) > 1210
    assert "audit.export" in {row["action"] for row in all_rows}


def test_audit_requires_permission(client: TestClient) -> None:
    csrf, _ = owner_login(client)
    make_user(client, csrf, "dev-person", "developer")
    dev, _ = sign_in(client.app, "dev-person")
    from mrk_control_plane.auth import ROLE_PERMISSIONS

    if "audit:read" not in ROLE_PERMISSIONS["developer"]:
        assert dev.get("/api/v1/audit-events").status_code == 403
        assert dev.get("/api/v1/audit-events/export.csv").status_code == 403
