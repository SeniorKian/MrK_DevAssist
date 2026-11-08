"""Custom roles, invites, must-change-password and field errors (docs/33 §2.3, §5)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from mrk_control_plane import auth as auth_module
from mrk_control_plane.auth import (
    BUILTIN_ROLE_INFO,
    KNOWN_PERMISSIONS,
    PERMISSION_REQUIRES,
    ROLE_PERMISSIONS,
    AuthStore,
    FieldError,
    PermissionEscalationError,
    missing_dependencies,
)
from mrk_control_plane.config import Settings
from mrk_control_plane.database import Database
from mrk_control_plane.main import create_app
from mrk_control_plane.models import AuditEvent, UserInvite
from sqlalchemy import inspect, select

from .helpers import login_owner

PASSWORD = "a-strong-password-123"  # noqa: S105 - test-only fixture


@pytest.fixture
def client(tmp_path: Path):
    with TestClient(create_app(Settings.for_test(tmp_path))) as test_client:
        yield test_client


def owner_csrf(client: TestClient) -> str:
    return str(login_owner(client)["csrf_token"])


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


def create_role(client: TestClient, csrf: str, name: str, permissions: list[str]):
    return client.post(
        "/api/v1/roles",
        headers={"X-CSRF-Token": csrf},
        json={"name": name, "description": "made in a test", "permissions": permissions},
    )


# ----------------------------------------------------------------------------- catalogue


def test_catalogue_covers_every_builtin_permission_and_roles_are_closed() -> None:
    granted = set().union(*(perms for perms in ROLE_PERMISSIONS.values())) - {"*"}
    assert granted == set(KNOWN_PERMISSIONS)
    for role, perms in ROLE_PERMISSIONS.items():
        if "*" not in perms:
            assert missing_dependencies(perms) == {}, role
    for permission, requires in PERMISSION_REQUIRES.items():
        assert requires <= KNOWN_PERMISSIONS, permission
    assert set(BUILTIN_ROLE_INFO) == set(ROLE_PERMISSIONS)


def test_permissions_endpoint_groups_by_nav_section(client: TestClient) -> None:
    owner_csrf(client)
    body = client.get("/api/v1/permissions").json()
    ids = [group["id"] for group in body["groups"]]
    assert ids == ["home", "packages", "server", "files", "security", "people", "alerts"]
    flat = {item["id"]: item for group in body["groups"] for item in group["permissions"]}
    assert set(flat) == set(KNOWN_PERMISSIONS) | {"*"}
    assert flat["*"]["assignable"] is False
    assert flat["cache:write"]["requires"] == ["cache:read"]
    assert flat["docker:prune"]["requires"] == ["docker:operate"]
    assert flat["firewall:write"]["danger"] == "critical"
    for item in flat.values():
        assert item["name_fa"] and item["name_en"]
        assert item["description_fa"] and item["description_en"]
        assert item["danger"] in body["danger_levels"]


def test_roles_endpoint_returns_cards(client: TestClient) -> None:
    owner_csrf(client)
    items = {item["id"]: item for item in client.get("/api/v1/roles").json()["items"]}
    assert list(items)[:5] == ["owner", "admin", "operator", "developer", "viewer"]
    viewer = items["viewer"]
    assert viewer["name"] == "viewer" and viewer["builtin"] is True
    assert viewer["name_fa"] == "بیننده" and viewer["can_fa"] and viewer["cannot_en"]
    assert viewer["permissions"] == sorted(ROLE_PERMISSIONS["viewer"])
    assert items["owner"]["user_count"] == 1


# ----------------------------------------------------------------------------- custom roles


def test_custom_role_crud_and_permission_resolution(client: TestClient) -> None:
    csrf = owner_csrf(client)
    created = create_role(client, csrf, "Package keeper", ["cache:read", "cache:write"])
    assert created.status_code == 201, created.text
    role = created.json()
    assert role["id"].startswith("custom:") and role["builtin"] is False
    assert role["permissions"] == ["cache:read", "cache:write"]
    make_user(client, csrf, "keeper", role["id"])

    keeper, login = sign_in(client.app, "keeper")
    assert sorted(login["user"]["permissions"]) == ["cache:read", "cache:write"]
    assert keeper.get("/api/v1/packages").status_code == 200
    assert keeper.get("/api/v1/upstreams").status_code == 403

    # Editing the role applies to the open session at once (computed per request).
    patched = client.patch(
        f"/api/v1/roles/{role['id']}",
        headers={"X-CSRF-Token": csrf},
        json={"permissions": ["cache:read", "upstream:read"], "name": "Reader"},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["name_en"] == "Reader"
    assert keeper.get("/api/v1/upstreams").status_code == 200
    me = keeper.get("/api/v1/auth/me").json()["user"]
    assert me["permissions"] == ["cache:read", "upstream:read"]

    listed = {item["id"]: item for item in client.get("/api/v1/roles").json()["items"]}
    assert listed[role["id"]]["user_count"] == 1
    assert client.get(f"/api/v1/roles/{role['id']}").json()["name_fa"] == "Reader"

    with client.app.state.database.session() as db:
        actions = set(db.scalars(select(AuditEvent.action)))
    assert {"role.create", "role.update"} <= actions


def test_role_in_use_cannot_be_deleted(client: TestClient) -> None:
    csrf = owner_csrf(client)
    role = create_role(client, csrf, "Watcher", ["system:read"]).json()
    user_id = make_user(client, csrf, "watcher", role["id"])
    blocked = client.delete(f"/api/v1/roles/{role['id']}", headers={"X-CSRF-Token": csrf})
    assert blocked.status_code == 409
    error = blocked.json()["error"]
    assert error["code"] == "role_in_use"
    assert [item["username"] for item in error["users"]] == ["watcher"]
    assert error["fields"][0]["field"] == "role"

    moved = client.patch(f"/api/v1/users/{user_id}", headers={"X-CSRF-Token": csrf},
                         json={"role": "viewer"})
    assert moved.status_code == 200
    deleted = client.delete(f"/api/v1/roles/{role['id']}", headers={"X-CSRF-Token": csrf})
    assert deleted.status_code == 200
    assert client.get(f"/api/v1/roles/{role['id']}").status_code == 404
    again = client.delete(f"/api/v1/roles/{role['id']}", headers={"X-CSRF-Token": csrf})
    assert again.status_code == 404


def test_builtin_roles_are_immutable(client: TestClient) -> None:
    csrf = owner_csrf(client)
    for verb in ("patch", "delete"):
        kwargs = {"json": {"name": "Boss"}} if verb == "patch" else {}
        response = getattr(client, verb)("/api/v1/roles/admin",
                                         headers={"X-CSRF-Token": csrf}, **kwargs)
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "builtin_role_immutable"


def test_custom_role_validation(client: TestClient) -> None:
    csrf = owner_csrf(client)
    wildcard = create_role(client, csrf, "Everything", ["*"])
    assert wildcard.status_code == 422
    assert wildcard.json()["error"]["fields"] == [
        {"field": "permissions", "reason_code": "wildcard_forbidden"}
    ]
    unknown = create_role(client, csrf, "Odd", ["cache:read", "made:up"]).json()["error"]
    assert unknown["fields"][0]["params"] == {"permission": "made:up"}
    dependency = create_role(client, csrf, "Writer", ["cache:write", "s3:admin"])
    assert dependency.status_code == 422
    error = dependency.json()["error"]
    assert error["code"] == "permission_dependency_missing"
    assert {(item["params"]["permission"], tuple(item["params"]["requires"]))
            for item in error["fields"]} == {("cache:write", ("cache:read",)),
                                             ("s3:admin", ("s3:read",))}
    reserved = create_role(client, csrf, "admin", ["system:read"])
    assert reserved.json()["error"]["fields"][0]["reason_code"] == "reserved"
    assert create_role(client, csrf, "Same", ["system:read"]).status_code == 201
    duplicate = create_role(client, csrf, "same", ["system:read"])
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["fields"] == [{"field": "name", "reason_code": "duplicate"}]
    empty = create_role(client, csrf, "Nothing", [])
    assert empty.json()["error"]["fields"][0]["reason_code"] == "required"


def test_only_owner_manages_custom_roles(client: TestClient) -> None:
    csrf = owner_csrf(client)
    make_user(client, csrf, "boss", "admin")
    admin, login = sign_in(client.app, "boss")
    headers = {"X-CSRF-Token": login["csrf_token"]}
    assert admin.get("/api/v1/roles").status_code == 200
    assert admin.post("/api/v1/roles", headers=headers,
                      json={"name": "Mine", "permissions": ["system:read"]}).status_code == 403
    role = create_role(client, csrf, "Shared", ["system:read"]).json()
    assert admin.patch(f"/api/v1/roles/{role['id']}", headers=headers,
                       json={"name": "Hijack"}).status_code == 403
    assert admin.delete(f"/api/v1/roles/{role['id']}", headers=headers).status_code == 403


def test_escalation_prevention(tmp_path: Path) -> None:
    store = AuthStore(tmp_path)
    narrow = frozenset({"system:read", "user:read", "user:write"})
    with pytest.raises(PermissionEscalationError) as raised:
        store.validate_role_permissions(["cache:read", "cache:write"], narrow)
    assert raised.value.permissions == ["cache:read", "cache:write"]
    assert store.validate_role_permissions(["system:read"], narrow) == ["system:read"]

    owner_id = store.create_user("the-owner", PASSWORD, "owner", None)
    owner = auth_module.Principal(owner_id, "the-owner", "owner", frozenset({"*"}), None, "")
    role = store.create_custom_role("Ops", "", ["agent:read", "docker:operate"], owner)
    actor_id = store.create_user("actor", PASSWORD, "viewer", None)
    actor = auth_module.Principal(actor_id, "actor", "custom:x", narrow, None, "")
    # Someone who lacks the role's permissions can neither assign nor edit it.
    with pytest.raises(PermissionEscalationError):
        store.create_user("target", PASSWORD, str(role["id"]), actor_id,
                          actor_permissions=narrow)
    with pytest.raises(PermissionEscalationError):
        store.update_custom_role(str(role["id"]), actor, name="Renamed")
    victim = store.create_user("victim", PASSWORD, str(role["id"]), None)
    with pytest.raises(PermissionEscalationError):
        store.update_user(victim, None, False, actor_id, actor_permissions=narrow)
    with pytest.raises(FieldError) as unknown:
        store.create_user("ghost", PASSWORD, "custom:nope", None)
    assert unknown.value.fields[0]["reason_code"] == "unknown_role"


def test_admin_cannot_assign_owner_or_escalate_over_http(client: TestClient) -> None:
    csrf = owner_csrf(client)
    make_user(client, csrf, "boss", "admin")
    admin, login = sign_in(client.app, "boss")
    headers = {"X-CSRF-Token": login["csrf_token"]}
    assert admin.post("/api/v1/users", headers=headers,
                      json={"username": "newowner", "password": PASSWORD,
                            "role": "owner"}).status_code == 403
    assert admin.post("/api/v1/users/invite", headers=headers,
                      json={"display_name": "New Owner", "role": "owner"}).status_code == 403
    assert admin.post("/api/v1/users", headers=headers,
                      json={"username": "helper", "password": PASSWORD,
                            "role": "operator"}).status_code == 201


def test_token_scopes_intersect_with_custom_role(client: TestClient) -> None:
    csrf = owner_csrf(client)
    role = create_role(client, csrf, "CI", ["cache:read", "cache:write", "token:read",
                                            "token:write", "system:read"]).json()
    make_user(client, csrf, "ci-user", role["id"])
    ci, login = sign_in(client.app, "ci-user")
    headers = {"X-CSRF-Token": login["csrf_token"]}
    too_wide = ci.post("/api/v1/tokens", headers=headers,
                       json={"name": "wide", "scopes": ["upstream:read"],
                             "expires_in_seconds": 3600})
    assert too_wide.status_code == 409
    assert too_wide.json()["error"]["fields"][0] == {
        "field": "scopes", "reason_code": "exceeds_role",
        "params": {"permissions": ["upstream:read"]},
    }
    unknown = ci.post("/api/v1/tokens", headers=headers,
                      json={"name": "odd", "scopes": ["nope:read"], "expires_in_seconds": 3600})
    assert unknown.json()["error"]["fields"][0]["reason_code"] == "unknown_permission"
    created = ci.post("/api/v1/tokens", headers=headers,
                      json={"name": "prefetch", "scopes": ["cache:read", "cache:write"],
                            "expires_in_seconds": 3600})
    assert created.status_code == 201, created.text
    bearer = TestClient(client.app)
    auth = {"Authorization": f"Bearer {created.json()['token']}"}
    assert bearer.get("/api/v1/packages", headers=auth).status_code == 200

    # Narrow the role: the token loses cache:write but keeps cache:read.
    client.patch(f"/api/v1/roles/{role['id']}", headers={"X-CSRF-Token": csrf},
                 json={"permissions": ["cache:read", "system:read", "token:read",
                                       "token:write"]})
    me = bearer.get("/api/v1/auth/me", headers=auth).json()["user"]
    assert me["permissions"] == ["cache:read"]
    # Remove every scope the token had: it no longer authenticates.
    client.patch(f"/api/v1/roles/{role['id']}", headers={"X-CSRF-Token": csrf},
                 json={"permissions": ["system:read"]})
    assert bearer.get("/api/v1/auth/me", headers=auth).status_code == 401


# ----------------------------------------------------------------------------- invites


def invite(client: TestClient, csrf: str, **body):
    payload = {"display_name": "Maryam Ahmadi", "email": "maryam@example.test",
               "role": "operator", **body}
    return client.post("/api/v1/users/invite", headers={"X-CSRF-Token": csrf}, json=payload)


def test_invite_one_time_password_and_forced_change(client: TestClient) -> None:
    csrf = owner_csrf(client)
    response = invite(client, csrf)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["must_change_password"] is True
    assert body["user"]["username"] == "maryam"
    otp = body["one_time_password"]
    AuthStore.validate_password(otp)  # always satisfies the policy
    # The password is never shown again.
    listed = {item["username"]: item for item in client.get("/api/v1/users").json()["items"]}
    assert listed["maryam"]["must_change_password"] is True
    assert listed["maryam"]["invite_pending"] is True
    assert otp not in client.get("/api/v1/users").text

    maryam, login = sign_in(client.app, "maryam", otp)
    assert login["must_change_password"] is True
    assert login["user"]["must_change_password"] is True
    blocked = maryam.get("/api/v1/upstreams")
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "password_change_required"
    assert maryam.get("/api/v1/auth/me").status_code == 200
    assert maryam.get("/api/v1/home").json()["must_change_password"] is True

    headers = {"X-CSRF-Token": login["csrf_token"]}
    wrong = maryam.post("/api/v1/auth/change-password", headers=headers,
                        json={"current_password": "not-it-123", "new_password": PASSWORD})
    assert wrong.status_code == 422
    assert wrong.json()["error"]["fields"] == [
        {"field": "current_password", "reason_code": "incorrect"}
    ]
    weak = maryam.post("/api/v1/auth/change-password", headers=headers,
                       json={"current_password": otp, "new_password": "abc"})
    assert weak.json()["error"]["code"] == "weak_password"
    assert weak.json()["error"]["fields"][0]["field"] == "new_password"
    assert weak.json()["error"]["fields"][0]["reason_code"] == "too_short"
    same = maryam.post("/api/v1/auth/change-password", headers=headers,
                       json={"current_password": otp, "new_password": otp})
    assert same.json()["error"]["fields"][0]["reason_code"] == "same_as_current"

    changed = maryam.post("/api/v1/auth/change-password", headers=headers,
                          json={"current_password": otp, "new_password": PASSWORD})
    assert changed.status_code == 200, changed.text
    assert changed.json()["user"]["must_change_password"] is False
    assert maryam.get("/api/v1/upstreams").status_code == 200
    # The old one-time password is dead; the link was revoked too.
    assert TestClient(client.app).post(
        "/api/v1/auth/login", json={"username": "maryam", "password": otp}
    ).status_code == 401
    token = body["invite"]["token"]
    assert TestClient(client.app).get(f"/api/v1/auth/invite/{token}").status_code == 410

    with client.app.state.database.session() as db:
        actions = set(db.scalars(select(AuditEvent.action)))
    assert {"user.invite", "auth.password.change"} <= actions


def test_invite_link_accept_is_single_use(client: TestClient) -> None:
    csrf = owner_csrf(client)
    body = invite(client, csrf, role="viewer").json()
    token = body["invite"]["token"]
    assert body["invite"]["path"] == f"/#/invite/{token}"
    public = TestClient(client.app)
    details = public.get(f"/api/v1/auth/invite/{token}")
    assert details.status_code == 200
    assert details.json()["email"] == "maryam@example.test"
    assert details.json()["display_name"] == "Maryam Ahmadi"
    assert "password_policy" in details.json()

    mismatch = public.post(f"/api/v1/auth/invite/{token}/accept",
                           json={"password": PASSWORD, "password_confirmation": "other-123"})
    assert mismatch.json()["error"]["fields"][0]["field"] == "password_confirmation"
    weak = public.post(f"/api/v1/auth/invite/{token}/accept", json={"password": "short"})
    assert weak.status_code == 422
    assert weak.json()["error"]["fields"][0]["field"] == "password"

    accepted = public.post(f"/api/v1/auth/invite/{token}/accept",
                           json={"password": PASSWORD, "password_confirmation": PASSWORD})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["user"]["username"] == "maryam"
    assert accepted.json()["must_change_password"] is False
    assert public.get("/api/v1/upstreams").status_code == 200  # signed in by the cookie

    reused = TestClient(client.app).post(f"/api/v1/auth/invite/{token}/accept",
                                         json={"password": "another-pass-456"})
    assert reused.status_code == 410
    assert reused.json()["error"]["code"] == "invite_used"
    assert TestClient(client.app).post(
        "/api/v1/auth/login", json={"username": "maryam", "password": body["one_time_password"]}
    ).status_code == 401
    unknown = TestClient(client.app).get("/api/v1/auth/invite/not-a-real-token")
    assert unknown.status_code == 404
    assert unknown.json()["error"]["code"] == "invite_invalid"
    with client.app.state.database.session() as db:
        stored = db.scalars(select(UserInvite.token_hash)).all()
        actions = set(db.scalars(select(AuditEvent.action)))
    assert token not in stored  # only the hash is kept
    assert "auth.invite.accept" in actions


def test_invite_link_expires(client: TestClient) -> None:
    csrf = owner_csrf(client)
    token = invite(client, csrf).json()["invite"]["token"]
    with client.app.state.database.session() as db, db.begin():
        row = db.scalars(select(UserInvite)).one()
        assert 7 * 86400 - 60 <= row.expires_at - row.created_at <= 7 * 86400
        row.expires_at = int(time.time()) - 1
    expired = TestClient(client.app).get(f"/api/v1/auth/invite/{token}")
    assert expired.status_code == 410
    assert expired.json()["error"]["code"] == "invite_expired"
    assert TestClient(client.app).post(f"/api/v1/auth/invite/{token}/accept",
                                       json={"password": PASSWORD}).status_code == 410


def test_invite_without_link_and_field_errors(client: TestClient) -> None:
    csrf = owner_csrf(client)
    plain = invite(client, csrf, create_link=False, email=None, display_name="Ali Rezaei")
    assert plain.status_code == 201
    assert plain.json()["invite"] is None
    assert plain.json()["user"]["username"] == "ali-rezaei"
    persian = invite(client, csrf, create_link=False, email=None, display_name="مریم")
    assert persian.json()["user"]["username"] == "user"
    bad_email = invite(client, csrf, email="not-an-email")
    assert bad_email.status_code == 422
    assert bad_email.json()["error"]["fields"] == [
        {"field": "email", "reason_code": "invalid_format"}
    ]
    first = invite(client, csrf, email="dup@example.test", username="dup-user")
    assert first.status_code == 201
    duplicate = invite(client, csrf, email="dup@example.test", username="other")
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["fields"][0] == {"field": "email", "reason_code": "duplicate"}
    bad_role = invite(client, csrf, role="custom:missing")
    assert bad_role.json()["error"]["fields"][0] == {"field": "role",
                                                     "reason_code": "unknown_role"}


# ----------------------------------------------------------------------------- field errors


def test_request_validation_error_names_fields(client: TestClient) -> None:
    csrf = owner_csrf(client)
    response = client.post("/api/v1/users", headers={"X-CSRF-Token": csrf},
                           json={"username": "ab", "role": "viewer"})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["message"] == "Request validation failed"
    assert error["request_id"]
    fields = {item["field"]: item for item in error["fields"]}
    assert fields["username"]["reason_code"] == "too_short"
    assert fields["username"]["params"]["min_length"] == 3
    assert fields["password"]["reason_code"] == "required"
    assert error["field"] == error["fields"][0]["field"]


def test_value_errors_name_fields_and_keep_codes(client: TestClient) -> None:
    csrf = owner_csrf(client)
    bad_username = client.post("/api/v1/users", headers={"X-CSRF-Token": csrf},
                               json={"username": "bad name", "password": PASSWORD,
                                     "role": "viewer"})
    assert bad_username.status_code == 409
    error = bad_username.json()["error"]
    assert error["code"] == "invalid_user"  # backwards compatible
    assert error["fields"][0]["field"] == "username"
    assert error["fields"][0]["reason_code"] == "invalid_characters"
    weak = client.post("/api/v1/users", headers={"X-CSRF-Token": csrf},
                       json={"username": "weakling", "password": "abcdefgh", "role": "viewer"})
    assert weak.json()["error"]["fields"][0] == {"field": "password",
                                                 "reason_code": "missing_digit"}
    make_user(client, csrf, "twice", "viewer")
    twice = client.post("/api/v1/users", headers={"X-CSRF-Token": csrf},
                        json={"username": "twice", "password": PASSWORD, "role": "viewer"})
    assert twice.json()["error"]["fields"][0] == {"field": "username",
                                                  "reason_code": "duplicate"}
    owner_id = next(item["id"] for item in client.get("/api/v1/users").json()["items"]
                    if item["role"] == "owner")
    last_owner = client.patch(f"/api/v1/users/{owner_id}", headers={"X-CSRF-Token": csrf},
                              json={"enabled": False})
    assert last_owner.status_code == 409
    assert last_owner.json()["error"]["code"] == "invalid_user_update"
    assert last_owner.json()["error"]["fields"][0] == {"field": "enabled",
                                                       "reason_code": "last_owner"}


def test_setup_errors_name_fields(tmp_path: Path) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        response = client.post("/api/v1/auth/setup", json={
            "display_name": "Owner", "email": "owner@example.test",
            "password": "abc", "password_confirmation": "abc",
        })
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "weak_password"
        assert error["fields"][0]["field"] == "password"
        assert error["fields"][0]["params"]["min_length"] >= 4
        mismatch = client.post("/api/v1/auth/setup", json={
            "display_name": "Owner", "email": "owner@example.test",
            "password": PASSWORD, "password_confirmation": "different-123",
        })
        assert mismatch.json()["error"]["fields"] == [
            {"field": "password_confirmation", "reason_code": "mismatch"}
        ]


# ----------------------------------------------------------------------------- migration


def test_migration_chain_has_single_head_on_fresh_sqlite(tmp_path: Path) -> None:
    script = ScriptDirectory(str(Path(auth_module.__file__).parent / "migrations"))
    assert script.get_heads() == ["20261108_0011"]
    revision = script.get_revision("20261108_0011")
    assert revision is not None and revision.down_revision == "20261108_0010"
    chain = [item.revision for item in script.walk_revisions()]
    assert chain[-1] == "20261107_0001" and len(chain) == 11
    database = Database(tmp_path)
    database.initialize()
    inspector = inspect(database.engine)
    assert {"custom_roles", "user_password_states", "user_invites"} <= set(
        inspector.get_table_names()
    )
    columns = {column["name"] for column in inspector.get_columns("user_invites")}
    assert "token_hash" in columns and "token" not in columns
    with database.engine.connect() as connection:
        version = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
    assert version == "20261108_0011"
    database.dispose()
