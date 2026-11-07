from pathlib import Path

from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app

from .helpers import OWNER_EMAIL, OWNER_PASSWORD, login_owner, setup_owner


def test_first_run_setup_creates_only_owner_and_accepts_email(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        status = client.get("/api/v1/auth/setup-status")
        assert status.status_code == 200
        assert status.json()["required"] is True
        created = client.post(
            "/api/v1/auth/setup",
            json={
                "display_name": "Test Owner",
                "email": "Owner@Example.Test",
                "password": "a-strong-owner-password-123",
                "password_confirmation": "a-strong-owner-password-123",
            },
        )
        assert created.status_code == 201
        assert created.json()["user"]["display_name"] == "Test Owner"
        assert created.json()["user"]["email"] == "owner@example.test"
        assert created.json()["user"]["role"] == "owner"
        assert client.get("/api/v1/auth/setup-status").json()["required"] is False

        second_registration = client.post(
            "/api/v1/auth/setup",
            json={
                "display_name": "Second Owner",
                "email": "second@example.test",
                "password": "another-strong-password-123",
                "password_confirmation": "another-strong-password-123",
            },
        )
        assert second_registration.status_code == 409

        policy = client.get("/api/v1/settings/registration")
        assert policy.status_code == 200
        assert policy.json()["enabled"] is False
        enabled = client.patch(
            "/api/v1/settings/registration",
            headers={"X-CSRF-Token": str(created.json()["csrf_token"])},
            json={"enabled": True},
        )
        assert enabled.status_code == 200
        assert enabled.json()["default_role"] == "viewer"

        public_client = TestClient(app)
        registered = public_client.post(
            "/api/v1/auth/register",
            json={
                "display_name": "Public Viewer",
                "email": "viewer@example.test",
                "password": "a-strong-viewer-password-123",
                "password_confirmation": "a-strong-viewer-password-123",
            },
        )
        assert registered.status_code == 201
        assert registered.json()["user"]["role"] == "viewer"

        client.cookies.clear()
        login = client.post(
            "/api/v1/auth/login",
            json={
                "username": "owner@example.test",
                "password": "a-strong-owner-password-123",
            },
        )
        assert login.status_code == 200


def test_first_time_owner_login_session_and_logout(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        assert client.get("/api/v1/system/status").status_code == 401
        assert client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "definitely-wrong"},
        ).status_code == 401

        setup_owner(client)
        client.cookies.clear()
        login = client.post(
            "/api/v1/auth/login",
            json={"username": OWNER_EMAIL, "password": OWNER_PASSWORD},
        )
        payload = login.json()
        csrf = str(payload["csrf_token"])

        assert login.status_code == 200
        assert payload["user"]["role"] == "owner"
        assert "HttpOnly" in login.headers["set-cookie"]
        assert "SameSite=strict" in login.headers["set-cookie"]
        me = client.get("/api/v1/auth/me")
        assert me.status_code == 200
        csrf = str(me.json()["csrf_token"])
        assert client.post("/api/v1/auth/logout").status_code == 403

        logged_out = client.post(
            "/api/v1/auth/logout", headers={"X-CSRF-Token": csrf}
        )
        assert logged_out.status_code == 200
        assert client.get("/api/v1/auth/me").status_code == 401


def test_owner_can_create_viewer_and_rbac_is_enforced(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        owner = login_owner(client)
        csrf = str(owner["csrf_token"])
        created = client.post(
            "/api/v1/users",
            headers={"X-CSRF-Token": csrf},
            json={
                "username": "readonly",
                "password": "a-long-viewer-password-123",
                "role": "viewer",
            },
        )
        assert created.status_code == 201
        users = client.get("/api/v1/users").json()["items"]
        assert any(item["username"] == "readonly" for item in users)

        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
        viewer = client.post(
            "/api/v1/auth/login",
            json={"username": "readonly", "password": "a-long-viewer-password-123"},
        )
        assert viewer.status_code == 200
        viewer_csrf = str(viewer.json()["csrf_token"])
        assert client.get("/api/v1/system/status").status_code == 200
        assert client.get("/api/v1/users").status_code == 403
        assert client.post(
            "/api/v1/users",
            headers={"X-CSRF-Token": viewer_csrf},
            json={
                "username": "blocked",
                "password": "another-long-password-123",
                "role": "viewer",
            },
        ).status_code == 403


def test_session_refresh_rotates_csrf_and_audit_is_recorded(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        login = login_owner(client)
        old_csrf = str(login["csrf_token"])
        refreshed = client.post(
            "/api/v1/auth/refresh", headers={"X-CSRF-Token": old_csrf}
        )
        new_csrf = str(refreshed.json()["csrf_token"])

        assert refreshed.status_code == 200
        assert new_csrf != old_csrf
        assert client.post(
            "/api/v1/auth/logout", headers={"X-CSRF-Token": old_csrf}
        ).status_code == 403
        audit = client.get("/api/v1/audit-events")
        assert audit.status_code == 200
        actions = {item["action"] for item in audit.json()["items"]}
        assert {"auth.setup", "auth.login", "auth.refresh"}.issubset(actions)


def test_user_update_revokes_sessions_and_last_owner_is_protected(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        owner = login_owner(client)
        csrf = str(owner["csrf_token"])
        assert client.patch(
            "/api/v1/users/1",
            headers={"X-CSRF-Token": csrf},
            json={"enabled": False},
        ).status_code == 409

        created = client.post(
            "/api/v1/users",
            headers={"X-CSRF-Token": csrf},
            json={
                "username": "operator1",
                "password": "operator-password-12345",
                "role": "operator",
            },
        )
        user_id = int(created.json()["id"])
        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
        operator = client.post(
            "/api/v1/auth/login",
            json={"username": "operator1", "password": "operator-password-12345"},
        )
        assert operator.status_code == 200

        client.cookies.clear()
        owner = login_owner(client)
        disabled = client.patch(
            f"/api/v1/users/{user_id}",
            headers={"X-CSRF-Token": str(owner["csrf_token"])},
            json={"enabled": False, "role": "viewer"},
        )
        assert disabled.status_code == 200
        client.cookies.clear()
        assert client.post(
            "/api/v1/auth/login",
            json={"username": "operator1", "password": "operator-password-12345"},
        ).status_code == 401


def test_scoped_api_token_is_shown_once_and_revoked_immediately(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        owner = login_owner(client)
        created = client.post(
            "/api/v1/tokens",
            headers={"X-CSRF-Token": str(owner["csrf_token"])},
            json={
                "name": "ci-readonly",
                "scopes": ["system:read", "upstream:read"],
                "expires_in_seconds": 3600,
            },
        )
        assert created.status_code == 201
        token_id = int(created.json()["id"])
        token = str(created.json()["token"])
        assert token.startswith("mrk_")

        listed = client.get("/api/v1/tokens")
        assert listed.status_code == 200
        assert listed.json()["items"][0]["id"] == token_id
        assert "token" not in listed.json()["items"][0]

        token_client = TestClient(app)
        assert token_client.get(
            "/api/v1/system/status", headers={"Authorization": f"Bearer {token}"}
        ).status_code == 200
        assert token_client.get(
            "/api/v1/users", headers={"Authorization": f"Bearer {token}"}
        ).status_code == 403

        revoked = client.delete(
            f"/api/v1/tokens/{token_id}",
            headers={"X-CSRF-Token": str(owner["csrf_token"])},
        )
        assert revoked.status_code == 200
        assert token_client.get(
            "/api/v1/system/status", headers={"Authorization": f"Bearer {token}"}
        ).status_code == 401
