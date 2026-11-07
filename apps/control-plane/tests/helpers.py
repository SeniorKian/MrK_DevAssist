from __future__ import annotations

from fastapi.testclient import TestClient

OWNER_EMAIL = "owner@example.test"
OWNER_PASSWORD = "first-time-owner-password-123"  # noqa: S105 - test-only fixture


def setup_owner(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/api/v1/auth/setup",
        json={
            "display_name": "Test Owner",
            "email": OWNER_EMAIL,
            "password": OWNER_PASSWORD,
            "password_confirmation": OWNER_PASSWORD,
        },
    )
    assert response.status_code == 201
    return response.json()


def login_owner(client: TestClient) -> dict[str, object]:
    status = client.get("/api/v1/auth/setup-status")
    assert status.status_code == 200
    if status.json()["required"]:
        return setup_owner(client)
    response = client.post(
        "/api/v1/auth/login",
        json={"username": OWNER_EMAIL, "password": OWNER_PASSWORD},
    )
    assert response.status_code == 200
    return response.json()
