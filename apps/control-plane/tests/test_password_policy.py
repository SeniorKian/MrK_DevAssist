from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.auth import AuthStore, password_policy
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app


def test_default_policy_is_six_chars_with_letters_and_digits() -> None:
    AuthStore.validate_password("abc123")
    for weak in ("ab12", "abcdef", "123456"):
        with pytest.raises(ValueError):
            AuthStore.validate_password(weak)
    assert password_policy() == {"min_length": 6, "require_letters": True, "require_digits": True}


def test_policy_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_PASSWORD_MIN_LENGTH", "10")
    monkeypatch.setenv("MRK_PASSWORD_REQUIRE_DIGITS", "false")
    AuthStore.validate_password("onlyletters")
    with pytest.raises(ValueError):
        AuthStore.validate_password("short1")


def test_setup_accepts_simple_password_and_reports_policy(tmp_path: Path) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        status = client.get("/api/v1/auth/setup-status").json()
        assert status["password_policy"]["min_length"] == 6
        response = client.post(
            "/api/v1/auth/setup",
            json={
                "display_name": "Owner",
                "email": "owner@example.test",
                "password": "pass12",
                "password_confirmation": "pass12",
            },
        )
        assert response.status_code == 201
