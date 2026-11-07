from pathlib import Path

import pytest
from mrk_control_plane.config import Settings


def test_production_rejects_wildcard_trusted_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_ENV", "production")
    monkeypatch.setenv("MRK_TRUSTED_HOSTS", "*")

    with pytest.raises(ValueError, match="wildcard trusted hosts"):
        Settings.from_env()


def test_test_settings_use_requested_data_directory(tmp_path: Path) -> None:
    settings = Settings.for_test(tmp_path)

    assert settings.data_dir == tmp_path
    assert settings.environment == "test"


def test_npm_health_host_must_be_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_NPM_HEALTH_HOST", "192.0.2.10")

    with pytest.raises(ValueError, match="loopback"):
        Settings.from_env()


def test_pypi_health_host_must_be_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_PYPI_HEALTH_HOST", "192.0.2.11")

    with pytest.raises(ValueError, match="loopback"):
        Settings.from_env()
