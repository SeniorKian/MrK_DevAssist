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


def test_development_default_data_directory_is_workspace_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MRK_ENV", "development")
    monkeypatch.delenv("MRK_DATA_DIR", raising=False)

    assert Settings.from_env().data_dir == tmp_path / ".data"


def test_production_default_data_directory_remains_volume_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MRK_ENV", "production")
    monkeypatch.delenv("MRK_DATA_DIR", raising=False)

    assert Settings.from_env().data_dir == Path("/data")


def test_npm_health_host_must_be_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_NPM_HEALTH_HOST", "192.0.2.10")

    with pytest.raises(ValueError, match="loopback"):
        Settings.from_env()


def test_pypi_health_host_must_be_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_PYPI_HEALTH_HOST", "192.0.2.11")

    with pytest.raises(ValueError, match="loopback"):
        Settings.from_env()
