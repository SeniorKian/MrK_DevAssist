# ruff: noqa: S105 - throwaway test passwords
"""The panel's PostgreSQL password comes from a generated file (compose mrk-db-init)."""

from __future__ import annotations

from pathlib import Path

import pytest
from mrk_control_plane import db_secret
from mrk_control_plane.config import database_url_with_password

URL = "postgresql+psycopg://devassist@mrk-db:5432/devassist?sslmode=disable"


def test_password_file_is_put_into_the_url(tmp_path: Path) -> None:
    secret = tmp_path / "password"
    secret.write_text("s3cr/t@pass word\n", encoding="utf-8")
    url = database_url_with_password(URL, str(secret))
    assert url is not None and url.startswith("postgresql+psycopg://devassist:")
    assert "@mrk-db:5432/devassist?sslmode=disable" in url
    from sqlalchemy.engine import make_url

    assert make_url(url).password == "s3cr/t@pass word"  # URL-quoted, round-trips


def test_url_with_its_own_password_or_no_file_is_unchanged(tmp_path: Path) -> None:
    with_password = "postgresql+psycopg://u:p@db:5432/x"
    assert database_url_with_password(with_password, str(tmp_path / "missing")) == with_password
    assert database_url_with_password(URL, None) == URL
    assert database_url_with_password(None, str(tmp_path / "x")) is None


def test_missing_or_empty_password_file_fails_clearly(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot be read"):
        database_url_with_password(URL, str(tmp_path / "missing"))
    empty = tmp_path / "empty"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        database_url_with_password(URL, str(empty))


def test_generator_creates_once_and_never_rotates(tmp_path: Path) -> None:
    path = tmp_path / "run" / "password"
    assert db_secret.ensure(path) is True
    first = path.read_text(encoding="utf-8")
    assert len(first.strip()) >= 40
    assert db_secret.ensure(path) is False
    assert path.read_text(encoding="utf-8") == first


def test_generator_refuses_an_empty_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "password"
    path.write_text("", encoding="utf-8")
    with pytest.raises(SystemExit):
        db_secret.ensure(path)
