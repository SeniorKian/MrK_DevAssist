from __future__ import annotations

import argparse
import json
import secrets
import tempfile
from pathlib import Path

from alembic import command
from alembic.config import Config
from mrk_control_plane.auth import AuthStore
from mrk_control_plane.database import Database
from sqlalchemy import inspect, text


def _config(database: Database) -> Config:
    migration_root = (
        Path(__file__).resolve().parents[1]
        / "apps"
        / "control-plane"
        / "src"
        / "mrk_control_plane"
        / "migrations"
    )
    config = Config()
    config.set_main_option("script_location", migration_root.as_posix())
    config.set_main_option("sqlalchemy.url", database.url.replace("%", "%%"))
    return config


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Rehearse Alembic downgrade/upgrade")
    parser.add_argument(
        "--database-url",
        default=None,
        help=(
            "SQLAlchemy URL of an empty database to rehearse against "
            "(e.g. PostgreSQL on 127.0.0.1:5432); defaults to a temporary SQLite file"
        ),
    )
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="mrk-migration-rehearsal-") as temporary:
        data_dir = Path(temporary)
        database = Database(data_dir, args.database_url)
        if not database.is_embedded_sqlite:
            database.wait_until_reachable()
        existing = inspect(database.engine).get_table_names()
        if existing:
            database.dispose()
            # The rehearsal downgrades the schema; never run it against real data.
            raise SystemExit(
                f"refusing to rehearse migrations on a non-empty database ({len(existing)} tables)"
            )
        database.initialize()
        auth = AuthStore(data_dir, database=database)
        password = f"migration-rehearsal-{secrets.token_urlsafe(18)}"
        auth.create_user("rehearsal-owner", password, "owner", None)
        config = _config(database)
        with database.engine.begin() as connection:
            config.attributes["connection"] = connection
            command.downgrade(config, "20261107_0001")
            downgraded_tables = set(inspect(connection).get_table_names())
            if "system_settings" in downgraded_tables or "users" not in downgraded_tables:
                raise RuntimeError("downgrade rehearsal produced an unexpected schema")
            command.upgrade(config, "head")
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
        if auth.authenticate("rehearsal-owner", password, "127.0.0.1", "rehearsal") is None:
            raise RuntimeError("user data did not survive migration rehearsal")
        print(
            json.dumps(
                {
                    "dialect": database.dialect,
                    "downgrade": "20261107_0001",
                    "upgrade": revision,
                    "data_preserved": True,
                },
                sort_keys=True,
            )
        )
        database.dispose()


if __name__ == "__main__":
    main()
