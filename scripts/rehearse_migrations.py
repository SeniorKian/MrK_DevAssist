from __future__ import annotations

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


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="mrk-migration-rehearsal-") as temporary:
        data_dir = Path(temporary)
        database = Database(data_dir)
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
