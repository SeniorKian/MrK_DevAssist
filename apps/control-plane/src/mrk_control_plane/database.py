from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterator
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, inspect
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

LOGGER = logging.getLogger(__name__)


def default_database_url(data_dir: Path) -> str:
    database = (data_dir / "control-plane" / "control-plane.sqlite3").resolve()
    database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return f"sqlite:///{database.as_posix()}"


class Database:
    """Application database boundary shared by repositories and future modules.

    SQLite remains available for source-level tests. The panel stack supplies
    PostgreSQL (the mrk-db container, or the host's own PostgreSQL in a native
    install); any managed PostgreSQL works the same way.
    """

    def __init__(self, data_dir: Path, url: str | None = None) -> None:
        self.url = url or default_database_url(data_dir)
        parsed_url = make_url(self.url)
        self.is_pglite = (
            parsed_url.get_backend_name() == "postgresql"
            and parsed_url.host in {"127.0.0.1", "localhost", "::1"}
            and parsed_url.port == 5433
        )
        if self.url.startswith("sqlite"):
            self.engine = create_engine(
                self.url,
                connect_args={"check_same_thread": False, "timeout": 5},
                pool_pre_ping=True,
            )
            event.listen(self.engine, "connect", self._configure_sqlite)
        elif self.url.startswith(("postgresql", "postgres")):
            self.engine = create_engine(
                self.url,
                # PGlite serializes work through one connection. A real
                # PostgreSQL deployment gets a conventional bounded pool.
                pool_size=1 if self.is_pglite else 10,
                max_overflow=0 if self.is_pglite else 20,
                pool_pre_ping=True,
                pool_recycle=1800,
            )
        else:
            raise ValueError("MRK_DATABASE_URL must use sqlite or postgresql")
        self.session_factory = sessionmaker(
            bind=self.engine, expire_on_commit=False, autoflush=False
        )

    @staticmethod
    def _configure_sqlite(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
        finally:
            cursor.close()

    def wait_until_reachable(self, timeout_seconds: float | None = None) -> None:
        """Wait for the database to accept connections before running migrations.

        Supervisor only orders process start; it does not wait for PGlite to be
        ready, and a slow first boot used to exhaust the control plane's retries.
        """
        if timeout_seconds is None:
            timeout_seconds = float(os.getenv("MRK_DATABASE_WAIT_SECONDS", "120"))
        deadline = time.monotonic() + timeout_seconds
        delay = 0.25
        while True:
            try:
                with self.engine.connect() as connection:
                    connection.exec_driver_sql("SELECT 1")
                return
            except OperationalError:
                if time.monotonic() >= deadline:
                    raise
                LOGGER.info("waiting for the database to accept connections")
                time.sleep(delay)
                delay = min(delay * 2, 5.0)

    def initialize(self) -> None:
        if not self.url.startswith("sqlite"):
            self.wait_until_reachable()
        migration_root = Path(__file__).with_name("migrations")
        config = Config()
        config.set_main_option("script_location", migration_root.as_posix())
        config.set_main_option("sqlalchemy.url", self.url.replace("%", "%%"))
        with self.engine.begin() as connection:
            config.attributes["connection"] = connection
            tables = set(inspect(connection).get_table_names())
            if not tables:
                command.upgrade(config, "head")
            elif "alembic_version" in tables:
                command.upgrade(config, "head")
            else:
                # Pre-ORM preview builds created compatible tables directly.
                # Fill any missing tables, then establish the migration baseline.
                Base.metadata.create_all(connection)
                command.stamp(config, "head")

    def session(self) -> Session:
        return self.session_factory()

    def sessions(self) -> Iterator[Session]:
        with self.session_factory() as session:
            yield session

    def maintenance(self) -> None:
        """Reclaim dead rows and refresh planner statistics."""
        with self.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            if self.is_embedded_sqlite:
                connection.exec_driver_sql("PRAGMA optimize")
            else:
                connection.exec_driver_sql("VACUUM (ANALYZE)")

    def dispose(self) -> None:
        self.engine.dispose()

    @property
    def dialect(self) -> str:
        return self.engine.dialect.name

    @property
    def is_embedded_sqlite(self) -> bool:
        return self.dialect == "sqlite"

    @property
    def mode(self) -> str:
        if self.is_pglite:
            return "pglite"
        if self.is_embedded_sqlite:
            return "sqlite"
        return "external-postgresql"


def database_health(engine: Engine) -> bool:
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        return True
    except Exception:  # pragma: no cover - health boundary must never crash status
        LOGGER.exception("database health check failed")
        return False
