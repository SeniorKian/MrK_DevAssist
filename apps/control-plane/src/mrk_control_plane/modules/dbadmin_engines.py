"""Driver adapters for ``dbadmin`` (PostgreSQL, MySQL/MariaDB, MongoDB, Redis).

Every method is synchronous and runs in a worker thread; nothing here touches
the MRK control-plane database. Each call opens one connection to the target
and closes it again (no pooling: it is an interactive admin tool).

Read mode is enforced in the database where possible (PostgreSQL ``SET
TRANSACTION READ ONLY`` + ``statement_timeout``; MySQL ``START TRANSACTION
READ ONLY`` + ``max_execution_time``/``max_statement_time``) and by
allowlists otherwise (MongoDB find/aggregate/count/distinct without
``$out``/``$merge``; Redis read commands).
"""

from __future__ import annotations

import contextlib
import json
import math
import re
import ssl
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from ..logging_config import redact_text
from . import dbadmin_policy as policy
from . import dbadmin_sql as sqltext

SYSTEM_MYSQL_SCHEMAS = ("information_schema", "mysql", "performance_schema", "sys")
SYSTEM_MONGO_DATABASES = ("admin", "config", "local")
MAX_TABLES = 10000
MAX_NAMESPACES = 200
EXPORT_BATCH = 500


class EngineError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(slots=True)
class ConnSpec:
    id: str
    name: str
    engine: str
    host: str
    port: int
    database: str | None = None
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    tls_mode: str = "disable"
    options: dict[str, str] = field(default_factory=dict)
    address: str | None = None
    connect_timeout: int = 5
    statement_timeout_ms: int = 15000

    @property
    def target(self) -> str:
        """Host to hand the driver: the checked address, or the name when TLS verifies it."""
        if self.tls_mode == "verify" or self.address is None:
            return self.host
        return self.address


@dataclass(slots=True)
class Limits:
    max_rows: int = 1000
    max_cell_bytes: int = 65536
    max_response_bytes: int = 5 * 1024 * 1024

    def builder(self, max_rows: int | None = None) -> policy.ResultBuilder:
        return policy.ResultBuilder(
            max_rows=min(max_rows or self.max_rows, self.max_rows),
            max_cell_bytes=self.max_cell_bytes,
            max_response_bytes=self.max_response_bytes,
        )


@dataclass(slots=True)
class QueryRequest:
    text: str | None = None
    mongo: policy.MongoRequest | None = None
    redis: tuple[str, list[str]] | None = None
    write: bool = False
    dry_run: bool = False
    database: str | None = None


def safe_message(exc: BaseException, spec: ConnSpec | None = None) -> str:
    text = str(exc).strip() or type(exc).__name__
    if spec is not None and spec.password:
        text = text.replace(spec.password, "[REDACTED]")
    return redact_text(text)[:1000]


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 1)


def _tls_context(mode: str) -> ssl.SSLContext | None:
    if mode == "disable":
        return None
    context = ssl.create_default_context()
    if mode == "require":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


# =========================================================================================
# PostgreSQL
# =========================================================================================


class PostgresAdapter:
    READ_EXPORT_KEYWORDS = frozenset({"SELECT", "WITH", "VALUES", "TABLE"})

    def __init__(self, spec: ConnSpec, limits: Limits) -> None:
        self.spec = spec
        self.limits = limits

    # -- plumbing --------------------------------------------------------------------
    def connect(self, *, autocommit: bool = False, timeout_ms: int | None = None) -> Any:
        import psycopg

        spec = self.spec
        timeout = timeout_ms or spec.statement_timeout_ms
        kwargs: dict[str, Any] = {
            "host": spec.host,
            "port": spec.port,
            "dbname": spec.database or "postgres",
            "user": spec.username or "postgres",
            "connect_timeout": max(int(spec.connect_timeout), 1),
            "application_name": spec.options.get("application_name", "mrk-dbadmin"),
            "sslmode": {"disable": "disable", "require": "require", "verify": "verify-full"}[
                spec.tls_mode
            ],
            "gssencmode": "disable",
            "options": f"-c statement_timeout={timeout} "
            f"-c idle_in_transaction_session_timeout={max(timeout * 2, 60000)}",
            "tcp_user_timeout": timeout + 10000,
            "keepalives": 1,
            "keepalives_idle": 30,
            "autocommit": autocommit,
        }
        if spec.address is not None:
            kwargs["hostaddr"] = spec.address
        if spec.password:
            kwargs["password"] = spec.password
        if spec.tls_mode == "verify":
            kwargs["sslrootcert"] = "system"
        try:
            return psycopg.connect(**kwargs)
        except psycopg.OperationalError as exc:
            raise self._connect_error(exc) from None

    def _connect_error(self, exc: Exception) -> EngineError:
        text = str(exc).lower()
        if "password authentication failed" in text or "authentication failed" in text or (
            "no password supplied" in text
        ) or "role" in text and "does not exist" in text:
            return EngineError("db_auth_failed", safe_message(exc, self.spec), 502)
        if "timeout" in text or "timed out" in text:
            return EngineError("db_timeout", "the database did not answer in time", 504)
        return EngineError("db_unreachable", safe_message(exc, self.spec), 502)

    def _query_error(self, exc: Exception) -> EngineError:
        import psycopg

        if isinstance(exc, EngineError):
            return exc
        state = getattr(exc, "sqlstate", None)
        if state == "57014":
            return EngineError("db_timeout", "the statement timed out", 504)
        if state == "25006":
            return EngineError("read_only_violation", safe_message(exc, self.spec))
        if isinstance(exc, psycopg.OperationalError) and state is None:
            return EngineError("db_unreachable", safe_message(exc, self.spec), 502)
        return EngineError("db_query_failed", safe_message(exc, self.spec))

    @staticmethod
    def _begin_read(cursor: Any, timeout_ms: int) -> None:
        cursor.execute("SET TRANSACTION READ ONLY")
        cursor.execute("SELECT set_config('statement_timeout', %s, true)", (str(timeout_ms),))

    @staticmethod
    def _columns(cursor: Any) -> list[dict[str, Any]]:
        columns = []
        for item in cursor.description or []:
            type_name = None
            with contextlib.suppress(Exception):
                info = cursor.connection.adapters.types.get(item.type_code)
                type_name = info.name if info is not None else None
            columns.append({"name": item.name, "type": type_name})
        return columns

    def _collect(self, cursor: Any, builder: policy.ResultBuilder) -> None:
        while True:
            batch = cursor.fetchmany(200)
            if not batch:
                return
            for row in batch:
                if not builder.add(row):
                    return

    # -- operations ----------------------------------------------------------------
    def test(self) -> dict[str, Any]:
        started = time.perf_counter()
        with contextlib.closing(self.connect()) as conn:
            try:
                with conn.cursor() as cur:
                    self._begin_read(cur, self.spec.statement_timeout_ms)
                    cur.execute(
                        "SELECT current_setting('server_version'), current_user, "
                        "current_database(), pg_is_in_recovery()"
                    )
                    version, user, database, recovery = cur.fetchone()
                conn.rollback()
            except Exception as exc:
                raise self._query_error(exc) from None
        return {
            "ok": True, "latency_ms": _ms(started), "server_version": str(version),
            "user": user, "database": database, "replica": bool(recovery),
        }

    def schema(self) -> dict[str, Any]:
        with contextlib.closing(self.connect()) as conn:
            try:
                with conn.cursor() as cur:
                    self._begin_read(cur, self.spec.statement_timeout_ms)
                    cur.execute(
                        "SELECT nspname FROM pg_namespace WHERE nspname NOT IN "
                        "('pg_catalog', 'information_schema') AND nspname !~ '^pg_(toast|temp)' "
                        "ORDER BY nspname LIMIT %s", (MAX_NAMESPACES,),
                    )
                    namespaces = {row[0]: [] for row in cur.fetchall()}
                    cur.execute(
                        "SELECT n.nspname, c.relname, c.relkind, "
                        "CASE WHEN c.reltuples < 0 THEN NULL ELSE c.reltuples::bigint END, "
                        "pg_total_relation_size(c.oid) "
                        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') "
                        "AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
                        "AND n.nspname !~ '^pg_(toast|temp)' ORDER BY 1, 2 LIMIT %s",
                        (MAX_TABLES + 1,),
                    )
                    rows = cur.fetchall()
                    kinds = {"r": "table", "p": "table", "v": "view", "m": "materialized_view",
                             "f": "foreign_table"}
                    for schema, name, kind, estimate, size in rows[:MAX_TABLES]:
                        namespaces.setdefault(schema, []).append(
                            {"name": name, "type": kinds.get(kind, kind),
                             "rows_estimate": estimate, "size_bytes": size}
                        )
                    cur.execute(
                        "SELECT rolname, rolsuper, rolcanlogin FROM pg_roles "
                        "WHERE rolname !~ '^pg_' ORDER BY rolname LIMIT 500"
                    )
                    users = [{"name": r[0], "superuser": r[1], "can_login": r[2]}
                             for r in cur.fetchall()]
                    cur.execute("SELECT current_database()")
                    database = cur.fetchone()[0]
                conn.rollback()
            except Exception as exc:
                raise self._query_error(exc) from None
        return {
            "engine": self.spec.engine, "database": database, "namespace_kind": "schema",
            "namespaces": [{"name": key, "tables": value} for key, value in namespaces.items()],
            "users": users, "truncated": len(rows) > MAX_TABLES,
        }

    def _describe(self, cur: Any, schema: str, name: str) -> dict[str, Any]:
        cur.execute(
            "SELECT c.oid, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = %s AND c.relname = %s AND c.relkind IN ('r','p','v','m','f')",
            (schema, name),
        )
        found = cur.fetchone()
        if found is None:
            raise EngineError("table_not_found", "table not found", 404)
        oid = found[0]
        cur.execute(
            "SELECT a.attname, format_type(a.atttypid, a.atttypmod), NOT a.attnotnull, "
            "pg_get_expr(d.adbin, d.adrelid) FROM pg_attribute a LEFT JOIN pg_attrdef d "
            "ON d.adrelid = a.attrelid AND d.adnum = a.attnum "
            "WHERE a.attrelid = %s AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum",
            (oid,),
        )
        columns = [{"name": r[0], "type": r[1], "nullable": r[2], "default": r[3]}
                   for r in cur.fetchall()]
        cur.execute(
            "SELECT i.relname, pg_get_indexdef(ix.indexrelid), ix.indisunique, ix.indisprimary "
            "FROM pg_index ix JOIN pg_class i ON i.oid = ix.indexrelid "
            "WHERE ix.indrelid = %s ORDER BY i.relname", (oid,),
        )
        indexes = [{"name": r[0], "definition": r[1], "unique": r[2], "primary": r[3]}
                   for r in cur.fetchall()]
        cur.execute(
            "SELECT a.attname FROM pg_index ix JOIN pg_attribute a ON a.attrelid = ix.indrelid "
            "AND a.attnum = ANY(ix.indkey) WHERE ix.indrelid = %s AND ix.indisprimary "
            "ORDER BY array_position(ix.indkey, a.attnum)", (oid,),
        )
        primary_key = [r[0] for r in cur.fetchall()]
        cur.execute(
            "SELECT CASE WHEN reltuples < 0 THEN NULL ELSE reltuples::bigint END, "
            "pg_total_relation_size(oid) FROM pg_class WHERE oid = %s", (oid,),
        )
        estimate, size = cur.fetchone()
        return {"columns": columns, "indexes": indexes, "primary_key": primary_key,
                "rows_estimate": estimate, "size_bytes": size}

    def _data_query(self, schema: str, name: str, filters: list[policy.Filter],
                    sort: list[tuple[str, bool]]) -> tuple[Any, list[Any]]:
        from psycopg import sql

        where: list[Any] = []
        params: list[Any] = []
        operators = {"eq": "=", "ne": "<>", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
        for item in filters:
            column = sql.Identifier(item.column)
            if item.op in operators:
                where.append(sql.SQL("{} " + operators[item.op] + " %s").format(column))
                params.append(item.value)
            elif item.op in {"like", "ilike"}:
                keyword = "LIKE" if item.op == "like" else "ILIKE"
                where.append(sql.SQL("{}::text " + keyword + " %s").format(column))
                params.append(item.value)
            elif item.op == "is_null":
                where.append(sql.SQL("{} IS NULL").format(column))
            elif item.op == "not_null":
                where.append(sql.SQL("{} IS NOT NULL").format(column))
            elif item.op == "in":
                where.append(sql.SQL("{}::text = ANY(%s)").format(column))
                params.append(list(item.value))
        query = sql.SQL("SELECT * FROM {}.{}").format(sql.Identifier(schema), sql.Identifier(name))
        if where:
            query = sql.SQL("{} WHERE {}").format(query, sql.SQL(" AND ").join(where))
        if sort:
            query = sql.SQL("{} ORDER BY {}").format(query, sql.SQL(", ").join(
                sql.SQL("{} " + ("DESC" if desc else "ASC")).format(sql.Identifier(column))
                for column, desc in sort
            ))
        return query, params

    def table(self, schema: str | None, name: str, page: int, limit: int, sort_raw: str | None,
              filter_raw: str | None) -> dict[str, Any]:
        from psycopg import sql

        schema = schema or "public"
        started = time.perf_counter()
        with contextlib.closing(self.connect()) as conn:
            try:
                with conn.cursor() as cur:
                    self._begin_read(cur, self.spec.statement_timeout_ms)
                    described = self._describe(cur, schema, name)
                    names = [column["name"] for column in described["columns"]]
                    filters = policy.parse_filters(filter_raw, names)
                    sort = policy.parse_sort(sort_raw, names) or [
                        (column, False) for column in described["primary_key"]
                    ]
                    query, params = self._data_query(schema, name, filters, sort)
                    query = sql.SQL("{} LIMIT %s OFFSET %s").format(query)
                    cur.execute(query, [*params, limit + 1, (page - 1) * limit])
                    result_columns = self._columns(cur)
                    builder = self.limits.builder(limit + 1)
                    self._collect(cur, builder)
                conn.rollback()
            except policy.PolicyError:
                raise
            except Exception as exc:
                raise self._query_error(exc) from None
        payload = builder.payload()
        has_more = len(payload["rows"]) > limit
        payload["rows"] = payload["rows"][:limit]
        payload["row_count"] = len(payload["rows"])
        if has_more and payload["truncated_reason"] == "row_limit":
            payload.update(truncated=False, truncated_reason=None)
        return {
            "schema": schema, "table": name, **described, "result_columns": result_columns,
            **payload, "page": page, "limit": limit, "has_more": has_more,
            "sort": [{"column": c, "desc": d} for c, d in sort], "elapsed_ms": _ms(started),
        }

    def query(self, request: QueryRequest) -> dict[str, Any]:
        text = request.text or ""
        statement = sqltext.single_statement(text, "postgres")
        timeout = self.spec.statement_timeout_ms
        started = time.perf_counter()
        if not request.write:
            sqltext.check_read_only(statement, "postgres")
        elif request.dry_run and not sqltext.can_dry_run(statement, "postgres"):
            raise EngineError("dry_run_unsupported",
                              "a dry run is only possible for INSERT/UPDATE/DELETE/MERGE")
        autocommit = request.write and not request.dry_run
        with contextlib.closing(self.connect(autocommit=autocommit)) as conn:
            try:
                with conn.cursor() as cur:
                    if not request.write:
                        self._begin_read(cur, timeout)
                    else:
                        cur.execute("SELECT set_config('statement_timeout', %s, %s)",
                                    (str(timeout), not autocommit))
                    # prepare=True forces the extended protocol: one statement only.
                    cur.execute(text, prepare=True)
                    columns = self._columns(cur)
                    builder = self.limits.builder()
                    if cur.description:
                        self._collect(cur, builder)
                    affected = cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 \
                        else None
                if autocommit:
                    pass
                elif request.write and not request.dry_run:
                    conn.commit()
                else:
                    conn.rollback()
            except (policy.PolicyError, sqltext.SqlError):
                raise
            except Exception as exc:
                raise self._query_error(exc) from None
        return {
            "columns": columns, **builder.payload(), "affected_rows": affected,
            "statement_kind": statement.keyword, "elapsed_ms": _ms(started),
            "mode": "write" if request.write else "read", "dry_run": request.dry_run,
            "rolled_back": not request.write or request.dry_run,
        }

    def export(self, text: str | None, table: dict[str, Any] | None, max_rows: int,
               timeout_ms: int) -> Iterator[list[Any]]:
        """Yield the header row, then data rows (streamed with a server-side cursor)."""
        from psycopg import sql

        with contextlib.closing(self.connect(timeout_ms=timeout_ms)) as conn:
            try:
                with conn.cursor() as cur:
                    self._begin_read(cur, timeout_ms)
                    if table is not None:
                        schema = table.get("schema") or "public"
                        described = self._describe(cur, schema, table["name"])
                        names = [column["name"] for column in described["columns"]]
                        filters = policy.parse_filters(table.get("filter"), names)
                        sort = policy.parse_sort(table.get("sort"), names)
                        query, params = self._data_query(schema, table["name"], filters, sort)
                        query = sql.SQL("{} LIMIT %s").format(query)
                        params.append(max_rows)
                    else:
                        statement = sqltext.single_statement(text or "", "postgres")
                        sqltext.check_read_only(statement, "postgres")
                        if statement.keyword not in self.READ_EXPORT_KEYWORDS:
                            raise EngineError("export_unsupported",
                                              "only SELECT/WITH/VALUES/TABLE can be exported")
                        query, params = text, None
                with conn.cursor(name="mrk_dbadmin_export") as named:
                    named.itersize = EXPORT_BATCH
                    named.execute(query, params)
                    yield [item.name for item in named.description or []]
                    count = 0
                    for row in named:
                        if count >= max_rows:
                            break
                        count += 1
                        yield list(row)
                conn.rollback()
            except (policy.PolicyError, sqltext.SqlError, EngineError):
                raise
            except Exception as exc:
                raise self._query_error(exc) from None


# =========================================================================================
# MySQL / MariaDB
# =========================================================================================


class MysqlAdapter:
    def __init__(self, spec: ConnSpec, limits: Limits) -> None:
        self.spec = spec
        self.limits = limits

    def connect(self, *, database: str | None = None, timeout_ms: int | None = None) -> Any:
        import pymysql

        spec = self.spec
        timeout = timeout_ms or spec.statement_timeout_ms
        try:
            conn = pymysql.connect(
                host=spec.target,
                port=spec.port,
                user=spec.username or "root",
                password=spec.password or "",
                database=database or spec.database or None,
                connect_timeout=max(int(spec.connect_timeout), 1),
                read_timeout=math.ceil(timeout / 1000) + 10,
                write_timeout=math.ceil(timeout / 1000) + 10,
                charset=spec.options.get("charset", "utf8mb4"),
                ssl=_tls_context(spec.tls_mode),
                autocommit=False,
                local_infile=False,
                client_flag=0,
                program_name="mrk-dbadmin",
            )
        except pymysql.MySQLError as exc:
            raise self._connect_error(exc) from None
        conn.mrk_mariadb = "mariadb" in str(conn.get_server_info()).lower()  # type: ignore[attr-defined]
        return conn

    def _connect_error(self, exc: Exception) -> EngineError:
        code = exc.args[0] if exc.args and isinstance(exc.args[0], int) else None
        if code in {1045, 1044, 1698}:
            return EngineError("db_auth_failed", safe_message(exc, self.spec), 502)
        if code == 1049:
            return EngineError("db_query_failed", safe_message(exc, self.spec))
        if "timed out" in str(exc).lower():
            return EngineError("db_timeout", "the database did not answer in time", 504)
        return EngineError("db_unreachable", safe_message(exc, self.spec), 502)

    def _query_error(self, exc: Exception) -> EngineError:
        import pymysql

        if isinstance(exc, EngineError):
            return exc
        code = exc.args[0] if exc.args and isinstance(exc.args[0], int) else None
        if code in {3024, 1969, 1317}:
            return EngineError("db_timeout", "the statement timed out", 504)
        if code in {1792, 1290}:
            return EngineError("read_only_violation", safe_message(exc, self.spec))
        if code in {2006, 2013, 2003, 2055} or isinstance(exc, pymysql.err.InterfaceError):
            if "timed out" in str(exc).lower():
                return EngineError("db_timeout", "the statement timed out", 504)
            return EngineError("db_unreachable", safe_message(exc, self.spec), 502)
        return EngineError("db_query_failed", safe_message(exc, self.spec))

    @staticmethod
    def _set_timeout(conn: Any, cursor: Any, timeout_ms: int) -> None:
        with contextlib.suppress(Exception):
            if getattr(conn, "mrk_mariadb", False):
                cursor.execute("SET SESSION max_statement_time = %s", (timeout_ms / 1000,))
            else:
                cursor.execute("SET SESSION max_execution_time = %s", (int(timeout_ms),))

    def _begin_read(self, conn: Any, cursor: Any, timeout_ms: int) -> None:
        self._set_timeout(conn, cursor, timeout_ms)
        cursor.execute("START TRANSACTION READ ONLY")

    @staticmethod
    def _columns(cursor: Any) -> list[dict[str, Any]]:
        from pymysql.constants import FIELD_TYPE

        names = {value: key.lower() for key, value in vars(FIELD_TYPE).items()
                 if key.isupper() and isinstance(value, int)}
        return [{"name": item[0], "type": names.get(item[1])} for item in cursor.description or []]

    def _collect(self, cursor: Any, builder: policy.ResultBuilder) -> None:
        while True:
            batch = cursor.fetchmany(200)
            if not batch:
                return
            for row in batch:
                if not builder.add(row):
                    return

    def test(self) -> dict[str, Any]:
        started = time.perf_counter()
        with contextlib.closing(self.connect()) as conn:
            try:
                with conn.cursor() as cur:
                    self._begin_read(conn, cur, self.spec.statement_timeout_ms)
                    cur.execute("SELECT VERSION(), CURRENT_USER(), DATABASE()")
                    version, user, database = cur.fetchone()
                    conn.rollback()
            except Exception as exc:
                raise self._query_error(exc) from None
        return {"ok": True, "latency_ms": _ms(started), "server_version": str(version),
                "user": user, "database": database,
                "flavor": "mariadb" if conn.mrk_mariadb else "mysql"}

    def schema(self) -> dict[str, Any]:
        with contextlib.closing(self.connect()) as conn:
            try:
                with conn.cursor() as cur:
                    self._begin_read(conn, cur, self.spec.statement_timeout_ms)
                    if self.spec.database:
                        databases = [self.spec.database]
                    else:
                        cur.execute("SHOW DATABASES")
                        databases = [r[0] for r in cur.fetchall()
                                     if r[0].lower() not in SYSTEM_MYSQL_SCHEMAS][:MAX_NAMESPACES]
                    namespaces: dict[str, list[dict[str, Any]]] = {db: [] for db in databases}
                    rows: list[Any] = []
                    if databases:
                        cur.execute(
                            "SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, TABLE_ROWS, "
                            "DATA_LENGTH + INDEX_LENGTH FROM information_schema.TABLES "
                            "WHERE TABLE_SCHEMA IN %s ORDER BY 1, 2 LIMIT %s",
                            (tuple(databases), MAX_TABLES + 1),
                        )
                        rows = list(cur.fetchall())
                    for schema, name, kind, estimate, size in rows[:MAX_TABLES]:
                        namespaces.setdefault(schema, []).append({
                            "name": name,
                            "type": "view" if "VIEW" in str(kind).upper() else "table",
                            "rows_estimate": None if estimate is None else int(estimate),
                            "size_bytes": None if size is None else int(size),
                        })
                    users: list[dict[str, Any]] = []
                    try:
                        cur.execute("SELECT User, Host FROM mysql.user ORDER BY 1, 2 LIMIT 500")
                        users = [{"name": r[0], "host": r[1]} for r in cur.fetchall()]
                    except Exception:  # noqa: BLE001 - needs privileges; best effort
                        users = []
                    conn.rollback()
            except Exception as exc:
                raise self._query_error(exc) from None
        return {"engine": self.spec.engine, "database": self.spec.database,
                "namespace_kind": "database",
                "namespaces": [{"name": k, "tables": v} for k, v in namespaces.items()],
                "users": users, "truncated": len(rows) > MAX_TABLES}

    def _describe(self, cur: Any, schema: str, name: str) -> dict[str, Any]:
        cur.execute(
            "SELECT TABLE_ROWS, DATA_LENGTH + INDEX_LENGTH FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s", (schema, name),
        )
        found = cur.fetchone()
        if found is None:
            raise EngineError("table_not_found", "table not found", 404)
        cur.execute(
            "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_KEY, EXTRA "
            "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s "
            "ORDER BY ORDINAL_POSITION", (schema, name),
        )
        columns = [{"name": r[0], "type": r[1], "nullable": r[2] == "YES", "default": r[3],
                    "key": r[4] or None, "extra": r[5] or None} for r in cur.fetchall()]
        cur.execute(
            "SELECT INDEX_NAME, NON_UNIQUE, COLUMN_NAME FROM information_schema.STATISTICS "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY INDEX_NAME, SEQ_IN_INDEX",
            (schema, name),
        )
        indexes: dict[str, dict[str, Any]] = {}
        for index_name, non_unique, column in cur.fetchall():
            entry = indexes.setdefault(index_name, {
                "name": index_name, "columns": [], "unique": not int(non_unique),
                "primary": index_name == "PRIMARY"})
            entry["columns"].append(column)
        primary = indexes.get("PRIMARY", {}).get("columns", [])
        return {"columns": columns, "indexes": list(indexes.values()), "primary_key": primary,
                "rows_estimate": None if found[0] is None else int(found[0]),
                "size_bytes": None if found[1] is None else int(found[1])}

    @staticmethod
    def _data_query(schema: str, name: str, filters: list[policy.Filter],
                    sort: list[tuple[str, bool]]) -> tuple[str, list[Any]]:
        quote = sqltext.quote_mysql_ident
        operators = {"eq": "=", "ne": "<>", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
        where: list[str] = []
        params: list[Any] = []
        for item in filters:
            column = quote(item.column)
            if item.op in operators:
                where.append(f"{column} {operators[item.op]} %s")
                params.append(item.value)
            elif item.op == "like":
                where.append(f"{column} LIKE %s")
                params.append(item.value)
            elif item.op == "ilike":
                where.append(f"LOWER({column}) LIKE LOWER(%s)")
                params.append(item.value)
            elif item.op == "is_null":
                where.append(f"{column} IS NULL")
            elif item.op == "not_null":
                where.append(f"{column} IS NOT NULL")
            elif item.op == "in":
                where.append(f"{column} IN %s")
                params.append(tuple(item.value))
        # Identifiers come from the catalog and are quoted; values are parameters.
        query = f"SELECT * FROM {quote(schema)}.{quote(name)}"  # noqa: S608
        if where:
            query += " WHERE " + " AND ".join(where)
        if sort:
            query += " ORDER BY " + ", ".join(
                f"{quote(column)} {'DESC' if desc else 'ASC'}" for column, desc in sort
            )
        return query, params

    def _schema_for(self, schema: str | None) -> str:
        schema = schema or self.spec.database
        if not schema:
            raise EngineError("schema_required", "pass ?schema=<database> for this connection")
        return schema

    def table(self, schema: str | None, name: str, page: int, limit: int, sort_raw: str | None,
              filter_raw: str | None) -> dict[str, Any]:
        schema = self._schema_for(schema)
        started = time.perf_counter()
        with contextlib.closing(self.connect()) as conn:
            try:
                with conn.cursor() as cur:
                    self._begin_read(conn, cur, self.spec.statement_timeout_ms)
                    described = self._describe(cur, schema, name)
                    names = [column["name"] for column in described["columns"]]
                    filters = policy.parse_filters(filter_raw, names)
                    sort = policy.parse_sort(sort_raw, names) or [
                        (column, False) for column in described["primary_key"]
                    ]
                    query, params = self._data_query(schema, name, filters, sort)
                    cur.execute(query + " LIMIT %s OFFSET %s",
                                (*params, limit + 1, (page - 1) * limit))
                    result_columns = self._columns(cur)
                    builder = self.limits.builder(limit + 1)
                    self._collect(cur, builder)
                    conn.rollback()
            except policy.PolicyError:
                raise
            except Exception as exc:
                raise self._query_error(exc) from None
        payload = builder.payload()
        has_more = len(payload["rows"]) > limit
        payload["rows"] = payload["rows"][:limit]
        payload["row_count"] = len(payload["rows"])
        if has_more and payload["truncated_reason"] == "row_limit":
            payload.update(truncated=False, truncated_reason=None)
        return {
            "schema": schema, "table": name, **described, "result_columns": result_columns,
            **payload, "page": page, "limit": limit, "has_more": has_more,
            "sort": [{"column": c, "desc": d} for c, d in sort], "elapsed_ms": _ms(started),
        }

    def query(self, request: QueryRequest) -> dict[str, Any]:
        text = request.text or ""
        statement = sqltext.single_statement(text, "mysql")
        timeout = self.spec.statement_timeout_ms
        if not request.write:
            sqltext.check_read_only(statement, "mysql")
        elif request.dry_run and not sqltext.can_dry_run(statement, "mysql"):
            raise EngineError("dry_run_unsupported",
                              "a dry run is only possible for INSERT/UPDATE/DELETE/REPLACE")
        started = time.perf_counter()
        with contextlib.closing(self.connect(database=request.database)) as conn:
            try:
                with conn.cursor() as cur:
                    if not request.write:
                        self._begin_read(conn, cur, timeout)
                    else:
                        self._set_timeout(conn, cur, timeout)
                        if request.dry_run:
                            cur.execute("START TRANSACTION")
                    # args=None: PyMySQL performs no %-interpolation on the text.
                    cur.execute(text)
                    columns = self._columns(cur)
                    builder = self.limits.builder()
                    if cur.description:
                        self._collect(cur, builder)
                    affected = cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 \
                        else None
                    if request.write and not request.dry_run:
                        conn.commit()
                    else:
                        conn.rollback()
            except (policy.PolicyError, sqltext.SqlError):
                raise
            except Exception as exc:
                raise self._query_error(exc) from None
        return {
            "columns": columns, **builder.payload(),
            "affected_rows": None if cur.description and not request.write else affected,
            "statement_kind": statement.keyword, "elapsed_ms": _ms(started),
            "mode": "write" if request.write else "read", "dry_run": request.dry_run,
            "rolled_back": not request.write or request.dry_run,
        }

    def export(self, text: str | None, table: dict[str, Any] | None, max_rows: int,
               timeout_ms: int) -> Iterator[list[Any]]:
        import pymysql.cursors

        database = table.get("schema") if table else None
        with contextlib.closing(self.connect(database=database, timeout_ms=timeout_ms)) as conn:
            try:
                with conn.cursor() as cur:
                    if table is not None:
                        schema = self._schema_for(table.get("schema"))
                        self._begin_read(conn, cur, timeout_ms)
                        described = self._describe(cur, schema, table["name"])
                        names = [column["name"] for column in described["columns"]]
                        filters = policy.parse_filters(table.get("filter"), names)
                        sort = policy.parse_sort(table.get("sort"), names)
                        query, params = self._data_query(schema, table["name"], filters, sort)
                        query += " LIMIT %s"
                        args: Any = (*params, max_rows)
                    else:
                        statement = sqltext.single_statement(text or "", "mysql")
                        sqltext.check_read_only(statement, "mysql")
                        self._begin_read(conn, cur, timeout_ms)
                        query, args = text, None
                with conn.cursor(pymysql.cursors.SSCursor) as stream:
                    stream.execute(query, args)
                    yield [item[0] for item in stream.description or []]
                    count = 0
                    while count < max_rows:
                        batch = stream.fetchmany(EXPORT_BATCH)
                        if not batch:
                            break
                        for row in batch:
                            if count >= max_rows:
                                break
                            count += 1
                            yield list(row)
                conn.rollback()
            except (policy.PolicyError, sqltext.SqlError, EngineError):
                raise
            except Exception as exc:
                raise self._query_error(exc) from None


# =========================================================================================
# MongoDB
# =========================================================================================


def _mongo_to_json(document: Any) -> Any:
    from bson import json_util

    return json.loads(json_util.dumps(document, json_options=json_util.RELAXED_JSON_OPTIONS))


def _json_to_mongo(value: Any) -> Any:
    from bson import json_util

    return json_util.loads(json.dumps(value))


def _like_to_regex(pattern: str) -> str:
    out = []
    for char in pattern:
        out.append(".*" if char == "%" else "." if char == "_" else re.escape(char))
    return "^" + "".join(out) + "$"


class MongoAdapter:
    def __init__(self, spec: ConnSpec, limits: Limits) -> None:
        self.spec = spec
        self.limits = limits

    def client(self, timeout_ms: int | None = None) -> Any:
        from pymongo import MongoClient

        spec = self.spec
        timeout = timeout_ms or spec.statement_timeout_ms
        connect_ms = max(int(spec.connect_timeout), 1) * 1000
        kwargs: dict[str, Any] = {
            "host": spec.target,
            "port": spec.port,
            "directConnection": True,
            "serverSelectionTimeoutMS": connect_ms,
            "connectTimeoutMS": connect_ms,
            "socketTimeoutMS": timeout + 10000,
            "appname": "mrk-dbadmin",
            "retryWrites": False,
            "retryReads": False,
            "tz_aware": True,
            "uuidRepresentation": "standard",
            "maxPoolSize": 1,
            "connect": False,
        }
        if spec.tls_mode != "disable":
            kwargs["tls"] = True
            if spec.tls_mode == "require":
                kwargs["tlsAllowInvalidCertificates"] = True
                kwargs["tlsAllowInvalidHostnames"] = True
        if spec.username:
            kwargs["username"] = spec.username
            kwargs["password"] = spec.password or ""
            kwargs["authSource"] = spec.options.get("auth_source", "admin")
        return MongoClient(**kwargs)

    def _error(self, exc: Exception) -> EngineError:
        from pymongo import errors

        if isinstance(exc, EngineError):
            return exc
        if isinstance(exc, errors.ExecutionTimeout):
            return EngineError("db_timeout", "the operation timed out", 504)
        if isinstance(exc, errors.OperationFailure):
            if exc.code in {18, 13} and "auth" in str(exc).lower():
                return EngineError("db_auth_failed", safe_message(exc, self.spec), 502)
            if exc.code == 50:
                return EngineError("db_timeout", "the operation timed out", 504)
            return EngineError("db_query_failed", safe_message(exc, self.spec))
        if isinstance(exc, errors.ServerSelectionTimeoutError | errors.ConnectionFailure):
            if "auth" in str(exc).lower():
                return EngineError("db_auth_failed", safe_message(exc, self.spec), 502)
            if isinstance(exc, errors.NetworkTimeout) and "timed out" in str(exc).lower():
                return EngineError("db_timeout", "the database did not answer in time", 504)
            return EngineError("db_unreachable", safe_message(exc, self.spec), 502)
        if isinstance(exc, errors.PyMongoError | ValueError | TypeError):
            return EngineError("db_query_failed", safe_message(exc, self.spec))
        return EngineError("db_query_failed", safe_message(exc, self.spec))

    def _database(self, name: str | None) -> str:
        database = name or self.spec.database
        if not database:
            raise EngineError("schema_required", "pass the database name for this connection")
        return database

    def test(self) -> dict[str, Any]:
        started = time.perf_counter()
        client = self.client()
        try:
            client.admin.command("ping")
            info = client.admin.command("buildInfo")
            return {"ok": True, "latency_ms": _ms(started),
                    "server_version": str(info.get("version")), "user": self.spec.username,
                    "database": self.spec.database}
        except Exception as exc:
            raise self._error(exc) from None
        finally:
            client.close()

    def _collection_stats(self, db: Any, name: str) -> tuple[int | None, int | None]:
        timeout = self.spec.statement_timeout_ms
        count = size = None
        with contextlib.suppress(Exception):
            count = int(db[name].estimated_document_count(maxTimeMS=timeout))
        with contextlib.suppress(Exception):
            stats = db.command("collStats", name, maxTimeMS=timeout)
            size = int(stats.get("totalSize") or stats.get("storageSize") or stats.get("size"))
        return count, size

    def schema(self) -> dict[str, Any]:
        client = self.client()
        timeout = self.spec.statement_timeout_ms
        try:
            if self.spec.database:
                databases = [self.spec.database]
            else:
                databases = [name for name in client.list_database_names()
                             if name not in SYSTEM_MONGO_DATABASES][:MAX_NAMESPACES]
            namespaces = []
            total = 0
            for database in databases:
                db = client[database]
                tables = []
                for item in db.list_collections(maxTimeMS=timeout):
                    if total >= MAX_TABLES:
                        break
                    total += 1
                    name = item.get("name")
                    kind = item.get("type", "collection")
                    if not isinstance(name, str) or name.startswith("system."):
                        continue
                    count, size = (None, None)
                    if total <= 500 and kind == "collection":
                        count, size = self._collection_stats(db, name)
                    tables.append({"name": name, "type": kind, "rows_estimate": count,
                                   "size_bytes": size})
                tables.sort(key=lambda entry: entry["name"])
                namespaces.append({"name": database, "tables": tables})
            users: list[dict[str, Any]] = []
            with contextlib.suppress(Exception):
                info = client[self.spec.database or "admin"].command("usersInfo", maxTimeMS=timeout)
                users = [{"name": u.get("user"), "database": u.get("db"),
                          "roles": [r.get("role") for r in u.get("roles", [])]}
                         for u in info.get("users", [])][:500]
            return {"engine": "mongo", "database": self.spec.database,
                    "namespace_kind": "database", "namespaces": namespaces, "users": users,
                    "truncated": total >= MAX_TABLES}
        except EngineError:
            raise
        except Exception as exc:
            raise self._error(exc) from None
        finally:
            client.close()

    @staticmethod
    def _mongo_filter(filters: list[policy.Filter]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        conditions = []
        for item in filters:
            value = item.value
            if item.column == "_id" and isinstance(value, str) and re.fullmatch(
                r"[0-9a-fA-F]{24}", value
            ):
                value = {"$oid": value}
            ops = {"eq": "$eq", "ne": "$ne", "lt": "$lt", "lte": "$lte", "gt": "$gt",
                   "gte": "$gte", "in": "$in"}
            if item.op in ops:
                condition = {item.column: {ops[item.op]: value}}
            elif item.op in {"like", "ilike"}:
                condition = {item.column: {"$regex": _like_to_regex(str(item.value)),
                                           **({"$options": "i"} if item.op == "ilike" else {})}}
            elif item.op == "is_null":
                condition = {item.column: None}
            else:
                condition = {item.column: {"$ne": None}}
            conditions.append(condition)
        if conditions:
            result = conditions[0] if len(conditions) == 1 else {"$and": conditions}
        return _json_to_mongo(result)

    def _rows(self, documents: Iterator[Any], builder: policy.ResultBuilder,
              columns: list[str] | None = None) -> list[str]:
        docs = []
        for document in documents:
            docs.append(_mongo_to_json(document))
            if len(docs) > builder.max_rows:
                break
        names: list[str] = list(columns or [])
        if not names:
            for doc in docs:
                if isinstance(doc, dict):
                    for key in doc:
                        if key not in names and len(names) < 500:
                            names.append(key)
                elif "value" not in names:
                    names.append("value")
        for doc in docs:
            row = [doc.get(key) for key in names] if isinstance(doc, dict) else [doc]
            if not builder.add(row):
                break
        return names

    def table(self, schema: str | None, name: str, page: int, limit: int, sort_raw: str | None,
              filter_raw: str | None) -> dict[str, Any]:
        database = self._database(schema)
        started = time.perf_counter()
        filters = policy.parse_filters(filter_raw, None, keep_types=True)
        sort = policy.parse_sort(sort_raw, None)
        client = self.client()
        try:
            db = client[database]
            if name not in db.list_collection_names(filter={"name": name}):
                raise EngineError("table_not_found", "collection not found", 404)
            collection = db[name]
            cursor = collection.find(self._mongo_filter(filters))
            if sort:
                cursor = cursor.sort([(column, -1 if desc else 1) for column, desc in sort])
            cursor = cursor.skip((page - 1) * limit).limit(limit + 1).max_time_ms(
                self.spec.statement_timeout_ms
            )
            builder = self.limits.builder(limit + 1)
            columns = self._rows(cursor, builder)
            indexes = [
                {"name": index_name, "columns": [key for key, _ in info.get("key", [])],
                 "unique": bool(info.get("unique")), "primary": index_name == "_id_",
                 "definition": json.dumps(_mongo_to_json(dict(info.get("key", []))))}
                for index_name, info in collection.index_information().items()
            ]
            estimate, size = self._collection_stats(db, name)
        except (EngineError, policy.PolicyError):
            raise
        except Exception as exc:
            raise self._error(exc) from None
        finally:
            client.close()
        payload = builder.payload()
        has_more = len(payload["rows"]) > limit
        payload["rows"] = payload["rows"][:limit]
        payload["row_count"] = len(payload["rows"])
        if has_more and payload["truncated_reason"] == "row_limit":
            payload.update(truncated=False, truncated_reason=None)
        return {
            "schema": database, "table": name,
            "columns": [{"name": column, "type": None, "nullable": True, "default": None}
                        for column in columns],
            "indexes": indexes, "primary_key": ["_id"], "rows_estimate": estimate,
            "size_bytes": size, "result_columns": [{"name": c, "type": None} for c in columns],
            **payload, "page": page, "limit": limit, "has_more": has_more,
            "sort": [{"column": c, "desc": d} for c, d in sort], "elapsed_ms": _ms(started),
        }

    def query(self, request: QueryRequest) -> dict[str, Any]:
        req = request.mongo
        if req is None:
            raise EngineError("query_invalid", "this connection takes a mongo query")
        timeout = self.spec.statement_timeout_ms
        started = time.perf_counter()
        builder = self.limits.builder()
        client = self.client()
        affected: int | None = None
        extra: dict[str, Any] = {}
        columns: list[str] = []
        try:
            collection = client[self._database(req.database or request.database)][req.collection]
            filter_doc = _json_to_mongo(req.filter)
            if req.op == "find":
                if req.limit and req.limit <= builder.max_rows:
                    limit = req.limit
                else:
                    limit = builder.max_rows + 1
                cursor = collection.find(
                    filter_doc,
                    projection=_json_to_mongo(req.projection) if req.projection else None,
                    skip=req.skip, limit=limit, max_time_ms=timeout,
                )
                if req.sort:
                    cursor = cursor.sort(req.sort)
                columns = self._rows(cursor, builder)
            elif req.op == "aggregate":
                pipeline = [*_json_to_mongo(req.pipeline), {"$limit": builder.max_rows + 1}]
                cursor = collection.aggregate(pipeline, maxTimeMS=timeout, allowDiskUse=False)
                columns = self._rows(cursor, builder)
            elif req.op == "count":
                count = collection.count_documents(filter_doc, maxTimeMS=timeout)
                columns = ["count"]
                builder.add([count])
            elif req.op == "distinct":
                values = collection.distinct(req.key, filter_doc, maxTimeMS=timeout)
                columns = ["value"]
                for value in values:
                    if not builder.add([_mongo_to_json(value)]):
                        break
            elif request.dry_run:
                if req.op.startswith("insert"):
                    affected = len(req.documents)
                else:
                    matched = collection.count_documents(filter_doc, maxTimeMS=timeout)
                    affected = min(matched, 1) if req.op.endswith("_one") else matched
                extra["preview"] = "matched documents (nothing was changed)"
            elif req.op == "insert_one":
                result = collection.insert_one(_json_to_mongo(req.documents[0]))
                affected = 1
                extra["inserted_ids"] = [_mongo_to_json(result.inserted_id)]
            elif req.op == "insert_many":
                result = collection.insert_many(_json_to_mongo(req.documents), ordered=True)
                affected = len(result.inserted_ids)
                extra["inserted_ids"] = _mongo_to_json(result.inserted_ids)[:100]
            elif req.op in {"update_one", "update_many"}:
                update = _json_to_mongo(req.update)
                method = collection.update_one if req.op == "update_one" else \
                    collection.update_many
                result = method(filter_doc, update)
                affected = result.modified_count
                extra["matched"] = result.matched_count
            elif req.op in {"delete_one", "delete_many"}:
                method = collection.delete_one if req.op == "delete_one" else \
                    collection.delete_many
                result = method(filter_doc)
                affected = result.deleted_count
        except (EngineError, policy.PolicyError):
            raise
        except Exception as exc:
            raise self._error(exc) from None
        finally:
            client.close()
        return {
            "columns": [{"name": c, "type": None} for c in columns], **builder.payload(),
            "affected_rows": affected, "statement_kind": req.op, "elapsed_ms": _ms(started),
            "mode": "write" if request.write else "read", "dry_run": request.dry_run,
            "rolled_back": not request.write or request.dry_run, **extra,
        }

    def export(self, mongo: policy.MongoRequest | None, table: dict[str, Any] | None,
               max_rows: int, timeout_ms: int) -> Iterator[list[Any]]:
        client = self.client(timeout_ms)
        try:
            if table is not None:
                database = self._database(table.get("schema"))
                filters = policy.parse_filters(table.get("filter"), None, keep_types=True)
                sort = policy.parse_sort(table.get("sort"), None)
                cursor = client[database][table["name"]].find(self._mongo_filter(filters))
                if sort:
                    cursor = cursor.sort([(c, -1 if d else 1) for c, d in sort])
                cursor = cursor.limit(max_rows).max_time_ms(timeout_ms)
            elif mongo is not None and mongo.op in {"find", "aggregate"}:
                collection = client[self._database(mongo.database)][mongo.collection]
                if mongo.op == "find":
                    cursor = collection.find(
                        _json_to_mongo(mongo.filter),
                        projection=_json_to_mongo(mongo.projection) if mongo.projection else None,
                        skip=mongo.skip, limit=min(mongo.limit or max_rows, max_rows),
                        max_time_ms=timeout_ms,
                    )
                    if mongo.sort:
                        cursor = cursor.sort(mongo.sort)
                else:
                    cursor = collection.aggregate(
                        [*_json_to_mongo(mongo.pipeline), {"$limit": max_rows}],
                        maxTimeMS=timeout_ms, allowDiskUse=False, batchSize=EXPORT_BATCH,
                    )
            else:
                raise EngineError("export_unsupported", "only find/aggregate can be exported")
            # Columns come from the first batch; later extra fields are not exported.
            head: list[Any] = []
            for document in cursor:
                head.append(_mongo_to_json(document))
                if len(head) >= 100:
                    break
            names: list[str] = []
            for doc in head:
                for key in doc if isinstance(doc, dict) else ["value"]:
                    if key not in names and len(names) < 500:
                        names.append(key)
            yield names
            count = 0
            for doc in head:
                count += 1
                yield [doc.get(k) for k in names] if isinstance(doc, dict) else [doc]
            for document in cursor:
                if count >= max_rows:
                    break
                count += 1
                doc = _mongo_to_json(document)
                yield [doc.get(k) for k in names] if isinstance(doc, dict) else [doc]
        except (EngineError, policy.PolicyError):
            raise
        except Exception as exc:
            raise self._error(exc) from None
        finally:
            client.close()


# =========================================================================================
# Redis
# =========================================================================================


def _redis_value(value: Any) -> Any:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value
    if isinstance(value, list | tuple | set):
        return [_redis_value(item) for item in value]
    if isinstance(value, dict):
        return {str(_redis_value(k)): _redis_value(v) for k, v in value.items()}
    return value


class RedisAdapter:
    def __init__(self, spec: ConnSpec, limits: Limits) -> None:
        self.spec = spec
        self.limits = limits

    def client(self) -> Any:
        import redis
        from redis.backoff import NoBackoff
        from redis.retry import Retry

        spec = self.spec
        kwargs: dict[str, Any] = {
            "host": spec.target,
            "port": spec.port,
            "db": int(spec.database or 0),
            "username": spec.username or None,
            "password": spec.password or None,
            "socket_timeout": spec.statement_timeout_ms / 1000 + 5,
            "socket_connect_timeout": max(int(spec.connect_timeout), 1),
            "retry": Retry(NoBackoff(), 0),
            "decode_responses": False,
            "single_connection_client": True,
        }
        if spec.tls_mode != "disable":
            kwargs["ssl"] = True
            kwargs["ssl_cert_reqs"] = "required" if spec.tls_mode == "verify" else "none"
            kwargs["ssl_check_hostname"] = spec.tls_mode == "verify"
        return redis.Redis(**kwargs)

    def _error(self, exc: Exception) -> EngineError:
        import redis

        if isinstance(exc, EngineError):
            return exc
        if isinstance(exc, redis.AuthenticationError | redis.AuthorizationError):
            return EngineError("db_auth_failed", safe_message(exc, self.spec), 502)
        if isinstance(exc, redis.TimeoutError):
            return EngineError("db_timeout", "the database did not answer in time", 504)
        if isinstance(exc, redis.ConnectionError):
            if "auth" in str(exc).lower() or "NOAUTH" in str(exc):
                return EngineError("db_auth_failed", safe_message(exc, self.spec), 502)
            return EngineError("db_unreachable", safe_message(exc, self.spec), 502)
        if isinstance(exc, redis.ResponseError) and "NOAUTH" in str(exc):
            return EngineError("db_auth_failed", safe_message(exc, self.spec), 502)
        return EngineError("db_query_failed", safe_message(exc, self.spec))

    def test(self) -> dict[str, Any]:
        started = time.perf_counter()
        client = self.client()
        try:
            client.ping()
            info = client.info("server")
            return {"ok": True, "latency_ms": _ms(started),
                    "server_version": str(info.get("redis_version")),
                    "user": self.spec.username, "database": self.spec.database or "0"}
        except Exception as exc:
            raise self._error(exc) from None
        finally:
            client.close()

    def schema(self) -> dict[str, Any]:
        client = self.client()
        try:
            keyspace = client.info("keyspace")
            namespaces = []
            for name, value in sorted(keyspace.items()):
                if isinstance(value, dict) and str(name).startswith("db"):
                    namespaces.append({"name": str(name)[2:], "keys": value.get("keys"),
                                       "expires": value.get("expires"), "tables": []})
            return {"engine": "redis", "database": self.spec.database or "0",
                    "namespace_kind": "database", "namespaces": namespaces, "users": [],
                    "truncated": False, "dbsize": client.dbsize()}
        except Exception as exc:
            raise self._error(exc) from None
        finally:
            client.close()

    def table(self, *_args: Any) -> dict[str, Any]:
        raise EngineError("unsupported_for_engine",
                          "Redis has no tables; use the query endpoint with SCAN")

    def query(self, request: QueryRequest) -> dict[str, Any]:
        if request.redis is None:
            raise EngineError("query_invalid", "this connection takes a redis command")
        if request.dry_run:
            raise EngineError("dry_run_unsupported", "Redis commands cannot be dry-run")
        name, args = request.redis
        started = time.perf_counter()
        builder = self.limits.builder()
        client = self.client()
        extra: dict[str, Any] = {}
        try:
            result = client.execute_command(name, *args)
        except Exception as exc:
            raise self._error(exc) from None
        finally:
            client.close()
        value = _redis_value(result)
        if name in policy.REDIS_SCAN_COMMANDS and isinstance(value, list) and len(value) == 2:
            extra["cursor"] = str(value[0])
            items = value[1]
            if name in {"HSCAN", "ZSCAN"} and isinstance(items, dict):
                columns = ["field", "value"]
                rows = [[k, v] for k, v in items.items()]
            elif name in {"HSCAN", "ZSCAN"} and isinstance(items, list) and items and \
                    isinstance(items[0], list):
                columns = ["field", "value"]
                rows = [list(item) for item in items]
            else:
                columns = ["key"]
                rows = [[item] for item in (items if isinstance(items, list) else [items])]
        elif isinstance(value, dict):
            columns = ["field", "value"]
            rows = [[k, v] for k, v in value.items()]
        elif isinstance(value, list):
            columns = ["value"]
            rows = [[item] for item in value]
        else:
            columns = ["value"]
            rows = [[value]]
        for row in rows:
            if not builder.add(row):
                break
        affected = None
        if request.write and isinstance(result, int) and not isinstance(result, bool):
            affected = result
        return {
            "columns": [{"name": c, "type": None} for c in columns], **builder.payload(),
            "affected_rows": affected, "statement_kind": name, "elapsed_ms": _ms(started),
            "mode": "write" if request.write else "read", "dry_run": False,
            "rolled_back": not request.write, **extra,
        }


ADAPTERS: dict[str, type] = {
    "postgres": PostgresAdapter,
    "mysql": MysqlAdapter,
    "mariadb": MysqlAdapter,
    "mongo": MongoAdapter,
    "redis": RedisAdapter,
}


def adapter_for(spec: ConnSpec, limits: Limits) -> Any:
    return ADAPTERS[spec.engine](spec, limits)
