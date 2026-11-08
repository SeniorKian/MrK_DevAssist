"""Gate 19 S9 database admin module (docs/32 §5): unit and API tests with fakes."""

from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.database import Database
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import dbadmin
from mrk_control_plane.modules import dbadmin_engines as engines
from mrk_control_plane.modules import dbadmin_policy as policy
from mrk_control_plane.modules import dbadmin_sql as sqltext
from sqlalchemy import inspect

from .helpers import login_owner

API = "/api/v1/dbadmin"
PASSWORD = "db-secret-Pa55word-xyz"  # noqa: S105 - test fixture


# ----- SQL tokenizer ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "dialect"),
    [
        ("SELECT 1", "postgres"),
        ("SELECT 1;", "postgres"),
        ("SELECT 1;;  ", "postgres"),
        ("SELECT ';' AS semi", "postgres"),
        ("SELECT 'it''s; fine'", "postgres"),
        ('SELECT 1 AS "a;b"', "postgres"),
        ('SELECT 1 AS "a"";b"', "postgres"),
        ("SELECT E'a\\'; b'", "postgres"),
        ("SELECT $$ ; $$", "postgres"),
        ("SELECT $body$ ; $notbody$ ; $body$", "postgres"),
        ("CREATE FUNCTION f() RETURNS int AS $f$ BEGIN RETURN 1; END; $f$ LANGUAGE plpgsql",
         "postgres"),
        ("SELECT 1 -- trailing; comment", "postgres"),
        ("SELECT /* a; /* nested; */ still; */ 1", "postgres"),
        ("SELECT a$b FROM t", "postgres"),
        ("SELECT $1", "postgres"),
        ("SELECT 'a\\'; b'", "mysql"),
        ('SELECT "a\\"; b"', "mysql"),
        ("SELECT `we;ird` FROM t", "mysql"),
        ("SELECT 1 # comment; here", "mysql"),
        ("SELECT 1 -- comment; here", "mysql"),
        ("SELECT /* a; */ 1", "mysql"),
    ],
)
def test_single_statement_accepts(text: str, dialect: str) -> None:
    assert sqltext.single_statement(text, dialect).keyword in {"SELECT", "CREATE"}


@pytest.mark.parametrize(
    ("text", "dialect", "code"),
    [
        ("SELECT 1; SELECT 2", "postgres", "sql_multiple_statements"),
        ("SELECT 1; DROP TABLE t", "mysql", "sql_multiple_statements"),
        ("SELECT 'a'';'; DELETE FROM t", "postgres", "sql_multiple_statements"),
        ("SELECT $$ x $$; DELETE FROM t", "postgres", "sql_multiple_statements"),
        ("SELECT /* x */ 1; /* y */ DELETE FROM t", "postgres", "sql_multiple_statements"),
        # In PostgreSQL a backslash does not escape a quote in a standard string.
        ("SELECT 'a\\'; DELETE FROM t; SELECT ''", "postgres", "sql_multiple_statements"),
        # MySQL: "--x" is not a comment, so the ';' is real.
        ("SELECT 1--1; DELETE FROM t", "mysql", "sql_multiple_statements"),
        ("SELECT 'open", "postgres", "sql_unterminated"),
        ("SELECT $$ open", "postgres", "sql_unterminated"),
        ("SELECT /* open", "postgres", "sql_unterminated"),
        ("SELECT /* outer /* inner */ 1; DROP", "postgres", "sql_unterminated"),
        ('SELECT "open', "postgres", "sql_unterminated"),
        ("SELECT `open", "mysql", "sql_unterminated"),
        ("SELECT 1 /*! ; DROP TABLE t */", "mysql", "sql_executable_comment"),
        ("   ", "postgres", "sql_empty"),
        ("-- only a comment", "postgres", "sql_empty"),
        (";;", "mysql", "sql_empty"),
        ("SELECT 1\x00", "postgres", "sql_invalid"),
    ],
)
def test_single_statement_rejects(text: str, dialect: str, code: str) -> None:
    with pytest.raises(sqltext.SqlError) as raised:
        sqltext.single_statement(text, dialect)
    assert raised.value.code == code


def test_mysql_block_comment_does_not_nest() -> None:
    # MySQL ends the comment at the first */, so "; DROP" is a second statement.
    with pytest.raises(sqltext.SqlError) as raised:
        sqltext.single_statement("SELECT /* a /* b */ 1; DROP TABLE t", "mysql")
    assert raised.value.code == "sql_multiple_statements"


def test_read_only_classification() -> None:
    for text in ("SELECT 1", "WITH x AS (SELECT 1) SELECT * FROM x", "EXPLAIN SELECT 1",
                 "SHOW search_path", "VALUES (1)", "TABLE t", "  (SELECT 1)"):
        statement = sqltext.single_statement(text, "postgres")
        if statement.keyword:
            sqltext.check_read_only(statement, "postgres")
    for text in ("UPDATE t SET a = 1", "DELETE FROM t", "INSERT INTO t VALUES (1)",
                 "DROP TABLE t", "COPY t TO PROGRAM 'id'", "DO $$ BEGIN END $$",
                 "SET default_transaction_read_only = off", "COMMIT", "CALL p()",
                 "SELECT pg_terminate_backend(1)", "SELECT pg_catalog.pg_read_file('x')",
                 'SELECT "pg_reload_conf"()', "SELECT dblink_exec('x', 'y')",
                 "SELECT set_config('a', 'b', false)", "SELECT lo_export(1, '/tmp/x')"):
        with pytest.raises(sqltext.SqlError) as raised:
            sqltext.check_read_only(sqltext.single_statement(text, "postgres"), "postgres")
        assert raised.value.code == "read_only_violation", text
    for text in ("SELECT * FROM t INTO OUTFILE '/tmp/x'", "SELECT LOAD_FILE('/etc/passwd')",
                 "LOAD DATA INFILE 'x' INTO TABLE t", "SET GLOBAL x = 1", "HANDLER t OPEN"):
        with pytest.raises(sqltext.SqlError):
            sqltext.check_read_only(sqltext.single_statement(text, "mysql"), "mysql")
    sqltext.check_read_only(sqltext.single_statement("DESCRIBE t", "mysql"), "mysql")
    # A denied word inside a string literal is data, not a call.
    sqltext.check_read_only(
        sqltext.single_statement("SELECT 'pg_terminate_backend'", "postgres"), "postgres"
    )
    assert sqltext.can_dry_run(sqltext.single_statement("UPDATE t SET a=1", "mysql"), "mysql")
    assert not sqltext.can_dry_run(sqltext.single_statement("DROP TABLE t", "mysql"), "mysql")
    assert sqltext.quote_mysql_ident("a`b") == "`a``b`"
    assert len(sqltext.statement_hash("SELECT 1")) == 64


# ----- destination policy ---------------------------------------------------------------------


def test_destination_policy() -> None:
    allowed = ["10.0.0.5", "172.18.0.4", "192.168.1.20", "100.64.0.1", "8.8.8.8", "fd12::1",
               "2001:4860::8888"]
    for address in allowed:
        assert policy.address_allowed(ipaddress.ip_address(address)) is None, address
    denied = ["127.0.0.1", "127.8.8.8", "::1", "169.254.169.254", "169.254.1.1", "fe80::1",
              "0.0.0.0",  # noqa: S104
              "::", "224.0.0.1", "255.255.255.255", "240.0.0.1", "fd00:ec2::254",
              "100.100.100.200", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "2002:7f00:1::"]
    for address in denied:
        assert policy.address_allowed(ipaddress.ip_address(address)) is not None, address
    with pytest.raises(policy.PolicyError) as raised:
        policy.resolve_destination("127.0.0.1", 5432)
    assert raised.value.code == "destination_forbidden"
    assert policy.resolve_destination("127.0.0.1", 5432, allow_loopback=True) == "127.0.0.1"
    assert policy.resolve_destination("10.1.2.3", 5432) == "10.1.2.3"
    for host in ("localhost", "LOCALHOST.", "ip6-localhost"):
        with pytest.raises(policy.PolicyError):
            policy.validate_host(host)
    for host in ("", "a b", "x" * 300, "-bad", "host/path", "user@host", "a..b"):
        with pytest.raises(policy.PolicyError):
            policy.validate_host(host)
    assert policy.validate_host("My-DB-x1y2.") == "my-db-x1y2"
    assert policy.validate_host("[fd12::1]") == "fd12::1"


def test_resolve_checks_every_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, port: int, **_kw: Any) -> list[Any]:
        return [(2, 1, 6, "", ("10.0.0.7", port)), (2, 1, 6, "", ("169.254.169.254", port))]

    monkeypatch.setattr(policy.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(policy.PolicyError) as raised:
        policy.resolve_destination("mixed.example", 5432)
    assert raised.value.code == "destination_forbidden"

    def fake_ok(host: str, port: int, **_kw: Any) -> list[Any]:
        return [(10, 1, 6, "", ("fd12::9", port, 0, 0)), (2, 1, 6, "", ("10.0.0.7", port))]

    monkeypatch.setattr(policy.socket, "getaddrinfo", fake_ok)
    assert policy.resolve_destination("db.example", 5432) == "10.0.0.7"

    def fake_fail(*_a: Any, **_kw: Any) -> list[Any]:
        raise OSError("nope")

    monkeypatch.setattr(policy.socket, "getaddrinfo", fake_fail)
    with pytest.raises(policy.PolicyError) as raised:
        policy.resolve_destination("missing.example", 5432)
    assert raised.value.code == "db_unresolvable"


def test_field_validation() -> None:
    assert policy.validate_database("redis", "3") == "3"
    for bad in ("x", "256", "-1"):
        with pytest.raises(policy.PolicyError):
            policy.validate_database("redis", bad)
    assert policy.validate_options("mongo", {"auth_source": "admin"}) == {"auth_source": "admin"}
    for engine, options in (("mongo", {"x": "1"}), ("postgres", {"application_name": "a;b"}),
                            ("redis", {"charset": "utf8"})):
        with pytest.raises(policy.PolicyError):
            policy.validate_options(engine, options)
    with pytest.raises(policy.PolicyError):
        policy.validate_tls("prefer")
    with pytest.raises(policy.PolicyError):
        policy.validate_port(70000)
    settings = policy.validate_settings({"max_rows": 5000, "bogus": 1}, strict=False)
    assert settings["max_rows"] == 1000
    with pytest.raises(policy.PolicyError):
        policy.validate_settings({"max_rows": 5000}, strict=True)
    with pytest.raises(policy.PolicyError):
        policy.validate_settings({"concurrency_per_connection": 3}, strict=True)


# ----- Redis / Mongo allowlists -------------------------------------------------------------


def test_redis_allowlist() -> None:
    assert policy.validate_redis("get", ["k"], write=False) == ("GET", ["k"])
    assert policy.validate_redis("SCAN", ["0"], write=False) == ("SCAN", ["0", "COUNT", "100"])
    assert policy.validate_redis("scan", ["0", "count", "99999"], write=False)[1][-1] == "1000"
    assert policy.validate_redis("XINFO", ["STREAM", "s"], write=False)[0] == "XINFO"
    for command in ("FLUSHALL", "FLUSHDB", "CONFIG", "EVAL", "EVALSHA", "SCRIPT", "MODULE",
                    "DEBUG", "SHUTDOWN", "KEYS", "MIGRATE", "SAVE", "BGSAVE", "REPLICAOF",
                    "SLAVEOF", "CLIENT", "ACL", "SORT", "FUNCTION", "MONITOR", "SUBSCRIBE",
                    "SELECT", "MULTI", "SWAPDB"):
        for write in (False, True):
            with pytest.raises(policy.PolicyError) as raised:
                policy.validate_redis(command, [], write=write)
            assert raised.value.code == "redis_command_denied", command
    for command in ("SET", "DEL", "EXPIRE", "HSET", "LPUSH"):
        with pytest.raises(policy.PolicyError) as raised:
            policy.validate_redis(command, ["k", "v"], write=False)
        assert raised.value.code == "read_only_violation"
        assert policy.validate_redis(command, ["k", "v"], write=True)[0] == command
    for bad_command in ("GET SET", "", "G3T", "x" * 40):
        with pytest.raises(policy.PolicyError):
            policy.validate_redis(bad_command, [], write=False)
    with pytest.raises(policy.PolicyError):
        policy.validate_redis("XINFO", ["HELP"], write=False)
    with pytest.raises(policy.PolicyError):
        policy.validate_redis("MGET", ["k"] * 300, write=False)
    with pytest.raises(policy.PolicyError):
        policy.validate_redis("GET", [{"a": 1}], write=False)


def test_mongo_allowlist() -> None:
    find = policy.validate_mongo({"collection": "users", "op": "find", "filter": {"a": 1},
                                  "sort": {"a": -1}, "limit": 5}, write=False)
    assert find.sort == [("a", -1)] and find.limit == 5
    agg = policy.validate_mongo({"collection": "users", "op": "aggregate",
                                 "pipeline": [{"$match": {}}, {"$group": {"_id": "$a"}}]},
                                write=False)
    assert len(agg.pipeline) == 2
    for stage in ({"$out": "x"}, {"$merge": {"into": "x"}}):
        with pytest.raises(policy.PolicyError) as raised:
            policy.validate_mongo({"collection": "c", "op": "aggregate",
                                   "pipeline": [{"$match": {}}, stage]}, write=True)
        assert raised.value.code == "mongo_operator_denied"
    # Nested inside $facet / $lookup pipelines too.
    with pytest.raises(policy.PolicyError):
        policy.validate_mongo({"collection": "c", "op": "aggregate", "pipeline": [
            {"$facet": {"a": [{"$out": "x"}]}}]}, write=False)
    with pytest.raises(policy.PolicyError):
        policy.validate_mongo({"collection": "c", "filter": {"$where": "sleep(1)"}}, write=False)
    with pytest.raises(policy.PolicyError) as raised:
        policy.validate_mongo({"collection": "c", "op": "delete_many", "filter": {"a": 1}},
                              write=False)
    assert raised.value.code == "read_only_violation"
    with pytest.raises(policy.PolicyError) as raised:
        policy.validate_mongo({"collection": "c", "op": "delete_many", "filter": {}}, write=True)
    assert raised.value.code == "mongo_filter_required"
    with pytest.raises(policy.PolicyError):
        policy.validate_mongo({"collection": "c", "op": "update_many", "filter": {"a": 1},
                               "update": {"b": 2}}, write=True)
    ok = policy.validate_mongo({"collection": "c", "op": "update_one", "filter": {"a": 1},
                                "update": {"$set": {"b": 2}}}, write=True)
    assert ok.update == {"$set": {"b": 2}}
    for op in ("drop", "rename", "createIndex", "command", "mapReduce"):
        with pytest.raises(policy.PolicyError):
            policy.validate_mongo({"collection": "c", "op": op}, write=True)
    for collection in ("", "system.users", "a$b", 5):
        with pytest.raises(policy.PolicyError):
            policy.validate_mongo({"collection": collection}, write=False)


def test_filters_sort_and_caps() -> None:
    columns = ["id", "name"]
    filters = policy.parse_filters(json.dumps([{"column": "id", "op": "gte", "value": 5},
                                               {"column": "name", "op": "in",
                                                "value": ["a", "b"]}]), columns)
    assert filters[0] == policy.Filter("id", "gte", "5")
    assert filters[1].value == ["a", "b"]
    for bad in ('[{"column": "nope", "op": "eq", "value": 1}]',
                '[{"column": "id", "op": "regex", "value": 1}]',
                '[{"column": "id", "op": "eq", "value": {"x": 1}}]',
                '[{"column": "id", "op": "in", "value": []}]', "not json"):
        with pytest.raises(policy.PolicyError):
            policy.parse_filters(bad, columns)
    assert policy.parse_sort("-id,name", columns) == [("id", True), ("name", False)]
    with pytest.raises(policy.PolicyError):
        policy.parse_sort("id; DROP", columns)
    builder = policy.ResultBuilder(max_rows=2, max_cell_bytes=10, max_response_bytes=10_000)
    assert builder.add(["x" * 50, b"\x00" * 50]) and builder.add([1, 2])
    assert not builder.add([3, 4])
    payload = builder.payload()
    assert payload["truncated_reason"] == "row_limit" and payload["truncated_cells"] == 2
    assert len(payload["rows"][0][0]) == 10 and payload["rows"][0][1]["truncated"] is True
    small = policy.ResultBuilder(max_rows=1000, max_cell_bytes=1000, max_response_bytes=100)
    while small.add(["y" * 30]):
        pass
    assert small.payload()["truncated_reason"] == "response_size"
    assert policy.cell(2**60, 100) == (str(2**60), False)
    assert policy.csv_cell("=cmd()", excel_safe=True) == "'=cmd()"
    assert policy.csv_cell(-5, excel_safe=True) == "-5"
    assert policy.csv_cell("=x", excel_safe=False) == "=x"


# ----- read-only enforcement against recording fakes ---------------------------------------------


class FakeColumn(NamedTuple):
    name: str
    type_code: int


class RecordingCursor:
    def __init__(self, conn: RecordingConn) -> None:
        self.conn = conn
        self.description: list[Any] | None = None
        self.rowcount = -1
        self.connection = conn
        self._rows: list[tuple[Any, ...]] = []

    def __enter__(self) -> RecordingCursor:
        return self

    def __exit__(self, *_exc: Any) -> None:
        return None

    def execute(self, query: Any, params: Any = None, **kwargs: Any) -> None:
        text = str(query)
        self.conn.log.append((text, params, kwargs))
        # Simulate the database: sqlite executes, honouring a read-only transaction.
        if self.conn.read_only and text.strip().upper().startswith(("UPDATE", "DELETE", "INSERT")):
            raise self.conn.read_only_error("cannot execute in a read-only transaction")
        if text.startswith(("SET", "START", "SELECT set_config")):
            self.description = None
            if "READ ONLY" in text.upper():
                self.conn.read_only = True
            return
        cursor = self.conn.sqlite.execute(text)
        self.description = cursor.description and [
            FakeColumn(d[0], 0) for d in cursor.description
        ]
        self._rows = cursor.fetchall()
        self.rowcount = cursor.rowcount

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        batch, self._rows = self._rows[:size], self._rows[size:]
        return batch


class RecordingConn:
    def __init__(self, read_only_error: type[Exception]) -> None:
        self.sqlite = sqlite3.connect(":memory:")
        self.sqlite.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")
        self.sqlite.executemany("INSERT INTO t VALUES (?, ?)", [(1, "a"), (2, "b"), (3, "c")])
        self.log: list[tuple[str, Any, dict[str, Any]]] = []
        self.read_only = False
        self.read_only_error = read_only_error
        self.committed = False
        self.rolled_back = False
        self.adapters = type("A", (), {"types": {}})()

    def cursor(self, *_a: Any, **_kw: Any) -> RecordingCursor:
        return RecordingCursor(self)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True
        self.read_only = False

    def close(self) -> None:
        self.closed = True

    def get_server_info(self) -> str:
        return "8.0.40"


def spec(engine: str = "postgres", **extra: Any) -> engines.ConnSpec:
    return engines.ConnSpec(id="0123456789abcdef", name="app", engine=engine, host="db",
                            port=5432, address="10.0.0.5", password=PASSWORD, **extra)


def test_postgres_read_mode_sequence(monkeypatch: pytest.MonkeyPatch) -> None:
    import psycopg

    conn = RecordingConn(psycopg.errors.ReadOnlySqlTransaction)
    captured: dict[str, Any] = {}

    def fake_connect(**kwargs: Any) -> RecordingConn:
        captured.update(kwargs)
        return conn

    monkeypatch.setattr(psycopg, "connect", fake_connect)
    adapter = engines.PostgresAdapter(spec(), engines.Limits(max_rows=2))
    result = adapter.query(engines.QueryRequest(text="SELECT id, name FROM t ORDER BY id"))
    statements = [entry[0] for entry in conn.log]
    assert statements[0] == "SET TRANSACTION READ ONLY"
    assert "statement_timeout" in statements[1]
    assert conn.log[2][2] == {"prepare": True}
    assert conn.rolled_back and not conn.committed
    assert result["rows"] == [[1, "a"], [2, "b"]] and result["truncated_reason"] == "row_limit"
    assert captured["hostaddr"] == "10.0.0.5" and captured["host"] == "db"
    assert "statement_timeout=15000" in captured["options"]
    assert captured["sslmode"] == "disable" and captured["password"] == PASSWORD
    # Write statements never reach the driver in read mode.
    conn.log.clear()
    with pytest.raises(sqltext.SqlError):
        adapter.query(engines.QueryRequest(text="DELETE FROM t"))
    assert conn.log == []
    # Dry run: executed, counted, rolled back.
    result = adapter.query(engines.QueryRequest(text="DELETE FROM t WHERE id > 1", write=True,
                                                dry_run=True))
    assert result["affected_rows"] == 2 and result["rolled_back"] and conn.rolled_back
    assert not conn.committed
    with pytest.raises(engines.EngineError) as raised:
        adapter.query(engines.QueryRequest(text="DROP TABLE t", write=True, dry_run=True))
    assert raised.value.code == "dry_run_unsupported"


def test_mysql_read_mode_sequence(monkeypatch: pytest.MonkeyPatch) -> None:
    import pymysql

    conn = RecordingConn(pymysql.err.InternalError)
    captured: dict[str, Any] = {}

    def fake_connect(**kwargs: Any) -> RecordingConn:
        captured.update(kwargs)
        return conn

    monkeypatch.setattr(pymysql, "connect", fake_connect)
    adapter = engines.MysqlAdapter(spec("mysql", database="app"), engines.Limits())
    result = adapter.query(engines.QueryRequest(text="SELECT id FROM t WHERE name = 'a'"))
    statements = [entry[0] for entry in conn.log]
    assert statements[0].startswith("SET SESSION max_execution_time")
    assert statements[1] == "START TRANSACTION READ ONLY"
    assert conn.log[2][1] is None  # no %-interpolation of user text
    assert result["rows"] == [[1]] and conn.rolled_back
    assert captured["local_infile"] is False and captured["client_flag"] == 0
    assert captured["host"] == "10.0.0.5"
    tls = engines.MysqlAdapter(spec("mysql", tls_mode="verify"), engines.Limits())
    tls.connect()
    assert captured["host"] == "db" and captured["ssl"].check_hostname


# ----- API --------------------------------------------------------------------------------------


class FakeAdapter:
    calls: list[tuple[str, Any]] = []
    last_spec: engines.ConnSpec | None = None

    def __init__(self, spec: engines.ConnSpec, limits: engines.Limits) -> None:
        FakeAdapter.last_spec = spec
        self.limits = limits

    def test(self) -> dict[str, Any]:
        FakeAdapter.calls.append(("test", None))
        return {"ok": True, "latency_ms": 1.0, "server_version": "16.4"}

    def schema(self) -> dict[str, Any]:
        return {"engine": "postgres", "namespace_kind": "schema",
                "namespaces": [{"name": "public", "tables": [
                    {"name": "t", "type": "table", "rows_estimate": 3, "size_bytes": 8192}]}],
                "users": [], "truncated": False}

    def table(self, schema: str | None, name: str, page: int, limit: int, sort: str | None,
              filter_raw: str | None) -> dict[str, Any]:
        FakeAdapter.calls.append(("table", (schema, name, page, limit, sort, filter_raw)))
        if name == "missing":
            raise engines.EngineError("table_not_found", "table not found", 404)
        return {"table": name, "rows": [[1, "secret-row-data"]], "page": page, "limit": limit}

    def query(self, request: engines.QueryRequest) -> dict[str, Any]:
        FakeAdapter.calls.append(("query", request))
        return {"columns": [{"name": "x"}], "rows": [["secret-row-data"]], "row_count": 1,
                "affected_rows": 2 if request.write else None, "mode": "write" if request.write
                else "read", "dry_run": request.dry_run}

    def export(self, *args: Any) -> Any:
        yield ["id", "name"]
        for index in range(5):
            yield [index, f"=row{index}"]


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setitem(engines.ADAPTERS, "postgres", FakeAdapter)
    monkeypatch.setitem(engines.ADAPTERS, "redis", FakeAdapter)
    monkeypatch.setitem(engines.ADAPTERS, "mongo", FakeAdapter)
    FakeAdapter.calls = []
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as test_client:
        yield test_client


def owner(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}


def login_as(client: TestClient, owner_csrf: str, role: str) -> dict[str, str]:
    username, password = f"{role}1", f"a-long-{role}-password-123"
    created = client.post("/api/v1/users", headers={"X-CSRF-Token": owner_csrf},
                          json={"username": username, "password": password, "role": role})
    assert created.status_code == 201, created.text
    session = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    return {"X-CSRF-Token": str(session.json()["csrf_token"])}


def create(client: TestClient, headers: dict[str, str], **extra: Any) -> Any:
    body = {"name": "app", "engine": "postgres", "host": "10.0.0.5", "database": "app",
            "username": "app", "password": PASSWORD, **extra}
    return client.post(f"{API}/connections", headers=headers, json=body)


def audit_actions(client: TestClient) -> list[dict[str, Any]]:
    return client.get("/api/v1/audit-events", params={"limit": 500}).json()["items"]


def test_connection_crud_never_returns_secret(client: TestClient, caplog: Any,
                                              tmp_path: Path) -> None:
    caplog.set_level(logging.DEBUG)
    headers = owner(client)
    created = create(client, headers)
    assert created.status_code == 201, created.text
    item = created.json()
    assert item["password_configured"] is True and item["port"] == 5432
    secrets_file = tmp_path / "cp" / "control-plane" / "upstream-secrets.json"
    stored = len(json.loads(secrets_file.read_text(encoding="utf-8"))["items"])
    assert item["write_confirmation"] == "WRITE app"
    assert "POSTGRES_PASSWORD" in item["env_hints"]
    assert PASSWORD not in created.text
    assert create(client, headers).status_code == 409
    listed = client.get(f"{API}/connections")
    assert listed.status_code == 200 and PASSWORD not in listed.text
    assert client.get(f"{API}/connections/{item['id']}").json()["name"] == "app"
    # Changing the host keeps the password only when it is typed again.
    moved = client.patch(f"{API}/connections/{item['id']}", headers=headers,
                         json={"host": "10.0.0.6"})
    assert moved.status_code == 422 and moved.json()["error"]["code"] == "password_required"
    weaker = client.patch(f"{API}/connections/{item['id']}", headers=headers,
                          json={"tls_mode": "require"})
    assert weaker.status_code == 200
    downgraded = client.patch(f"{API}/connections/{item['id']}", headers=headers,
                              json={"tls_mode": "disable"})
    assert downgraded.json()["error"]["code"] == "password_required"
    renamed = client.patch(f"{API}/connections/{item['id']}", headers=headers,
                           json={"name": "app2", "host": "10.0.0.6", "password": "new-pass-1"})
    assert renamed.status_code == 200 and renamed.json()["write_confirmation"] == "WRITE app2"
    cleared = client.patch(f"{API}/connections/{item['id']}", headers=headers,
                           json={"clear_password": True})
    assert cleared.json()["password_configured"] is False
    for bad in ({"host": "127.0.0.1"}, {"engine": "oracle"}, {"host": "localhost"},
                {"port": 0}, {"tls_mode": "maybe"}, {"options": {"evil": "1"}}):
        response = client.patch(f"{API}/connections/{item['id']}", headers=headers, json=bad)
        if "host" in bad and bad["host"] == "127.0.0.1":
            # Literal loopback passes validation but is refused when connecting.
            assert response.status_code == 200
        else:
            assert response.status_code == 422, bad
    refused = client.post(f"{API}/connections/{item['id']}/test", headers=headers)
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "destination_forbidden"
    assert client.request("DELETE", f"{API}/connections/{item['id']}", headers=headers,
                          json={"confirmation": "wrong"}).status_code == 422
    deleted = client.request("DELETE", f"{API}/connections/{item['id']}", headers=headers,
                             json={"confirmation": "app2"})
    assert deleted.status_code == 200
    assert client.get(f"{API}/connections").json()["items"] == []
    assert PASSWORD not in secrets_file.read_text(encoding="utf-8")
    assert len(json.loads(secrets_file.read_text(encoding="utf-8"))["items"]) == stored - 1
    assert PASSWORD not in caplog.text and "new-pass-1" not in caplog.text
    actions = {event["action"] for event in audit_actions(client)}
    assert {"dbadmin.connection.create", "dbadmin.connection.update",
            "dbadmin.connection.delete"} <= actions


def test_browse_query_and_write_mode(client: TestClient, caplog: Any) -> None:
    caplog.set_level(logging.DEBUG)
    headers = owner(client)
    connection = create(client, headers).json()
    base = f"{API}/connections/{connection['id']}"
    tested = client.post(f"{base}/test", headers=headers)
    assert tested.status_code == 200 and tested.json()["ok"] is True
    assert FakeAdapter.last_spec is not None and FakeAdapter.last_spec.password == PASSWORD
    assert FakeAdapter.last_spec.address == "10.0.0.5"
    assert client.get(f"{API}/connections/{connection['id']}").json()["last_test_ok"] is True
    assert client.get(f"{base}/schema").json()["namespaces"][0]["name"] == "public"
    page = client.get(f"{base}/tables/t", params={"schema": "public", "page": 2, "limit": 10,
                                                  "sort": "-id"})
    assert page.status_code == 200 and FakeAdapter.calls[-1][1][:5] == (
        "public", "t", 2, 10, "-id")
    assert client.get(f"{base}/tables/t", params={"limit": 501}).status_code == 422
    assert client.get(f"{base}/tables/missing").status_code == 404

    read = client.post(f"{base}/query", headers=headers, json={"text": "SELECT 1"})
    assert read.status_code == 200 and read.json()["mode"] == "read"
    assert len(read.json()["statement_sha256"]) == 64
    multi = client.post(f"{base}/query", headers=headers, json={"text": "SELECT 1; SELECT 2"})
    assert multi.json()["error"]["code"] == "sql_multiple_statements"
    blocked = client.post(f"{base}/query", headers=headers, json={"text": "DELETE FROM t"})
    assert blocked.json()["error"]["code"] == "read_only_violation"
    no_confirm = client.post(f"{base}/query", headers=headers,
                             json={"text": "DELETE FROM t", "write": True})
    assert no_confirm.json()["error"]["code"] == "confirmation_required"
    wrong = client.post(f"{base}/query", headers=headers,
                        json={"text": "DELETE FROM t", "write": True, "confirmation": "WRITE x"})
    assert wrong.json()["error"]["code"] == "confirmation_required"
    dry_alone = client.post(f"{base}/query", headers=headers,
                            json={"text": "DELETE FROM t", "dry_run": True})
    assert dry_alone.json()["error"]["code"] == "write_required"
    dry = client.post(f"{base}/query", headers=headers,
                      json={"text": "DELETE FROM t WHERE id = 7", "write": True,
                            "dry_run": True, "confirmation": "WRITE app"})
    assert dry.status_code == 200 and dry.json()["dry_run"] is True
    write_text = "DELETE FROM t WHERE name = 'secret-statement'"
    done = client.post(f"{base}/query", headers=headers,
                       json={"text": write_text, "write": True, "confirmation": "WRITE app"})
    assert done.status_code == 200 and done.json()["affected_rows"] == 2
    wrong_shape = client.post(f"{base}/query", headers=headers,
                              json={"redis": {"command": "GET", "args": ["k"]}})
    assert wrong_shape.json()["error"]["code"] == "query_invalid"

    events = audit_actions(client)
    by_action = {event["action"]: event for event in events}
    write_event = by_action["dbadmin.query.write"]
    digest = sqltext.statement_hash(write_text)
    assert write_event["object_id"] == f"{connection['id']}:{digest}"
    assert "dbadmin.query.read" in by_action and "dbadmin.query.dry_run" in by_action
    dumped = json.dumps(events)
    assert "secret-statement" not in dumped and "secret-row-data" not in dumped
    assert "secret-statement" not in caplog.text and "secret-row-data" not in caplog.text


def test_export_streams_csv(client: TestClient) -> None:
    headers = owner(client)
    connection = create(client, headers).json()
    base = f"{API}/connections/{connection['id']}"
    response = client.post(f"{base}/export", headers=headers,
                           json={"table": {"name": "t", "schema": "public"}})
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    lines = response.text.strip().split("\r\n")
    assert lines[0] == "id,name" and lines[1] == "0,'=row0" and len(lines) == 6
    raw = client.post(f"{base}/export", headers=headers,
                      json={"text": "SELECT 1", "excel_safe": False})
    assert "=row0" in raw.text and "'=row0" not in raw.text
    assert client.post(f"{base}/export", headers=headers,
                       json={"text": "DELETE FROM t"}).json()["error"]["code"] == (
        "read_only_violation")
    assert client.post(f"{base}/export", headers=headers, json={}).status_code == 422
    assert "dbadmin.export" in {event["action"] for event in audit_actions(client)}


def test_settings_discover_and_network_guide(client: TestClient,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    headers = owner(client)
    assert client.get(f"{API}/settings").json()["max_rows"] == 1000
    updated = client.put(f"{API}/settings", headers=headers, json={"export_max_rows": 10})
    assert updated.status_code == 200 and updated.json()["export_max_rows"] == 10
    assert client.put(f"{API}/settings", headers=headers,
                      json={"max_rows": 100000}).status_code == 422
    guide = client.get(f"{API}/network-guide").json()
    assert guide["network"] == "dokploy-network"
    assert "external: true" in guide["compose_snippet"]

    class FakeDokploy:
        async def call(self, procedure: str, **_kw: Any) -> Any:
            assert procedure == "project.all"
            return [{"projectId": "p1", "name": "shop", "environments": [{
                "name": "production",
                "postgres": [{"postgresId": "x", "name": "Shop DB", "appName": "shop-db-a1b2",
                              "databaseName": "shop", "databaseUser": "shop",
                              "databasePassword": "dokploy-secret-pw",
                              "applicationStatus": "done"}],
                "redis": [{"redisId": "r", "name": "cache", "appName": "shop-cache",
                           "databasePassword": "dokploy-redis-pw"}],
            }]}]

    from mrk_control_plane.modules import dokploy, host_agent

    monkeypatch.setattr(dokploy, "ACTIVE_SERVICE", FakeDokploy())

    async def fake_agent_call(self: Any, path: str) -> Any:
        assert path == "/v1/backup/sources"
        return {"databases": [{"container_id": "c" * 64, "name": "legacy-mysql",
                               "image": "mysql:8", "engine": "mysql", "state": "running",
                               "protected": False}]}

    monkeypatch.setattr(host_agent.HostAgentService, "call", fake_agent_call)
    found = client.get(f"{API}/discover")
    assert found.status_code == 200
    text = found.text
    assert "dokploy-secret-pw" not in text and "dokploy-redis-pw" not in text
    payload = found.json()
    pg = payload["dokploy"]["items"][0]
    assert (pg["host"], pg["port"], pg["database"], pg["username"]) == (
        "shop-db-a1b2", 5432, "shop", "shop")
    assert payload["dokploy"]["items"][1]["port"] == 6379
    agent = payload["agent"]["items"][0]
    assert agent["host"] == "legacy-mysql" and agent["port"] == 3306
    assert "MYSQL_ROOT_PASSWORD" in agent["env_hints"]


def test_rbac_and_csrf(client: TestClient) -> None:
    owner_headers = owner(client)
    connection = create(client, owner_headers).json()
    base = f"{API}/connections/{connection['id']}"
    # CSRF is required on every mutation, including read queries (POST).
    no_csrf = {"X-CSRF-Token": "bogus"}
    assert client.post(f"{base}/query", headers=no_csrf, json={"text": "SELECT 1"}
                       ).status_code == 403
    assert client.post(f"{base}/test", headers=no_csrf).status_code == 403
    assert client.post(f"{base}/export", headers=no_csrf, json={"text": "SELECT 1"}
                       ).status_code == 403
    assert create(client, no_csrf, name="other").status_code == 403
    for role in ("viewer", "operator", "developer"):
        headers = login_as(client, owner_headers["X-CSRF-Token"], role)
        assert client.get(f"{API}/connections").status_code == 403
        assert client.get(f"{base}/schema").status_code == 403
        assert client.get(f"{API}/discover").status_code == 403
        assert client.post(f"{base}/query", headers=headers, json={"text": "SELECT 1"}
                           ).status_code == 403
        assert create(client, headers, name=f"by-{role}").status_code == 403
        client.post("/api/v1/auth/logout", headers=headers)
        owner_headers = owner(client)
    admin = login_as(client, owner_headers["X-CSRF-Token"], "admin")
    assert client.get(f"{API}/connections").status_code == 200
    assert client.post(f"{base}/query", headers=admin, json={"text": "SELECT 1"}
                       ).status_code == 200


def test_migration_on_fresh_sqlite(tmp_path: Path) -> None:
    database = Database(tmp_path)
    database.initialize()
    inspector = inspect(database.engine)
    assert "dbadmin_connections" in inspector.get_table_names()
    columns = {column["name"] for column in inspector.get_columns("dbadmin_connections")}
    assert {"secret_ref", "engine", "tls_mode", "options"} <= columns
    assert "password" not in columns
    with database.engine.connect() as connection:
        version = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
    # The dbadmin revision must be applied; later revisions may sit on top of it.
    assert version >= "20261108_0010"


def test_module_registered() -> None:
    from mrk_control_plane.modules import MODULES, _load

    if not MODULES:
        _load()
    assert "dbadmin" in [name for name, _ in MODULES]
    assert dbadmin.write_confirmation("x") == "WRITE x"
