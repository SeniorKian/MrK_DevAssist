"""dbadmin against real throwaway databases (Docker).

Opt-in: ``MRK_DBADMIN_DOCKER_TESTS=1``. Starts postgres:16-alpine, mysql:8, mongo:7 and
redis:7 with random names on random 127.0.0.1 ports, and removes them afterwards.
"""
# ruff: noqa: S603, S607, S110, S608 - test-only Docker helpers and fixed SQL

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import dbadmin
from mrk_control_plane.modules import dbadmin_engines as engines

from .helpers import login_owner

pytestmark = pytest.mark.skipif(
    os.getenv("MRK_DBADMIN_DOCKER_TESTS") != "1" or shutil.which("docker") is None,
    reason="set MRK_DBADMIN_DOCKER_TESTS=1 (needs Docker) to run",
)
API = "/api/v1/dbadmin"
PASSWORD = "It-Pa55-" + secrets.token_hex(6)
CONTAINERS = {
    "postgres": ("postgres:16-alpine", 5432, ["-e", f"POSTGRES_PASSWORD={PASSWORD}"], []),
    "mysql": ("mysql:8", 3306, ["-e", f"MYSQL_ROOT_PASSWORD={PASSWORD}",
                                "-e", "MYSQL_DATABASE=app"], []),
    "mongo": ("mongo:7", 27017, ["-e", "MONGO_INITDB_ROOT_USERNAME=root",
                                 "-e", f"MONGO_INITDB_ROOT_PASSWORD={PASSWORD}"], []),
    "redis": ("redis:7", 6379, [], ["redis-server", "--requirepass", PASSWORD]),
}
USERS = {"postgres": "postgres", "mysql": "root", "mongo": "root", "redis": None}
DATABASES = {"postgres": "postgres", "mysql": "app", "mongo": "app", "redis": None}


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True,
                          timeout=120).stdout.strip()


@pytest.fixture(scope="module")
def ports() -> Iterator[dict[str, int]]:
    suffix = secrets.token_hex(4)
    names: list[str] = []
    found: dict[str, int] = {}
    try:
        for engine, (image, port, env, command) in CONTAINERS.items():
            name = f"mrk-dbtest-{engine}-{suffix}"
            _docker("run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1::{port}", *env,
                    image, *command)
            names.append(name)
            mapped = _docker("port", name, f"{port}/tcp").splitlines()[0]
            found[engine] = int(mapped.rsplit(":", 1)[1])
        deadline = time.time() + 180
        pending = set(found)
        while pending and time.time() < deadline:
            for engine in list(pending):
                spec = engines.ConnSpec(
                    id="0" * 16, name="probe", engine=engine, host="127.0.0.1",
                    port=found[engine], address="127.0.0.1", username=USERS[engine],
                    password=PASSWORD, database=DATABASES[engine], connect_timeout=2,
                )
                try:
                    engines.adapter_for(spec, engines.Limits()).test()
                    pending.discard(engine)
                except Exception:  # noqa: BLE001 - still starting
                    pass
            time.sleep(1)
        if pending:
            pytest.fail(f"containers not ready: {sorted(pending)}")
        yield found
    finally:
        for name in names:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


@pytest.fixture(scope="module")
def client(ports: dict[str, int], tmp_path_factory: pytest.TempPathFactory) -> Iterator[Any]:
    app = create_app(Settings.for_test(Path(tmp_path_factory.mktemp("dbadmin")) / "cp"))
    with TestClient(app) as test_client:
        assert dbadmin.ACTIVE_SERVICE is not None
        dbadmin.ACTIVE_SERVICE.allow_loopback = True
        test_client.headers.update({"X-CSRF-Token": str(login_owner(test_client)["csrf_token"])})
        ids = {}
        for engine, port in ports.items():
            created = test_client.post(f"{API}/connections", json={
                "name": engine, "engine": engine, "host": "127.0.0.1", "port": port,
                "username": USERS[engine], "password": PASSWORD, "database": DATABASES[engine],
            })
            assert created.status_code == 201, created.text
            ids[engine] = created.json()["id"]
        test_client.ids = ids  # type: ignore[attr-defined]
        yield test_client


def q(client: Any, engine: str, body: dict[str, Any]) -> Any:
    return client.post(f"{API}/connections/{client.ids[engine]}/query", json=body)


def w(client: Any, engine: str, body: dict[str, Any], dry_run: bool = False) -> Any:
    return q(client, engine, {**body, "write": True, "dry_run": dry_run,
                              "confirmation": f"WRITE {engine}"})


def test_loopback_refused_without_test_override(client: Any) -> None:
    assert dbadmin.ACTIVE_SERVICE is not None
    dbadmin.ACTIVE_SERVICE.allow_loopback = False
    try:
        response = client.post(f"{API}/connections/{client.ids['postgres']}/test")
        assert response.json()["error"]["code"] == "destination_forbidden"
    finally:
        dbadmin.ACTIVE_SERVICE.allow_loopback = True


@pytest.mark.parametrize("engine", ["postgres", "mysql"])
def test_sql_engines(client: Any, engine: str) -> None:
    base = f"{API}/connections/{client.ids[engine]}"
    assert client.post(f"{base}/test").json()["ok"] is True
    created = w(client, engine, {"text": "CREATE TABLE items (id INT PRIMARY KEY, name "
                                         "VARCHAR(40), note TEXT)"})
    assert created.status_code == 200, created.text
    for index in range(30):
        inserted = w(client, engine, {"text": f"INSERT INTO items VALUES ({index}, "
                                              f"'item-{index}', 'n;{index}')"})
        assert inserted.status_code == 200, inserted.text
    read = q(client, engine, {"text": "SELECT id, name FROM items WHERE note LIKE 'n;%' "
                                      "ORDER BY id"})
    assert read.status_code == 200 and read.json()["row_count"] == 30
    # Read mode: the database itself refuses writes hidden in a read statement.
    if engine == "postgres":
        hidden = q(client, engine, {"text": "WITH d AS (DELETE FROM items RETURNING *) "
                                            "SELECT count(*) FROM d"})
        assert hidden.json()["error"]["code"] == "read_only_violation", hidden.text
    else:
        hidden = q(client, engine, {"text": "SELECT * FROM items FOR UPDATE"})
        assert hidden.status_code in {200, 422}
    assert q(client, engine, {"text": "UPDATE items SET name = 'x'"}).json()["error"][
        "code"] == "read_only_violation"
    multi = q(client, engine, {"text": "SELECT 1; DELETE FROM items"})
    assert multi.json()["error"]["code"] == "sql_multiple_statements"
    # Dry run counts and rolls back.
    dry = w(client, engine, {"text": "DELETE FROM items WHERE id >= 20"}, dry_run=True)
    assert dry.status_code == 200 and dry.json()["affected_rows"] == 10, dry.text
    count = q(client, engine, {"text": "SELECT count(*) AS n FROM items"}).json()
    assert int(count["rows"][0][0]) == 30
    done = w(client, engine, {"text": "DELETE FROM items WHERE id >= 25"})
    assert done.json()["affected_rows"] == 5
    # Browse.
    schema = client.get(f"{base}/schema").json()
    tables = {t["name"] for ns in schema["namespaces"] for t in ns["tables"]}
    assert "items" in tables
    namespace = "public" if engine == "postgres" else "app"
    page = client.get(f"{base}/tables/items", params={
        "schema": namespace, "page": 2, "limit": 10, "sort": "-id",
        "filter": '[{"column": "id", "op": "lt", "value": "100"}]'})
    assert page.status_code == 200, page.text
    body = page.json()
    assert body["primary_key"] == ["id"] and body["has_more"] is True
    assert [row[0] for row in body["rows"]][:2] == [14, 13]
    assert {c["name"] for c in body["columns"]} == {"id", "name", "note"}
    filtered = client.get(f"{base}/tables/items", params={
        "schema": namespace, "filter": '[{"column": "name", "op": "in", '
                                       '"value": ["item-1", "item-2"]}]'}).json()
    assert filtered["row_count"] == 2
    injected = client.get(f"{base}/tables/items", params={
        "schema": namespace, "sort": "id; DROP TABLE items"})
    assert injected.status_code == 422
    assert client.get(f"{base}/tables/nope", params={"schema": namespace}).status_code == 404
    # Export.
    csv_response = client.post(f"{base}/export", json={
        "table": {"name": "items", "schema": namespace, "sort": "id"}})
    assert csv_response.status_code == 200
    lines = csv_response.text.strip().split("\r\n")
    assert lines[0] == "id,name,note" and len(lines) == 26
    exported = client.post(f"{base}/export", json={"text": "SELECT id FROM items ORDER BY id",
                                                   "max_rows": 3})
    assert exported.text.strip().split("\r\n") == ["id", "0", "1", "2"]


def test_postgres_timeout_and_driver_guard(client: Any) -> None:
    assert client.put(f"{API}/settings", json={"statement_timeout_ms": 1000}).status_code == 200
    try:
        slow = q(client, "postgres", {"text": "SELECT pg_sleep(5)"})
        assert slow.status_code == 504 and slow.json()["error"]["code"] == "db_timeout"
    finally:
        client.put(f"{API}/settings", json={"statement_timeout_ms": 15000})
    # Even if the tokenizer were bypassed, the extended protocol refuses two statements.
    spec = dbadmin.ACTIVE_SERVICE.spec(client.ids["postgres"])  # type: ignore[union-attr]
    spec.address = "127.0.0.1"
    adapter = engines.PostgresAdapter(spec, engines.Limits())
    conn = adapter.connect()
    try:
        with pytest.raises(Exception, match="multiple commands"):
            conn.execute("SELECT 1; SELECT 2", prepare=True)
    finally:
        conn.close()


def test_mongo(client: Any) -> None:
    docs = [{"n": index, "tag": "even" if index % 2 == 0 else "odd"} for index in range(20)]
    inserted = w(client, "mongo", {"mongo": {"collection": "things", "op": "insert_many",
                                             "documents": docs}})
    assert inserted.status_code == 200 and inserted.json()["affected_rows"] == 20, inserted.text
    found = q(client, "mongo", {"mongo": {"collection": "things", "filter": {"tag": "even"},
                                          "sort": {"n": -1}, "limit": 3}}).json()
    n_index = [c["name"] for c in found["columns"]].index("n")
    assert [row[n_index] for row in found["rows"]] == [18, 16, 14]
    grouped = q(client, "mongo", {"mongo": {"collection": "things", "op": "aggregate",
                                            "pipeline": [{"$group": {"_id": "$tag",
                                                                     "c": {"$sum": 1}}}]}})
    assert grouped.json()["row_count"] == 2
    out = q(client, "mongo", {"mongo": {"collection": "things", "op": "aggregate",
                                        "pipeline": [{"$out": "copy"}]}})
    assert out.json()["error"]["code"] == "mongo_operator_denied"
    denied = q(client, "mongo", {"mongo": {"collection": "things", "op": "delete_many",
                                           "filter": {"tag": "odd"}}})
    assert denied.json()["error"]["code"] == "read_only_violation"
    dry = w(client, "mongo", {"mongo": {"collection": "things", "op": "delete_many",
                                        "filter": {"tag": "odd"}}}, dry_run=True)
    assert dry.json()["affected_rows"] == 10
    done = w(client, "mongo", {"mongo": {"collection": "things", "op": "update_many",
                                         "filter": {"tag": "odd"},
                                         "update": {"$set": {"seen": True}}}})
    assert done.json()["affected_rows"] == 10
    base = f"{API}/connections/{client.ids['mongo']}"
    schema = client.get(f"{base}/schema").json()
    assert any(t["name"] == "things" and t["rows_estimate"] == 20
               for ns in schema["namespaces"] for t in ns["tables"])
    page = client.get(f"{base}/tables/things", params={
        "schema": "app", "limit": 5, "sort": "n",
        "filter": '[{"column": "n", "op": "gte", "value": 10}]'}).json()
    assert page["row_count"] == 5 and page["has_more"] is True
    exported = client.post(f"{base}/export", json={"table": {"name": "things", "schema": "app",
                                                             "sort": "n"}})
    assert exported.status_code == 200 and len(exported.text.strip().split("\r\n")) == 21


def test_redis(client: Any) -> None:
    assert w(client, "redis", {"redis": {"command": "SET", "args": ["greeting", "hello"]}}
             ).status_code == 200
    got = q(client, "redis", {"redis": {"command": "GET", "args": ["greeting"]}}).json()
    assert got["rows"] == [["hello"]]
    blocked = q(client, "redis", {"redis": {"command": "SET", "args": ["x", "y"]}})
    assert blocked.json()["error"]["code"] == "read_only_violation"
    flush = w(client, "redis", {"redis": {"command": "FLUSHALL"}})
    assert flush.json()["error"]["code"] == "redis_command_denied"
    scan = q(client, "redis", {"redis": {"command": "SCAN", "args": ["0"]}}).json()
    assert ["greeting"] in scan["rows"] and "cursor" in scan
    info = q(client, "redis", {"redis": {"command": "INFO", "args": ["server"]}}).json()
    assert info["row_count"] > 0
    schema = client.get(f"{API}/connections/{client.ids['redis']}/schema").json()
    assert schema["namespaces"][0]["keys"] >= 1
