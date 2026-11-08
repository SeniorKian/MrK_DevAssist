"""Validation, destination policy, allowlists and result caps for ``dbadmin``.

Pure functions only (no driver imports) so they are easy to test.
"""

from __future__ import annotations

import base64
import datetime as dt
import decimal
import ipaddress
import json
import math
import re
import socket
import uuid
from dataclasses import dataclass, field
from typing import Any

ENGINES = ("postgres", "mysql", "mariadb", "mongo", "redis")
DEFAULT_PORTS = {"postgres": 5432, "mysql": 3306, "mariadb": 3306, "mongo": 27017, "redis": 6379}
TLS_MODES = ("disable", "require", "verify")
# Environment variables in the database container that hold the credentials;
# shown as guidance only, MRK never reads them.
ENV_HINTS: dict[str, list[str]] = {
    "postgres": ["POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB"],
    "mysql": ["MYSQL_USER", "MYSQL_PASSWORD", "MYSQL_DATABASE", "MYSQL_ROOT_PASSWORD"],
    "mariadb": [
        "MARIADB_USER", "MARIADB_PASSWORD", "MARIADB_DATABASE", "MARIADB_ROOT_PASSWORD",
        "MYSQL_USER", "MYSQL_PASSWORD", "MYSQL_DATABASE", "MYSQL_ROOT_PASSWORD",
    ],
    "mongo": [
        "MONGO_INITDB_ROOT_USERNAME", "MONGO_INITDB_ROOT_PASSWORD", "MONGO_INITDB_DATABASE",
    ],
    "redis": ["REDIS_PASSWORD", "--requirepass (container command)"],
}
OPTION_KEYS: dict[str, dict[str, re.Pattern[str]]] = {
    "postgres": {"application_name": re.compile(r"^[A-Za-z0-9 _.-]{1,63}$")},
    "mysql": {"charset": re.compile(r"^[A-Za-z0-9_]{1,32}$")},
    "mariadb": {"charset": re.compile(r"^[A-Za-z0-9_]{1,32}$")},
    "mongo": {"auth_source": re.compile(r"^[A-Za-z0-9_.-]{1,64}$")},
    "redis": {},
}
_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*\.?$"
)
_DATABASE = re.compile(r"^[^\x00-\x1f\x7f/\\]{1,128}$")
_USERNAME = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)
LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})


class PolicyError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


# --- connection fields ---------------------------------------------------------------


def validate_name(value: object) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if not _NAME.fullmatch(text):
        raise PolicyError("invalid_name", "name must be 1-80 printable characters")
    return text


def validate_engine(value: object) -> str:
    if value not in ENGINES:
        raise PolicyError("invalid_engine", f"engine must be one of {', '.join(ENGINES)}")
    return str(value)


def validate_host(value: object) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if not _HOST.fullmatch(text):
        raise PolicyError("invalid_host", "host must be a DNS name or an IP address")
    if text.lower().rstrip(".") in LOOPBACK_NAMES:
        raise PolicyError("destination_forbidden", "loopback destinations are not allowed")
    return text.rstrip(".").lower()


def validate_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise PolicyError("invalid_port", "port must be between 1 and 65535")
    return value


def validate_database(engine: str, value: object) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise PolicyError("invalid_database", "database must be text")
    if engine == "redis":
        if not value.isdigit() or not 0 <= int(value) <= 255:
            raise PolicyError("invalid_database", "redis database must be a number 0-255")
        return str(int(value))
    if not _DATABASE.fullmatch(value):
        raise PolicyError("invalid_database", "database name is invalid")
    return value


def validate_username(value: object) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not _USERNAME.fullmatch(value):
        raise PolicyError("invalid_username", "username is invalid")
    return value


def validate_password(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\x00" in value:
        raise PolicyError("invalid_password", "password must be 1-1024 characters")
    return value


def validate_tls(value: object) -> str:
    if value in (None, ""):
        return "disable"
    if value not in TLS_MODES:
        raise PolicyError("invalid_tls_mode", f"tls_mode must be one of {', '.join(TLS_MODES)}")
    return str(value)


def validate_options(engine: str, value: object) -> dict[str, str]:
    if value in (None, {}):
        return {}
    if not isinstance(value, dict):
        raise PolicyError("invalid_options", "options must be an object")
    allowed = OPTION_KEYS[engine]
    result: dict[str, str] = {}
    for key, item in value.items():
        pattern = allowed.get(key)
        if pattern is None:
            raise PolicyError("invalid_options", f"unknown option for {engine}: {key}")
        if not isinstance(item, str) or not pattern.fullmatch(item):
            raise PolicyError("invalid_options", f"option {key} is invalid")
        result[key] = item
    return result


# --- destination policy ----------------------------------------------------------------


def address_allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return a refusal reason, or None when a database may live at ``address``.

    Private/LAN and public addresses are allowed (it is a database admin tool);
    loopback (this appliance itself, PGlite), link-local/cloud metadata,
    unspecified, multicast and reserved ranges are not.
    """
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped or address.sixtofour
        if mapped is not None:
            return address_allowed(mapped)
    if address in METADATA_ADDRESSES:
        return "cloud metadata endpoints are not allowed"
    if address.is_loopback:
        return "loopback destinations are not allowed"
    if address.is_link_local:
        return "link-local destinations are not allowed"
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        return "this address range is not allowed"
    if isinstance(address, ipaddress.IPv4Address) and address == ipaddress.IPv4Address(
        "255.255.255.255"
    ):
        return "this address range is not allowed"
    return None


def resolve_destination(host: str, port: int, *, allow_loopback: bool = False) -> str:
    """Resolve once and check every answer; return the address to connect to.

    Connecting to the returned address (not the name) prevents a DNS answer
    from changing between the check and the connection.
    """
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        candidates = [literal]
    else:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except (OSError, UnicodeError) as exc:
            raise PolicyError("db_unresolvable", f"host {host} could not be resolved", 502) from exc
        candidates = []
        for info in infos:
            try:
                candidate = ipaddress.ip_address(info[4][0].split("%", 1)[0])
            except ValueError:
                continue
            if candidate not in candidates:
                candidates.append(candidate)
        if not candidates:
            raise PolicyError("db_unresolvable", f"host {host} could not be resolved", 502)
    for candidate in candidates:
        reason = address_allowed(candidate)
        if reason and not (allow_loopback and candidate.is_loopback):
            raise PolicyError("destination_forbidden", reason)
    preferred = sorted(candidates, key=lambda item: item.version)
    return str(preferred[0])


# --- settings -----------------------------------------------------------------------------

SETTINGS_LIMITS: dict[str, tuple[int, int, int]] = {
    # key: (default, low, high)
    "connect_timeout_seconds": (5, 1, 60),
    "statement_timeout_ms": (15000, 100, 600000),
    "max_rows": (1000, 1, 1000),
    "max_cell_bytes": (65536, 256, 1048576),
    "max_response_bytes": (5 * 1024 * 1024, 65536, 5 * 1024 * 1024),
    "export_max_rows": (100000, 1, 5000000),
    "export_max_bytes": (100 * 1024 * 1024, 1024 * 1024, 2 * 1024 * 1024 * 1024),
    "export_statement_timeout_ms": (300000, 1000, 3600000),
    "concurrency_per_connection": (2, 1, 2),
}


def default_settings() -> dict[str, int]:
    return {key: spec[0] for key, spec in SETTINGS_LIMITS.items()}


def validate_settings(raw: object, *, strict: bool) -> dict[str, int]:
    result = default_settings()
    if not isinstance(raw, dict):
        if strict:
            raise PolicyError("invalid_settings", "settings must be an object")
        return result
    for key, value in raw.items():
        spec = SETTINGS_LIMITS.get(key)
        if spec is None:
            if strict:
                raise PolicyError("invalid_settings", f"unknown setting {key}")
            continue
        _default, low, high = spec
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            if strict:
                raise PolicyError("invalid_settings", f"{key} must be between {low} and {high}")
            continue
        result[key] = value
    return result


# --- Redis ------------------------------------------------------------------------------

REDIS_READ_COMMANDS = frozenset(
    {
        "GET", "MGET", "STRLEN", "GETRANGE", "EXISTS", "TYPE", "TTL", "PTTL", "EXPIRETIME",
        "HGET", "HMGET", "HGETALL", "HKEYS", "HVALS", "HLEN", "HEXISTS", "HSTRLEN", "HSCAN",
        "LRANGE", "LLEN", "LINDEX", "LPOS",
        "SMEMBERS", "SCARD", "SISMEMBER", "SMISMEMBER", "SSCAN", "SRANDMEMBER",
        "ZRANGE", "ZRANGEBYSCORE", "ZRANGEBYLEX", "ZREVRANGE", "ZREVRANGEBYSCORE", "ZCARD",
        "ZSCORE", "ZMSCORE", "ZRANK", "ZREVRANK", "ZCOUNT", "ZSCAN",
        "XRANGE", "XREVRANGE", "XLEN", "XINFO",
        "SCAN", "INFO", "DBSIZE", "PING", "MEMORY", "OBJECT", "PFCOUNT", "BITCOUNT", "GETBIT",
    }
)
REDIS_WRITE_COMMANDS = frozenset(
    {
        "SET", "DEL", "UNLINK", "EXPIRE", "PEXPIRE", "PERSIST", "HSET", "HDEL", "LPUSH",
        "RPUSH", "LREM", "LSET", "SADD", "SREM", "ZADD", "ZREM", "INCR", "INCRBY", "DECR",
        "DECRBY", "RENAME", "XADD", "XDEL",
    }
)
# Multi-word commands: only these subcommands.
REDIS_SUBCOMMANDS = {
    "XINFO": frozenset({"STREAM", "GROUPS", "CONSUMERS"}),
    "MEMORY": frozenset({"USAGE"}),
    "OBJECT": frozenset({"ENCODING", "IDLETIME", "FREQ", "REFCOUNT"}),
}
REDIS_SCAN_COMMANDS = frozenset({"SCAN", "HSCAN", "SSCAN", "ZSCAN"})
REDIS_MAX_ARGS = 200
REDIS_MAX_ARG_BYTES = 1024 * 1024


def validate_redis(command: object, args: object, *, write: bool) -> tuple[str, list[str]]:
    if not isinstance(command, str) or not re.fullmatch(r"[A-Za-z]{1,32}", command.strip()):
        raise PolicyError("redis_command_invalid", "command must be one Redis command name")
    name = command.strip().upper()
    if args is None:
        args = []
    if not isinstance(args, list) or len(args) > REDIS_MAX_ARGS or any(
        isinstance(item, bool) or not isinstance(item, str | int | float) for item in args
    ):
        raise PolicyError("redis_args_invalid", "args must be a list of up to 200 scalars")
    values = [str(item) for item in args]
    if sum(len(item.encode("utf-8")) for item in values) > REDIS_MAX_ARG_BYTES:
        raise PolicyError("redis_args_invalid", "args are too large")
    allowed = REDIS_READ_COMMANDS | (REDIS_WRITE_COMMANDS if write else frozenset())
    if name not in allowed:
        if name in REDIS_WRITE_COMMANDS:
            raise PolicyError("read_only_violation", f"{name} needs write mode")
        raise PolicyError("redis_command_denied", f"{name} is not on the allowlist")
    subcommands = REDIS_SUBCOMMANDS.get(name)
    if subcommands is not None and (not values or values[0].upper() not in subcommands):
        raise PolicyError("redis_command_denied", f"{name} subcommand is not on the allowlist")
    if name in REDIS_SCAN_COMMANDS:
        values = _cap_scan_count(values)
    return name, values


def _cap_scan_count(values: list[str]) -> list[str]:
    upper = [item.upper() for item in values]
    if "COUNT" in upper:
        index = upper.index("COUNT")
        if index + 1 < len(values):
            try:
                count = int(values[index + 1])
            except ValueError:
                raise PolicyError("redis_args_invalid", "COUNT must be a number") from None
            values[index + 1] = str(min(max(count, 1), 1000))
        return values
    return [*values, "COUNT", "100"]


# --- MongoDB -----------------------------------------------------------------------------

MONGO_READ_OPS = frozenset({"find", "aggregate", "count", "distinct"})
MONGO_WRITE_OPS = frozenset(
    {"insert_one", "insert_many", "update_one", "update_many", "delete_one", "delete_many"}
)
MONGO_DENIED_KEYS = frozenset({"$out", "$merge", "$where", "$function", "$accumulator"})
_COLLECTION = re.compile(r"^(?!system\.)[^\x00$]{1,255}$")


def _deny_keys(value: Any, depth: int = 0) -> None:
    if depth > 64:
        raise PolicyError("mongo_invalid", "the document is nested too deeply")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PolicyError("mongo_invalid", "document keys must be text")
            if key in MONGO_DENIED_KEYS:
                raise PolicyError("mongo_operator_denied", f"{key} is not allowed")
            _deny_keys(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _deny_keys(item, depth + 1)


@dataclass(slots=True)
class MongoRequest:
    collection: str
    op: str
    filter: dict[str, Any] = field(default_factory=dict)
    projection: dict[str, Any] | None = None
    sort: list[tuple[str, int]] | None = None
    limit: int | None = None
    skip: int = 0
    pipeline: list[dict[str, Any]] = field(default_factory=list)
    update: Any = None
    documents: list[dict[str, Any]] = field(default_factory=list)
    key: str | None = None
    database: str | None = None


def validate_mongo(raw: object, *, write: bool) -> MongoRequest:
    if not isinstance(raw, dict):
        raise PolicyError("mongo_invalid", "mongo must be an object")
    unknown = set(raw) - {
        "collection", "op", "filter", "projection", "sort", "limit", "skip", "pipeline",
        "update", "documents", "document", "key", "database",
    }
    if unknown:
        raise PolicyError("mongo_invalid", f"unknown mongo fields: {', '.join(sorted(unknown))}")
    collection = raw.get("collection")
    if not isinstance(collection, str) or not _COLLECTION.fullmatch(collection):
        raise PolicyError("mongo_invalid", "collection name is invalid")
    op = raw.get("op", "find")
    if op not in MONGO_READ_OPS | MONGO_WRITE_OPS:
        raise PolicyError("mongo_op_denied", "unknown or disallowed mongo operation")
    if op in MONGO_WRITE_OPS and not write:
        raise PolicyError("read_only_violation", f"{op} needs write mode")
    database = raw.get("database")
    if database is not None and (
        not isinstance(database, str) or not _DATABASE.fullmatch(database)
    ):
        raise PolicyError("mongo_invalid", "database name is invalid")
    request = MongoRequest(collection=collection, op=op, database=database)
    filter_value = raw.get("filter", {})
    if filter_value is None:
        filter_value = {}
    if not isinstance(filter_value, dict):
        raise PolicyError("mongo_invalid", "filter must be an object")
    _deny_keys(filter_value)
    request.filter = filter_value
    if op == "find":
        projection = raw.get("projection")
        if projection is not None:
            if not isinstance(projection, dict):
                raise PolicyError("mongo_invalid", "projection must be an object")
            _deny_keys(projection)
        request.projection = projection
        sort = raw.get("sort")
        if sort is not None:
            if not isinstance(sort, dict) or len(sort) > 8 or any(
                value not in (1, -1) for value in sort.values()
            ):
                raise PolicyError("mongo_invalid", "sort must map up to 8 fields to 1 or -1")
            request.sort = [(str(key), int(value)) for key, value in sort.items()]
        limit = raw.get("limit")
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
                raise PolicyError("mongo_invalid", "limit must be a positive number")
            request.limit = limit
        skip = raw.get("skip", 0)
        if isinstance(skip, bool) or not isinstance(skip, int) or not 0 <= skip <= 10_000_000:
            raise PolicyError("mongo_invalid", "skip is invalid")
        request.skip = skip
    elif op == "aggregate":
        pipeline = raw.get("pipeline")
        if not isinstance(pipeline, list) or not pipeline or len(pipeline) > 100 or any(
            not isinstance(stage, dict) or len(stage) != 1 for stage in pipeline
        ):
            raise PolicyError("mongo_invalid", "pipeline must be a list of 1-100 stages")
        _deny_keys(pipeline)
        request.pipeline = pipeline
    elif op == "distinct":
        key = raw.get("key")
        if not isinstance(key, str) or not key or len(key) > 255:
            raise PolicyError("mongo_invalid", "distinct needs a key")
        request.key = key
    elif op in {"update_one", "update_many", "delete_one", "delete_many"}:
        if not filter_value:
            raise PolicyError(
                "mongo_filter_required", f"{op} needs an explicit, non-empty filter"
            )
        if op.startswith("update"):
            update = raw.get("update")
            if isinstance(update, dict):
                if not update or not all(key.startswith("$") for key in update):
                    raise PolicyError(
                        "mongo_invalid", "update must use update operators such as $set"
                    )
            elif isinstance(update, list):
                if not update or any(not isinstance(stage, dict) for stage in update):
                    raise PolicyError("mongo_invalid", "update pipeline is invalid")
            else:
                raise PolicyError("mongo_invalid", "update must be an object or a pipeline")
            _deny_keys(update)
            request.update = update
    elif op in {"insert_one", "insert_many"}:
        documents = raw.get("documents")
        if op == "insert_one":
            document = raw.get("document")
            documents = [document] if document is not None else documents
        if not isinstance(documents, list) or not documents or len(documents) > 1000 or any(
            not isinstance(doc, dict) for doc in documents
        ):
            raise PolicyError("mongo_invalid", "documents must be a list of 1-1000 objects")
        if op == "insert_one" and len(documents) != 1:
            raise PolicyError("mongo_invalid", "insert_one takes exactly one document")
        _deny_keys(documents)
        request.documents = documents
    return request


# --- table browse -----------------------------------------------------------------------

FILTER_OPS = frozenset(
    {"eq", "ne", "lt", "lte", "gt", "gte", "like", "ilike", "is_null", "not_null", "in"}
)


@dataclass(frozen=True, slots=True)
class Filter:
    column: str
    op: str
    value: Any = None


_FIELD = re.compile(r"^(?!\$)[^\x00]{1,255}$")


def parse_filters(
    raw: str | None, columns: list[str] | None, *, keep_types: bool = False
) -> list[Filter]:
    """``columns=None`` accepts any field name (MongoDB); ``keep_types`` keeps JSON scalars."""
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except ValueError:
        raise PolicyError("invalid_filter", "filter must be a JSON array") from None
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list) or len(payload) > 20:
        raise PolicyError("invalid_filter", "filter must be a list of up to 20 conditions")
    result: list[Filter] = []
    for item in payload:
        if not isinstance(item, dict) or set(item) - {"column", "op", "value"}:
            raise PolicyError("invalid_filter", "each filter takes column, op and value")
        column, op, value = item.get("column"), item.get("op", "eq"), item.get("value")
        if columns is None:
            if not isinstance(column, str) or not _FIELD.fullmatch(column):
                raise PolicyError("invalid_filter", "filter field is invalid")
        elif column not in columns:
            raise PolicyError("invalid_filter", "filter column does not exist")
        if op not in FILTER_OPS:
            raise PolicyError("invalid_filter", "unknown filter operator")
        if op == "in":
            if not isinstance(value, list) or not 1 <= len(value) <= 100 or any(
                isinstance(entry, dict | list) for entry in value
            ):
                raise PolicyError("invalid_filter", "in takes a list of 1-100 scalar values")
            if not keep_types:
                value = [None if entry is None else str(entry) for entry in value]
        elif op in {"is_null", "not_null"}:
            value = None
        else:
            if isinstance(value, dict | list) or value is None:
                raise PolicyError("invalid_filter", "filter value must be a scalar")
            if not keep_types:
                value = str(value)
        result.append(Filter(str(column), op, value))
    return result


def parse_sort(raw: str | None, columns: list[str] | None) -> list[tuple[str, bool]]:
    """``col`` ascending, ``-col`` descending, comma-separated, up to 3."""
    if not raw:
        return []
    result: list[tuple[str, bool]] = []
    for part in raw.split(",")[:4]:
        part = part.strip()
        descending = part.startswith("-")
        name = part[1:] if descending else part
        if columns is None:
            if not _FIELD.fullmatch(name):
                raise PolicyError("invalid_sort", "sort field is invalid")
        elif name not in columns:
            raise PolicyError("invalid_sort", "sort column does not exist")
        result.append((name, descending))
    if len(result) > 3:
        raise PolicyError("invalid_sort", "sort takes up to 3 columns")
    return result


# --- result shaping ----------------------------------------------------------------------


def _jsonable(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, bool | str):
        return value
    if isinstance(value, int):
        return value if abs(value) <= 2**53 else str(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        raw = bytes(value)
        return {"$binary": base64.b64encode(raw).decode("ascii"), "bytes": len(raw)}
    if isinstance(value, dt.datetime | dt.date | dt.time):
        return value.isoformat()
    if isinstance(value, dt.timedelta):
        return str(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if depth > 32:
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_jsonable(item, depth + 1) for item in value]
    return str(value)


def cell(value: Any, max_bytes: int) -> tuple[Any, bool]:
    """Return a JSON-safe value capped to about ``max_bytes`` and whether it was cut."""
    if isinstance(value, bytes | bytearray | memoryview):
        raw = bytes(value)
        limit = max(max_bytes * 3 // 4, 1)
        return (
            {"$binary": base64.b64encode(raw[:limit]).decode("ascii"), "bytes": len(raw),
             **({"truncated": True} if len(raw) > limit else {})},
            len(raw) > limit,
        )
    if isinstance(value, str):
        if len(value.encode("utf-8", "surrogatepass")) <= max_bytes:
            return value, False
        return value.encode("utf-8", "surrogatepass")[:max_bytes].decode(
            "utf-8", "ignore"
        ), True
    converted = _jsonable(value)
    if isinstance(converted, dict | list):
        text = json.dumps(converted, ensure_ascii=False, separators=(",", ":"))
        if len(text.encode("utf-8")) > max_bytes:
            return text.encode("utf-8")[:max_bytes].decode("utf-8", "ignore"), True
        return converted, False
    if isinstance(converted, str):
        return cell(converted, max_bytes)
    return converted, False


class ResultBuilder:
    """Collect rows while enforcing row, cell and response-size caps."""

    def __init__(self, *, max_rows: int, max_cell_bytes: int, max_response_bytes: int) -> None:
        self.max_rows = max_rows
        self.max_cell_bytes = max_cell_bytes
        self.max_response_bytes = max_response_bytes
        self.rows: list[list[Any]] = []
        self.size = 0
        self.truncated_cells = 0
        self.truncated_reason: str | None = None

    def add(self, row: list[Any] | tuple[Any, ...]) -> bool:
        """Add one row; False means stop reading (a cap was reached)."""
        if len(self.rows) >= self.max_rows:
            self.truncated_reason = "row_limit"
            return False
        cells = []
        for value in row:
            shaped, cut = cell(value, self.max_cell_bytes)
            self.truncated_cells += int(cut)
            cells.append(shaped)
        size = len(json.dumps(cells, ensure_ascii=False, separators=(",", ":"), default=str))
        if self.size + size > self.max_response_bytes:
            self.truncated_reason = "response_size"
            return False
        self.size += size
        self.rows.append(cells)
        return True

    def payload(self) -> dict[str, Any]:
        return {
            "rows": self.rows,
            "row_count": len(self.rows),
            "truncated": self.truncated_reason is not None,
            "truncated_reason": self.truncated_reason,
            "truncated_cells": self.truncated_cells,
        }


def csv_cell(value: Any, *, excel_safe: bool) -> str:
    converted = _jsonable(value)
    if converted is None:
        return ""
    if isinstance(converted, bool):
        text = "true" if converted else "false"
    elif isinstance(converted, dict | list):
        text = json.dumps(converted, ensure_ascii=False, separators=(",", ":"))
    else:
        text = str(converted)
    # Spreadsheet formula injection: only text values, so negative numbers stay numbers.
    if excel_safe and isinstance(converted, str) and text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text
