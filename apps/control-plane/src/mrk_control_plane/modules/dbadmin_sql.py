"""SQL text helpers for the database admin module (Gate 19 S9, docs/32 §5).

A small, careful tokenizer that understands enough of PostgreSQL and MySQL
lexical rules to find statement boundaries: single/double quoted strings
(with ``''`` and, where the dialect uses them, backslash escapes), ``E'...'``
strings, backtick identifiers, PostgreSQL ``$tag$`` dollar quotes, ``--``
/ ``#`` line comments and (nested for PostgreSQL) block comments. It is used
to reject multi-statement text and to classify the single statement; the
drivers are additionally configured so they cannot run more than one
statement per call (psycopg extended protocol, PyMySQL without
MULTI_STATEMENTS).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

DIALECTS = ("postgres", "mysql")

_WORD_START = re.compile(r"[A-Za-z_\u0080-￿]")
_PG_WORD = re.compile(r"[A-Za-z0-9_$\u0080-￿]*")
_MY_WORD = re.compile(r"[A-Za-z0-9_$\u0080-￿]*")
_DOLLAR_TAG = re.compile(r"\$(?:[A-Za-z_\u0080-￿][A-Za-z0-9_\u0080-￿]*)?\$")
_NUMBER = re.compile(r"(?:\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)")
_MAX_TEXT = 1_000_000

# First keyword allowed in read mode.
READ_KEYWORDS = {
    "postgres": frozenset({"SELECT", "WITH", "VALUES", "TABLE", "SHOW", "EXPLAIN"}),
    "mysql": frozenset(
        {"SELECT", "WITH", "VALUES", "TABLE", "SHOW", "EXPLAIN", "DESCRIBE", "DESC"}
    ),
}
# Words that are never accepted in read mode even inside an allowed statement:
# server administration, file access and session-lock functions that a read-only
# transaction does not stop. Real protection is still a read-only database user.
READ_DENIED_WORDS = {
    "postgres": frozenset(
        {
            "PG_TERMINATE_BACKEND", "PG_CANCEL_BACKEND", "PG_RELOAD_CONF", "PG_ROTATE_LOGFILE",
            "PG_READ_FILE", "PG_READ_BINARY_FILE", "PG_LS_DIR", "PG_STAT_FILE", "PG_LS_LOGDIR",
            "PG_LS_WALDIR", "PG_LS_TMPDIR", "PG_LS_ARCHIVE_STATUSDIR", "LO_IMPORT", "LO_EXPORT",
            "DBLINK", "DBLINK_EXEC", "DBLINK_CONNECT", "DBLINK_CONNECT_U", "DBLINK_SEND_QUERY",
            "SET_CONFIG", "PG_ADVISORY_LOCK", "PG_ADVISORY_LOCK_SHARED", "PG_ADVISORY_XACT_LOCK",
            "PG_ADVISORY_XACT_LOCK_SHARED", "PG_TRY_ADVISORY_LOCK", "PG_PROMOTE",
            "PG_SWITCH_WAL", "PG_CREATE_RESTORE_POINT", "PG_LOGICAL_EMIT_MESSAGE",
            "PG_FILE_WRITE", "PG_FILE_RENAME", "PG_FILE_UNLINK", "PG_LOG_BACKEND_MEMORY_CONTEXTS",
            "PG_NOTIFY", "QUERY_TO_XML", "QUERY_TO_XML_AND_XMLSCHEMA", "CURSOR_TO_XML",
        }
    ),
    "mysql": frozenset({"OUTFILE", "DUMPFILE", "LOAD_FILE", "GET_LOCK"}),
}
# Statements whose affected rows can be previewed in a rolled-back transaction.
DRY_RUN_KEYWORDS = {
    "postgres": frozenset({"UPDATE", "DELETE", "INSERT", "MERGE"}),
    "mysql": frozenset({"UPDATE", "DELETE", "INSERT", "REPLACE"}),
}


class SqlError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class Token:
    kind: str  # word, ident, string, number, param, punct, semicolon, comment
    text: str


@dataclass(frozen=True, slots=True)
class Statement:
    text: str
    keyword: str
    words: tuple[str, ...]
    idents: tuple[str, ...]


def dialect_for(engine: str) -> str:
    return "postgres" if engine == "postgres" else "mysql"


def statement_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _scan_quoted(text: str, start: int, quote: str, *, backslash: bool) -> int:
    """Return the index just past the closing quote that starts at ``start``."""
    i = start + 1
    length = len(text)
    while i < length:
        char = text[i]
        if backslash and char == "\\":
            i += 2
            continue
        if char == quote:
            if i + 1 < length and text[i + 1] == quote:
                i += 2
                continue
            return i + 1
        i += 1
    raise SqlError("sql_unterminated", f"unterminated {quote} quote")


def _scan_block_comment(text: str, start: int, *, nested: bool) -> int:
    depth = 1
    i = start + 2
    length = len(text)
    while i < length:
        if nested and text.startswith("/*", i):
            depth += 1
            i += 2
            continue
        if text.startswith("*/", i):
            depth -= 1
            i += 2
            if depth == 0:
                return i
            continue
        i += 1
    raise SqlError("sql_unterminated", "unterminated block comment")


def tokenize(text: str, dialect: str) -> list[Token]:
    if dialect not in DIALECTS:
        raise ValueError("unknown dialect")
    if len(text) > _MAX_TEXT:
        raise SqlError("sql_too_long", "the statement is too long")
    if "\x00" in text:
        raise SqlError("sql_invalid", "the statement contains a NUL character")
    postgres = dialect == "postgres"
    tokens: list[Token] = []
    i = 0
    length = len(text)
    while i < length:
        char = text[i]
        if char.isspace():
            i += 1
            continue
        # Line comments.
        if text.startswith("--", i) and (
            postgres or i + 2 >= length or text[i + 2].isspace() or ord(text[i + 2]) < 32
        ):
            end = text.find("\n", i)
            end = length if end < 0 else end + 1
            tokens.append(Token("comment", text[i:end]))
            i = end
            continue
        if char == "#" and not postgres:
            end = text.find("\n", i)
            end = length if end < 0 else end + 1
            tokens.append(Token("comment", text[i:end]))
            i = end
            continue
        if text.startswith("/*", i):
            if not postgres and text.startswith("/*!", i):
                raise SqlError(
                    "sql_executable_comment", "MySQL executable comments (/*! */) are not allowed"
                )
            end = _scan_block_comment(text, i, nested=postgres)
            tokens.append(Token("comment", text[i:end]))
            i = end
            continue
        if char == ";":
            tokens.append(Token("semicolon", ";"))
            i += 1
            continue
        if char == "'":
            end = _scan_quoted(text, i, "'", backslash=not postgres)
            tokens.append(Token("string", text[i:end]))
            i = end
            continue
        if char == '"':
            end = _scan_quoted(text, i, '"', backslash=not postgres)
            tokens.append(Token("ident" if postgres else "string", text[i:end]))
            i = end
            continue
        if char == "`" and not postgres:
            end = _scan_quoted(text, i, "`", backslash=False)
            tokens.append(Token("ident", text[i:end]))
            i = end
            continue
        if char == "$" and postgres:
            tag = _DOLLAR_TAG.match(text, i)
            if tag:
                closing = text.find(tag.group(0), tag.end())
                if closing < 0:
                    raise SqlError("sql_unterminated", "unterminated dollar-quoted string")
                end = closing + len(tag.group(0))
                tokens.append(Token("string", text[i:end]))
                i = end
                continue
            digits = re.compile(r"\$\d+").match(text, i)
            if digits:
                tokens.append(Token("param", digits.group(0)))
                i = digits.end()
                continue
            tokens.append(Token("punct", "$"))
            i += 1
            continue
        if _WORD_START.match(char):
            word = (_PG_WORD if postgres else _MY_WORD).match(text, i + 1)
            end = word.end() if word else i + 1
            value = text[i:end]
            # Prefixed strings: E'..' (backslash escapes), B'..', X'..', U&'..', N'..', _utf8'..'.
            if end < length and text[end] == "'":
                upper = value.upper()
                if postgres and upper == "E":
                    close = _scan_quoted(text, end, "'", backslash=True)
                    tokens.append(Token("string", text[i:close]))
                    i = close
                    continue
                if upper in {"B", "X", "N"} or (not postgres and value.startswith("_")):
                    close = _scan_quoted(text, end, "'", backslash=not postgres)
                    tokens.append(Token("string", text[i:close]))
                    i = close
                    continue
            if postgres and value.upper() == "U" and text.startswith("&'", end):
                close = _scan_quoted(text, end + 1, "'", backslash=False)
                tokens.append(Token("string", text[i:close]))
                i = close
                continue
            tokens.append(Token("word", value))
            i = end
            continue
        number = _NUMBER.match(text, i)
        if number and number.end() > i:
            tokens.append(Token("number", number.group(0)))
            i = number.end()
            continue
        tokens.append(Token("punct", char))
        i += 1
    return tokens


def split_statements(text: str, dialect: str) -> list[list[Token]]:
    statements: list[list[Token]] = []
    current: list[Token] = []
    for token in tokenize(text, dialect):
        if token.kind == "comment":
            continue
        if token.kind == "semicolon":
            if current:
                statements.append(current)
            current = []
            continue
        current.append(token)
    if current:
        statements.append(current)
    return statements


def _unquote_ident(text: str) -> str:
    quote = text[0]
    return text[1:-1].replace(quote * 2, quote)


def single_statement(text: str, dialect: str) -> Statement:
    """Parse ``text`` as exactly one statement or raise SqlError."""
    statements = split_statements(text, dialect)
    if not statements:
        raise SqlError("sql_empty", "the query is empty")
    if len(statements) > 1:
        raise SqlError(
            "sql_multiple_statements", "only one statement per request is allowed"
        )
    tokens = statements[0]
    words = tuple(token.text.upper() for token in tokens if token.kind == "word")
    idents = tuple(_unquote_ident(token.text) for token in tokens if token.kind == "ident")
    keyword = words[0] if words else ""
    return Statement(text=text, keyword=keyword, words=words, idents=idents)


def check_read_only(statement: Statement, dialect: str) -> None:
    if statement.keyword not in READ_KEYWORDS[dialect]:
        raise SqlError(
            "read_only_violation",
            "read mode only runs SELECT/WITH/SHOW/EXPLAIN-style statements; enable write mode",
        )
    denied = READ_DENIED_WORDS[dialect]
    names = set(statement.words) | {ident.upper() for ident in statement.idents}
    blocked = sorted(names & denied)
    if blocked:
        raise SqlError(
            "read_only_violation", f"read mode does not allow {blocked[0].lower()}"
        )


def can_dry_run(statement: Statement, dialect: str) -> bool:
    return statement.keyword in DRY_RUN_KEYWORDS[dialect]


def quote_mysql_ident(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"
