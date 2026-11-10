"""``mrk-db-secret PATH``: create the PostgreSQL password once (service mrk-db-init).

compose.yaml runs this one-shot before the database starts. It writes a random
password to PATH in the volume shared only by mrk-db (POSTGRES_PASSWORD_FILE) and
the panel (MRK_DATABASE_PASSWORD_FILE), and never changes an existing one, so the
stack needs no password in .env and a restart keeps working.

The file is world-readable inside that private volume because the PostgreSQL
image reads it as its own uid (999) and the panel as 10001.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path


def ensure(path: Path) -> bool:
    """Create the password file if it is missing. True when it was created."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SystemExit(f"refusing a symlinked password file: {path}")
    if path.exists():
        if not path.read_text(encoding="utf-8").strip():
            raise SystemExit(f"the database password file is empty: {path}")
        return False
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(secrets.token_urlsafe(32) + "\n")
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)
    return True


def run() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: mrk-db-secret PATH")
    created = ensure(Path(sys.argv[1]))
    print("database password created" if created else "database password already set")


if __name__ == "__main__":  # pragma: no cover
    run()
