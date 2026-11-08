"""Entry point for the ``mrk-agent`` console script."""

from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

from ..logging_config import configure_logging
from .signing import KEY_BYTES, decode_key, encode_key, generate_key

LOGGER = logging.getLogger("mrk_control_plane.agent")
DEFAULT_STATE_DIR = "/var/lib/mrk-agent"
DEFAULT_LISTEN = "0.0.0.0:7070"  # noqa: S104 - private compose network only, never published
KEY_FILE_NAME = "agent.key"


def load_or_create_key(state_dir: Path) -> tuple[bytes, bool]:
    """Return (key, newly_created). The key file holds the base64url text, mode 0600."""
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = state_dir / KEY_FILE_NAME
    if path.exists():
        if not path.is_file():
            raise ValueError("agent key path is not a regular file")
        raw = path.read_bytes()
        if len(raw) == KEY_BYTES:
            return raw, False
        return decode_key(raw.decode("ascii", errors="strict")), False
    key = generate_key()
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(encode_key(key) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    return key, True


def parse_listen(value: str) -> tuple[str, int]:
    host, separator, port_text = value.strip().rpartition(":")
    if not separator or not port_text.isdigit():
        raise ValueError("MRK_AGENT_LISTEN must be host:port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("MRK_AGENT_LISTEN port must be between 1 and 65535")
    return host.strip("[]") or "0.0.0.0", port  # noqa: S104


def run() -> None:
    import uvicorn

    from .app import AgentConfig, create_agent_app

    configure_logging(os.getenv("MRK_LOG_LEVEL", "INFO").strip().upper() or "INFO")
    state_dir = Path(os.getenv("MRK_AGENT_STATE_DIR", "").strip() or DEFAULT_STATE_DIR)
    key, created = load_or_create_key(state_dir)
    if created:
        # Shown exactly once, on first start. Paste it into Admin UI -> Server -> Host Agent.
        LOGGER.warning(
            "mrk-agent pairing key generated (shown once): %s ; key file: %s",
            encode_key(key),
            state_dir / KEY_FILE_NAME,
        )
    host, port = parse_listen(os.getenv("MRK_AGENT_LISTEN", DEFAULT_LISTEN))
    app = create_agent_app(AgentConfig.from_env(key))
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_config=None,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        timeout_graceful_shutdown=10,
    )


if __name__ == "__main__":  # pragma: no cover
    run()
