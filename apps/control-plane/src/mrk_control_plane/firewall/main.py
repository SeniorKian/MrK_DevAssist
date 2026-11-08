"""Entry point for the ``mrk-firewall`` console script.

Listens on a Unix socket by default (``MRK_FIREWALL_LISTEN=unix:/run/mrk-firewall/
firewall.sock``) inside a volume shared only with the control plane. A TCP listener
(``host:port``) is accepted for bare-metal/dev use; with ``network_mode: host`` keep it
on ``127.0.0.1`` (it is then NOT reachable from bridge-network containers).
"""

from __future__ import annotations

import logging
import os
import secrets
import stat
from pathlib import Path

from ..agent.signing import KEY_BYTES, decode_key, encode_key, generate_key
from ..logging_config import configure_logging

LOGGER = logging.getLogger("mrk_control_plane.firewall")
DEFAULT_STATE_DIR = "/var/lib/mrk-firewall"
DEFAULT_LISTEN = "unix:/run/mrk-firewall/firewall.sock"
KEY_FILE_NAME = "firewall.key"


def load_or_create_key(state_dir: Path) -> tuple[bytes, bool]:
    """Return (key, newly_created). The key file holds base64url text, mode 0600."""
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = state_dir / KEY_FILE_NAME
    if path.exists():
        if not path.is_file():
            raise ValueError("firewall key path is not a regular file")
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


def parse_listen(value: str) -> tuple[str, str | None, int | None]:
    """Return ("unix", path, None) or ("tcp", host, port)."""
    text = value.strip()
    if text.startswith("unix:"):
        path = text[5:]
        if not path.startswith("/") or ".." in path.split("/") or len(path) > 100:
            raise ValueError("MRK_FIREWALL_LISTEN unix path must be absolute (<=100 chars)")
        return "unix", path, None
    host, separator, port_text = text.rpartition(":")
    if not separator or not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ValueError("MRK_FIREWALL_LISTEN must be unix:/path or host:port")
    return "tcp", host.strip("[]") or "127.0.0.1", int(port_text)


def prepare_socket(path: str) -> None:
    """Remove a stale socket left by a crash; refuse to delete anything else."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode = target.lstat().st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(mode):
        raise ValueError(f"{path} exists and is not a socket")
    target.unlink()


def run() -> None:
    import uvicorn

    from .app import FirewallConfig, create_firewall_app

    configure_logging(os.getenv("MRK_LOG_LEVEL", "INFO").strip().upper() or "INFO")
    state_dir = Path(os.getenv("MRK_FIREWALL_STATE_DIR", "").strip() or DEFAULT_STATE_DIR)
    key, created = load_or_create_key(state_dir)
    if created:
        # Shown exactly once. Paste it into Admin UI -> Server -> Firewall -> Pair.
        LOGGER.warning(
            "mrk-firewall pairing key generated (shown once): %s ; key file: %s",
            encode_key(key),
            state_dir / KEY_FILE_NAME,
        )
    kind, host_or_path, port = parse_listen(os.getenv("MRK_FIREWALL_LISTEN", DEFAULT_LISTEN))
    app = create_firewall_app(FirewallConfig.from_env(key, state_dir))
    options = {
        "log_config": None,
        "access_log": False,
        "proxy_headers": False,
        "server_header": False,
        "timeout_graceful_shutdown": 10,
    }
    if kind == "unix":
        assert host_or_path is not None
        prepare_socket(host_or_path)
        # uvicorn chmods the socket 0666; access is limited by who mounts the volume,
        # and every request must still carry a valid HMAC signature.
        uvicorn.run(app, uds=host_or_path, **options)
    else:
        uvicorn.run(app, host=host_or_path, port=port, **options)


if __name__ == "__main__":  # pragma: no cover
    run()
