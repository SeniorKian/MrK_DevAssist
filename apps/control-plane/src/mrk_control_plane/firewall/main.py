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


def load_or_create_key(state_dir: Path, seed: str | None = None) -> tuple[bytes, bool]:
    """Return (key, newly_created).

    ``seed`` is the pairing key the panel's add-service wizard generated
    (``MRK_FIREWALL_PAIRING_KEY``). When given it is authoritative: it is written to the key
    file (mode 0600) if the file is missing or holds another key, so a key
    regenerated in the wizard takes effect on the next deploy. Nothing is
    logged for a seeded key: the panel already has it.
    """
    if seed is None or not seed.strip():
        return _load_or_create_key(state_dir)
    key = decode_key(seed.strip())
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = state_dir / KEY_FILE_NAME
    if path.exists():
        if not path.is_file():
            raise ValueError("firewall key path is not a regular file")
        raw = path.read_bytes()
        current = raw if len(raw) == KEY_BYTES else None
        if current is None:
            try:
                current = decode_key(raw.decode("ascii", errors="strict"))
            except ValueError:
                current = None
        if current == key:
            return key, False
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(encode_key(key) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    return key, False


def _load_or_create_key(state_dir: Path) -> tuple[bytes, bool]:
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


RECOVER_USAGE = """usage: mrk-firewall recover [--open]

Emergency recovery from the server console (docs/45), e.g.
  docker compose exec mrk-firewall mrk-firewall recover
  docker exec <firewall container> mrk-firewall recover --open

  recover         load the last confirmed (last-known-good) port policy now
  recover --open  turn the port policy off: every port is open again as before it was
                  enabled (blocked attacker addresses stay blocked)

It asks the running helper over its socket; if the helper is not running it loads the
ruleset itself. Last resort on the host: sudo nft delete table inet mrk
"""


def _read_key(state_dir: Path) -> bytes | None:
    path = state_dir / KEY_FILE_NAME
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) == KEY_BYTES:
        return raw
    try:
        return decode_key(raw.decode("ascii").strip())
    except ValueError:
        return None


def _recover_online(listen: str, key: bytes, open_ports: bool) -> dict[str, object]:
    import json

    import httpx

    from ..agent.signing import sign_headers

    kind, host_or_path, port = parse_listen(listen)
    if kind == "unix":
        transport = httpx.HTTPTransport(uds=host_or_path)
        base = "http://mrk-firewall"
    else:
        transport = httpx.HTTPTransport()
        base = f"http://{host_or_path}:{port}"
    body = json.dumps({"open": open_ports}).encode()
    headers = {"Content-Type": "application/json",
               **sign_headers(key, "POST", "/v1/recover", body)}
    with httpx.Client(transport=transport, base_url=base, timeout=20, trust_env=False) as client:
        response = client.post("/v1/recover", content=body, headers=headers)
    response.raise_for_status()
    result = response.json()
    return result if isinstance(result, dict) else {"result": result}


def _recover_offline(state_dir: Path, open_ports: bool) -> dict[str, object]:
    import time

    from .app import FirewallConfig, HelperState
    from .nft import DesiredState, NftRunner

    config = FirewallConfig.from_env(b"", state_dir)
    helper = HelperState(config, NftRunner(config.nft_binary, state_dir))
    helper.desired = helper.load() or DesiredState(mode="dry_run")
    helper.load_ports(time.time())
    reason = "recover_offline_open" if open_ports else "recover_offline"
    return {"rollback": helper.restore(reason, open_ports=open_ports)}


def recover(argv: list[str]) -> int:
    import json

    if any(item in {"-h", "--help"} for item in argv) or set(argv) - {"--open"}:
        print(RECOVER_USAGE)
        return 0 if any(item in {"-h", "--help"} for item in argv) else 2
    open_ports = "--open" in argv
    state_dir = Path(os.getenv("MRK_FIREWALL_STATE_DIR", "").strip() or DEFAULT_STATE_DIR)
    key = _read_key(state_dir)
    result: dict[str, object] | None = None
    if key is not None:
        try:
            result = _recover_online(os.getenv("MRK_FIREWALL_LISTEN", DEFAULT_LISTEN), key,
                                     open_ports)
            result["via"] = "helper"
        except Exception as exc:  # noqa: BLE001 - any failure -> do it ourselves
            print(f"helper not reachable ({type(exc).__name__}); applying directly")
    if result is None:
        result = _recover_offline(state_dir, open_ports)
        result["via"] = "direct"
    print(json.dumps(result, indent=2, default=str))
    rollback = result.get("rollback")
    outcome = rollback.get("outcome") if isinstance(rollback, dict) else None
    return 0 if outcome in {"restored", "table_deleted"} else 1


def run() -> None:
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "recover":
        raise SystemExit(recover(sys.argv[2:]))
    import uvicorn

    from .app import FirewallConfig, create_firewall_app

    configure_logging(os.getenv("MRK_LOG_LEVEL", "INFO").strip().upper() or "INFO")
    state_dir = Path(os.getenv("MRK_FIREWALL_STATE_DIR", "").strip() or DEFAULT_STATE_DIR)
    key, created = load_or_create_key(state_dir, os.getenv("MRK_FIREWALL_PAIRING_KEY"))
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
