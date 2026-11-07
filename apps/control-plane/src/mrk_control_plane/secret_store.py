from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretStore:
    """Small encrypted-at-rest store for appliance service credentials."""

    def __init__(self, data_dir: Path, key_path: Path | None = None) -> None:
        self.root = data_dir / "control-plane"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        configured_key = os.getenv("MRK_UPSTREAM_SECRET_KEY_FILE", "").strip()
        self.external_key = key_path is not None or bool(configured_key)
        self.key_path = (
            (key_path or Path(configured_key)).resolve()
            if self.external_key
            else self.root / "upstream-secrets.key"
        )
        self.store_path = self.root / "upstream-secrets.json"
        self._lock = threading.RLock()

    def _key(self, *, create: bool) -> bytes:
        if self.key_path.exists():
            if not self.key_path.is_file():
                raise ValueError("upstream secret key path is not a regular file")
            key = self.key_path.read_bytes()
            if len(key) != 32:
                raise ValueError("upstream secret key is invalid")
            return key
        if self.external_key:
            raise ValueError("configured upstream secret key file is unavailable")
        if not create:
            raise KeyError("secret key is unavailable")
        key = secrets.token_bytes(32)
        temporary = self.key_path.with_name(f".{self.key_path.name}.{secrets.token_hex(4)}.tmp")
        temporary.write_bytes(key)
        temporary.chmod(0o600)
        os.replace(temporary, self.key_path)
        return key

    def _read(self) -> dict[str, Any]:
        if not self.store_path.exists():
            return {"version": 1, "items": {}}
        payload = json.loads(self.store_path.read_text(encoding="utf-8"))
        if payload.get("version") != 1 or not isinstance(payload.get("items"), dict):
            raise ValueError("upstream secret store is invalid")
        return payload

    def _write(self, payload: dict[str, Any]) -> None:
        temporary = self.store_path.with_name(
            f".{self.store_path.name}.{secrets.token_hex(4)}.tmp"
        )
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, self.store_path)

    def replace(self, reference: str | None, value: dict[str, str]) -> tuple[str, int]:
        if not value or any(not isinstance(item, str) or not item for item in value.values()):
            raise ValueError("credential fields cannot be empty")
        encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
        with self._lock:
            payload = self._read()
            reference = reference or secrets.token_hex(16)
            nonce = secrets.token_bytes(12)
            ciphertext = AESGCM(self._key(create=True)).encrypt(
                nonce, encoded, reference.encode("ascii")
            )
            updated_at = int(time.time())
            payload["items"][reference] = {
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "updated_at": updated_at,
            }
            self._write(payload)
            return reference, updated_at

    def get(self, reference: str) -> dict[str, str]:
        with self._lock:
            item = self._read()["items"].get(reference)
            if not isinstance(item, dict):
                raise KeyError(reference)
            try:
                plaintext = AESGCM(self._key(create=False)).decrypt(
                    base64.b64decode(item["nonce"], validate=True),
                    base64.b64decode(item["ciphertext"], validate=True),
                    reference.encode("ascii"),
                )
                value = json.loads(plaintext)
            except Exception as exc:
                raise ValueError("upstream secret authentication failed") from exc
            if not isinstance(value, dict) or any(
                not isinstance(key, str) or not isinstance(item, str)
                for key, item in value.items()
            ):
                raise ValueError("upstream secret payload is invalid")
            return value

    def delete(self, reference: str) -> None:
        with self._lock:
            payload = self._read()
            payload["items"].pop(reference, None)
            self._write(payload)

    def authorization_header(self, reference: str, credential_type: str) -> str:
        value = self.get(reference)
        if credential_type == "bearer":
            token = value.get("token")
            if not token:
                raise ValueError("bearer token is unavailable")
            return f"Bearer {token}"
        if credential_type == "basic":
            username = value.get("username")
            password = value.get("password")
            if not username or not password:
                raise ValueError("basic credential is unavailable")
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
            return f"Basic {encoded}"
        raise ValueError("unsupported upstream credential type")
