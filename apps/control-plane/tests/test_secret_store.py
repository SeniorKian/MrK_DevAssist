from pathlib import Path

import pytest
from mrk_control_plane.secret_store import SecretStore


def test_secret_store_encrypts_rotates_and_deletes_credentials(tmp_path: Path) -> None:
    store = SecretStore(tmp_path)
    reference, first_updated = store.replace(
        None, {"username": "private-user", "password": "private-password"}
    )

    assert store.get(reference) == {
        "username": "private-user",
        "password": "private-password",
    }
    assert store.authorization_header(reference, "basic").startswith("Basic ")
    serialized = store.store_path.read_text(encoding="utf-8")
    assert "private-user" not in serialized
    assert "private-password" not in serialized
    assert store.key_path.stat().st_size == 32

    rotated_reference, second_updated = store.replace(reference, {"token": "rotated-token"})
    assert rotated_reference == reference
    assert second_updated >= first_updated
    assert store.authorization_header(reference, "bearer") == "Bearer rotated-token"
    assert "rotated-token" not in store.store_path.read_text(encoding="utf-8")

    store.delete(reference)
    assert reference not in store.store_path.read_text(encoding="utf-8")


def test_external_secret_key_is_read_only_and_fail_closed(tmp_path: Path) -> None:
    key_file = tmp_path / "runtime-secret" / "upstream.key"
    key_file.parent.mkdir()
    key_file.write_bytes(b"k" * 32)
    store = SecretStore(tmp_path / "data", key_path=key_file)

    reference, _ = store.replace(None, {"token": "private-token"})

    assert store.get(reference) == {"token": "private-token"}
    assert key_file.read_bytes() == b"k" * 32
    assert "private-token" not in store.store_path.read_text(encoding="utf-8")

    missing = tmp_path / "runtime-secret" / "missing.key"
    with pytest.raises(ValueError, match="unavailable"):
        SecretStore(tmp_path / "missing-data", key_path=missing).replace(
            None, {"token": "never-written"}
        )
    assert not missing.exists()


def test_external_secret_key_must_be_exactly_32_bytes(tmp_path: Path) -> None:
    key_file = tmp_path / "invalid.key"
    key_file.write_bytes(b"too-short")

    with pytest.raises(ValueError, match="invalid"):
        SecretStore(tmp_path / "data", key_path=key_file).replace(
            None, {"token": "never-written"}
        )
