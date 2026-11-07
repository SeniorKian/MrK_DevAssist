from __future__ import annotations

import importlib.util
import stat
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


def _load_entrypoint() -> ModuleType:
    entrypoint_path = (
        Path(__file__).resolve().parents[3] / "deploy" / "appliance" / "entrypoint.py"
    )
    spec = importlib.util.spec_from_file_location("mrk_appliance_entrypoint", entrypoint_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_stdio_handoff_never_changes_regular_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    entrypoint = _load_entrypoint()
    changed: list[tuple[int, int, int]] = []

    def fake_fstat(descriptor: int) -> SimpleNamespace:
        kind = stat.S_IFIFO if descriptor == 1 else stat.S_IFREG
        return SimpleNamespace(st_mode=kind | 0o600)

    monkeypatch.setattr(
        entrypoint,
        "os",
        SimpleNamespace(
            fstat=fake_fstat,
            fchown=lambda descriptor, uid, gid: changed.append((descriptor, uid, gid)),
        ),
    )

    entrypoint._handoff_container_pipes()

    assert changed == [(1, entrypoint.APP_UID, entrypoint.APP_GID)]


def test_data_initializer_rejects_non_directory(tmp_path: Path) -> None:
    entrypoint = _load_entrypoint()
    invalid_path = tmp_path / "not-a-directory"
    invalid_path.write_text("invalid", encoding="utf-8")
    with pytest.raises(RuntimeError, match="refusing non-directory"):
        entrypoint._ensure_real_directory(invalid_path)
