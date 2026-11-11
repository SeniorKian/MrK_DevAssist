from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_script():
    root = Path(__file__).resolve().parents[3]
    path = root / "scripts" / "e2e_local_engines.py"
    spec = importlib.util.spec_from_file_location("e2e_local_engines", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_devpi_init_binds_password_that_starts_with_dash(tmp_path: Path) -> None:
    script = _load_script()

    command = script._devpi_init_command(
        "devpi-init", tmp_path / "server", "-leading-dash"
    )

    assert command[-1] == "--root-passwd=-leading-dash"
    assert "--root-passwd" not in command
