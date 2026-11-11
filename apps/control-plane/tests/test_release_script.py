"""scripts/release.py: one version in every file, a changelog section, nothing else touched."""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
FILES = ("VERSION", "CHANGELOG.md", "compose.yaml", "apps/control-plane/pyproject.toml",
         "apps/control-plane/src/mrk_control_plane/__init__.py",
         "apps/admin-ui/package.json", "apps/admin-ui/package-lock.json")


def load(root: Path):
    spec = importlib.util.spec_from_file_location("release_script", REPO / "scripts/release.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.ROOT = root
    return module


def copy_repo(tmp_path: Path) -> Path:
    for relative in FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / relative, target)
    return tmp_path


def test_the_repository_versions_agree() -> None:
    release = load(REPO)
    assert release.check() == []


def test_bump_writes_one_version_everywhere(tmp_path: Path) -> None:
    root = copy_repo(tmp_path)
    release = load(root)
    lock_before = json.loads((root / "apps/admin-ui/package-lock.json").read_text("utf-8"))
    release.bump("9.8.7")
    release.changelog("9.8.7", "2030-01-02")
    assert release.check() == []
    found = release.versions_found()
    assert found["VERSION"] == "9.8.7" and found["compose.yaml"] == ["9.8.7", "9.8.7"]
    lock = json.loads((root / "apps/admin-ui/package-lock.json").read_text("utf-8"))
    # Only the panel's own entries change; every dependency keeps its version.
    for name, entry in lock_before["packages"].items():
        if name:
            assert lock["packages"][name].get("version") == entry.get("version"), name
    changelog = (root / "CHANGELOG.md").read_text("utf-8")
    assert "## [Unreleased]\n\n## [9.8.7] - 2030-01-02" in changelog
    assert release.notes("9.8.7") == release.notes("9.8.7").strip()


def test_check_reports_a_file_that_disagrees(tmp_path: Path) -> None:
    root = copy_repo(tmp_path)
    release = load(root)
    (root / "VERSION").write_text("0.9.0\n", encoding="utf-8")
    problems = release.check()
    assert any("pyproject.toml" in problem for problem in problems)
    assert any("compose.yaml" in problem for problem in problems)
