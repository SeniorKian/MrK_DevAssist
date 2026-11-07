import json
from pathlib import Path

from fastapi.testclient import TestClient
from mrk_control_plane.catalog import PackageCatalog
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app

from .helpers import login_owner


def _seed(data_dir: Path) -> None:
    pypi = data_dir / "pypi" / "server" / "+files" / "root" / "pypi" / "+f" / "abc"
    pypi.mkdir(parents=True)
    (pypi / "sampleproject-4.0.0-py3-none-any.whl").write_bytes(b"wheel")
    npm = data_dir / "npm" / "storage" / "left-pad"
    npm.mkdir(parents=True)
    (npm / "package.json").write_text(
        json.dumps({"name": "left-pad", "versions": {"1.3.0": {}}}),
        encoding="utf-8",
    )
    (npm / "left-pad-1.3.0.tgz").write_bytes(b"archive")


def test_catalog_scans_both_ecosystems_and_tracks_policy(tmp_path: Path) -> None:
    _seed(tmp_path)
    catalog = PackageCatalog(tmp_path)

    items = catalog.search()
    assert {(item["ecosystem"], item["name"]) for item in items} == {
        ("npm", "left-pad"),
        ("pypi", "sampleproject"),
    }
    catalog.set_policy("pypi", "sampleproject", pinned=True)
    sample = catalog.search("sample", "pypi")[0]
    assert sample["pinned"] is True
    assert catalog.purge_preview("pypi", "sampleproject")["blocked_by_pin"] is True


def test_catalog_api_search_policy_and_preview(tmp_path: Path) -> None:
    _seed(tmp_path)
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        csrf = str(login_owner(client)["csrf_token"])
        search = client.get("/api/v1/packages?q=sample&ecosystem=pypi")
        assert search.status_code == 200
        assert search.json()["items"][0]["name"] == "sampleproject"

        policy = client.put(
            "/api/v1/packages/pypi/sampleproject/policy",
            headers={"X-CSRF-Token": csrf},
            json={"pinned": True, "quarantined": True, "quarantine_reason": "review"},
        )
        assert policy.status_code == 200
        preview = client.post(
            "/api/v1/packages/pypi/sampleproject/purge-preview",
            headers={"X-CSRF-Token": csrf},
        )
        assert preview.status_code == 200
        assert preview.json()["blocked_by_pin"] is True
        assert preview.json()["confirmation"] == "PURGE pypi/sampleproject"
