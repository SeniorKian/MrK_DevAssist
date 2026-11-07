from pathlib import Path

from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app

from .helpers import login_owner


def test_cleanup_preview_and_integrity_enqueue(tmp_path: Path) -> None:
    package = tmp_path / "npm" / "storage" / "sample"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        '{"name":"sample","versions":{"1.0.0":{}}}', encoding="utf-8"
    )
    (package / "sample-1.0.0.tgz").write_bytes(b"package")
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        login = login_owner(client)
        csrf = str(login["csrf_token"])

        preview = client.get(
            "/api/v1/lifecycle/cleanup-preview?target_percent=20"
        )
        assert preview.status_code == 200
        assert preview.json()["dry_run"] is True
        assert isinstance(preview.json()["candidates"], list)

        scan = client.post(
            "/api/v1/lifecycle/integrity-scan",
            headers={"X-CSRF-Token": csrf},
        )
        assert scan.status_code == 202
        assert scan.json()["state"] == "pending"
