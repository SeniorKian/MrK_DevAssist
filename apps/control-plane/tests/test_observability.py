import io
import json
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app

from .helpers import login_owner


def test_metrics_audit_export_and_support_bundle(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))
    with TestClient(app) as client:
        assert client.get("/metrics").status_code == 401
        login_owner(client)

        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert "mrk_uptime_seconds" in metrics.text
        assert 'mrk_tasks_total{state="pending"}' in metrics.text
        assert "text/plain" in metrics.headers["content-type"]

        export = client.get("/api/v1/audit-events/export.csv")
        assert export.status_code == 200
        assert "attachment" in export.headers["content-disposition"]
        assert "action" in export.text

        bundle = client.get("/api/v1/support-bundle")
        assert bundle.status_code == 200
        with zipfile.ZipFile(io.BytesIO(bundle.content)) as archive:
            assert set(archive.namelist()) == {
                "manifest.json",
                "system.json",
                "upstreams.json",
                "tasks.json",
                "audit.json",
                "packages.json",
            }
            manifest = json.loads(archive.read("manifest.json"))
            assert manifest["contains_secrets"] is False
