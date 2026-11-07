from pathlib import Path

from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app

from .helpers import login_owner


def test_task_api_enqueue_list_cancel_and_retry(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))
    client = TestClient(app)
    try:
        csrf = str(login_owner(client)["csrf_token"])
        headers = {"X-CSRF-Token": csrf}

        created = client.post(
            "/api/v1/packages/pypi/sampleproject/revalidate", headers=headers
        )
        assert created.status_code == 202
        task_id = str(created.json()["task_id"])

        listed = client.get("/api/v1/tasks")
        assert listed.status_code == 200
        assert any(item["id"] == task_id for item in listed.json()["items"])

        cancelled = client.post(f"/api/v1/tasks/{task_id}/cancel", headers=headers)
        assert cancelled.status_code == 200

        retried = client.post(f"/api/v1/tasks/{task_id}/retry", headers=headers)
        assert retried.status_code == 202
        assert retried.json()["task_id"] != task_id
    finally:
        client.close()


def test_task_api_rejects_retry_while_task_is_active(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))
    client = TestClient(app)
    try:
        csrf = str(login_owner(client)["csrf_token"])
        headers = {"X-CSRF-Token": csrf}
        created = client.post(
            "/api/v1/packages/pypi/sampleproject/revalidate", headers=headers
        )

        retried = client.post(
            f"/api/v1/tasks/{created.json()['task_id']}/retry", headers=headers
        )
        assert retried.status_code == 409
    finally:
        client.close()
