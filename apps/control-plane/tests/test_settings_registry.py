"""Settings registry: schema, env/override precedence, validation, delegation, RBAC, audit."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from mrk_control_plane import config
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.settings_registry import (
    GROUP_IDS,
    GROUPS,
    SettingError,
    coerce,
    registry,
)

from .helpers import login_owner

PASSWORD = "a-long-role-password-123"  # noqa: S105 - test-only fixture
REPO = Path(__file__).resolve().parents[3]
SECRET_PASSPHRASE = "very-secret-passphrase-value-42"  # noqa: S105 - test-only fixture

# MRK_* names that are not operator settings: test/CI-only switches and the
# variables the agent passes into `docker exec` for database dumps.
IGNORED_ENV_NAMES = frozenset(
    {
        "MRK_DB_NAME", "MRK_DB_USER", "MRK_DB_PASSWORD",  # agent backup exec env (internal)
        "MRK_PGLITE_URL", "MRK_SMOKE_DATABASE_URL",  # CI smoke tests
        "MRK_E2E_KEEP_WORKDIR", "MRK_DBADMIN_DOCKER_TESTS", "MRK_INITIAL_ADMIN",  # test tools
        "MRK_ADMIN_ORIGIN", "MRK_NPM_ORIGIN", "MRK_PYPI_ORIGIN",  # load-test targets
        "MRK_S3_",  # documentation prefix ("MRK_S3_* variables")
        "MRK_VERSION",  # a Dokploy project variable the admin may define, not read by the panel
    }
)
SCANNED = ("apps/control-plane/src", "deploy", "scripts")
SCANNED_FILES = ("compose.yaml", ".env.example")
SUFFIXES = {".py", ".sh", ".yaml", ".yml", ".conf", ".example", ""}


def role_client(owner: TestClient, headers: dict[str, str], role: str):
    created = owner.post(
        "/api/v1/users",
        headers=headers,
        json={"username": f"{role}1", "password": PASSWORD, "role": role},
    )
    assert created.status_code == 201, created.text
    client = TestClient(owner.app)
    login = client.post("/api/v1/auth/login", json={"username": f"{role}1", "password": PASSWORD})
    assert login.status_code == 200
    return client, {"X-CSRF-Token": str(login.json()["csrf_token"])}


def items_by_key(payload: dict) -> dict[str, dict]:
    return {item["key"]: item for group in payload["groups"] for item in group["items"]}


@pytest.fixture
def clean_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("MRK_"):
            monkeypatch.delenv(name)
    yield monkeypatch


# ---- schema -------------------------------------------------------------------------


def test_registry_schema_is_complete_and_consistent() -> None:
    specs = registry().specs
    assert len(specs) >= 230
    assert len(GROUPS) == 17 and len(set(GROUP_IDS)) == 17
    assert {spec.group for spec in specs.values()} == set(GROUP_IDS)
    for spec in specs.values():
        assert re.fullmatch(r"[a-z0-9_]+(\.[a-z0-9_]+)+", spec.key), spec.key
        assert spec.description_fa and spec.description_en and spec.label_fa, spec.key
        assert re.search(r"[؀-ۿ]", spec.description_fa), spec.key
        if spec.source == "startup":
            assert spec.restart_required and spec.env and spec.env.startswith("MRK_")
            assert spec.overridable == (spec.write_permission == "settings:write"), spec.key
            assert spec.overridable or spec.env_only_reason, spec.key
        if spec.type in {"int", "float", "duration", "bytes"} and spec.min is not None:
            if spec.default is not None and spec.max is not None:
                assert spec.min <= spec.default <= spec.max, spec.key
        if spec.secret:
            assert not spec.overridable, spec.key
    envs = [spec.env for spec in specs.values() if spec.env]
    assert len(envs) == len(set(envs)), "an env name is registered twice"


def _flatten(payload: dict, prefix: tuple[str, ...] = ()) -> dict[tuple[str, ...], object]:
    out: dict[tuple[str, ...], object] = {}
    for key, value in payload.items():
        if isinstance(value, dict) and value and key not in {"mirrors", "registry_proxies"}:
            out.update(_flatten(value, (*prefix, key)))
        else:
            out[(*prefix, key)] = value
    return out


def test_every_module_setting_has_a_spec_with_the_same_default() -> None:
    from mrk_control_plane.modules import (
        dbadmin_policy,
        dns,
        dokploy,
        domains_settings,
        firewall_engine,
        monitoring_math,
        notifications_engine,
        s3_store,
        server_backups_cron,
        updates_settings,
        vuln_settings,
    )
    from mrk_control_plane.netresolve import DnsConfig

    by_path = {
        (spec.module, spec.path): spec
        for spec in registry().specs.values()
        if spec.source == "runtime"
    }
    modules = {
        "monitoring": monitoring_math.DEFAULT_SETTINGS,
        "updates": updates_settings.DEFAULT_SETTINGS,
        "vuln": vuln_settings.DEFAULT_SETTINGS,
        "notifications": notifications_engine.DEFAULT_SETTINGS,
        "s3": s3_store.DEFAULT_SETTINGS,
        "firewall": firewall_engine.DEFAULT_SETTINGS,
        "dbadmin": dbadmin_policy.default_settings(),
        "dokploy": {name: default for name, _env, default, _lo, _hi in dokploy.TUNABLES},
        "server_backups": {"timezone": server_backups_cron.DEFAULT_TIMEZONE},
        "services": domains_settings.DEFAULT_SETTINGS,
        "dns": dns.DEFAULT_SETTINGS,
        "network": {"dns": DnsConfig().public()},
    }
    for module, defaults in modules.items():
        for path, default in _flatten(dict(defaults)).items():
            spec = by_path.get((module, path))
            assert spec is not None, f"{module}.{'.'.join(path)} has no registry entry"
            assert spec.default == default, spec.key


def test_every_mrk_env_name_in_the_code_is_registered() -> None:
    pattern = re.compile(r"(?<![A-Za-z0-9_])MRK_[A-Z0-9_]+")
    found: dict[str, str] = {}
    paths = [REPO / name for name in SCANNED_FILES]
    for root in SCANNED:
        paths.extend(item for item in (REPO / root).rglob("*") if item.is_file())
    for path in paths:
        if not path.is_file() or "__pycache__" in path.parts or "node_modules" in path.parts:
            continue
        if path.suffix not in SUFFIXES and path.name != "Dockerfile":
            continue
        for name in pattern.findall(path.read_text(encoding="utf-8", errors="ignore")):
            found.setdefault(name, str(path.relative_to(REPO)))
    registered = {spec.env for spec in registry().specs.values() if spec.env}
    prefixes = {name[:-1] for name in registered if name.endswith("*")}
    missing = sorted(
        name for name in found
        if name not in registered
        and name not in IGNORED_ENV_NAMES
        and not any(name.startswith(prefix) for prefix in prefixes)
    )
    assert not missing, {name: found[name] for name in missing}
    assert len(found) > 100


# ---- validation -------------------------------------------------------------------


def test_validation_by_type_range_and_enum() -> None:
    specs = registry().specs
    ttl = specs["auth.session_ttl_seconds"]
    assert coerce(ttl, 3600) == 3600
    assert coerce(ttl, 3600.0) == 3600
    for bad in (10, 10**9, "3600", True, 3600.5, None):
        with pytest.raises(SettingError):
            coerce(ttl, bad)
    level = specs["system.log_level"]
    assert coerce(level, "DEBUG") == "DEBUG"
    with pytest.raises(SettingError):
        coerce(level, "LOUD")
    with pytest.raises(SettingError):
        coerce(specs["npm.enabled"], "yes")
    proxies = specs["web.trusted_proxies"]
    assert coerce(proxies, ["10.0.0.0/8", "127.0.0.1"]) == ["10.0.0.0/8", "127.0.0.1"]
    assert coerce(proxies, "10.0.0.1, 10.0.0.1") == ["10.0.0.1"]
    with pytest.raises(SettingError):
        coerce(proxies, ["not-an-ip"])
    with pytest.raises(SettingError):
        coerce(specs["web.trusted_hosts"], ["panel.example.com"])  # would break healthcheck
    with pytest.raises(SettingError):
        coerce(specs["npm.health_host"], "10.0.0.5")
    with pytest.raises(SettingError):
        coerce(specs["pypi.primary_upstream"], "ftp://example.com")
    with pytest.raises(SettingError):
        coerce(specs["notifications.quiet_hours.start"], "25:00")
    with pytest.raises(SettingError):
        coerce(specs["server_backups.timezone"], "Mars/Base")
    assert coerce(specs["s3.default_quota_bytes"], None) is None


# ---- precedence ---------------------------------------------------------------------


def _write_overrides(data_dir: Path, values: dict[str, str]) -> None:
    path = config.overrides_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "values": values}), encoding="utf-8")


def test_env_wins_over_override_which_wins_over_default(tmp_path: Path, clean_env) -> None:
    clean_env.setenv("MRK_DATA_DIR", str(tmp_path))
    _write_overrides(
        tmp_path,
        {"MRK_LOGIN_RATE_LIMIT_ATTEMPTS": "7", "MRK_CATALOG_CACHE_SECONDS": "5",
         "MRK_DATA_DIR": "/elsewhere", "MRK_SESSION_TTL_SECONDS": "3600"},
    )
    assert config.setting_env("MRK_LOGIN_RATE_LIMIT_ATTEMPTS", "5") == "7"
    assert config.setting_env("MRK_NPM_BLOCK_POLL_SECONDS", "30") == "30"
    clean_env.setenv("MRK_LOGIN_RATE_LIMIT_ATTEMPTS", "9")
    assert config.resolve_env("MRK_LOGIN_RATE_LIMIT_ATTEMPTS", "5") == ("9", "env")
    # Bootstrap names never come from the file.
    assert config.load_overrides(config.overrides_path(tmp_path)).get("MRK_DATA_DIR") is None
    # A value equal to the image's Dockerfile default is not an operator choice.
    clean_env.setenv("MRK_SESSION_TTL_SECONDS", "43200")
    assert config.resolve_env("MRK_SESSION_TTL_SECONDS", "43200") == ("3600", "override")
    clean_env.setenv("MRK_SESSION_TTL_SECONDS", "7200")
    assert config.resolve_env("MRK_SESSION_TTL_SECONDS", "43200") == ("7200", "env")

    settings = Settings.from_env()
    assert settings.login_rate_limit_attempts == 9  # env
    assert settings.session_ttl_seconds == 7200

    clean_env.delenv("MRK_LOGIN_RATE_LIMIT_ATTEMPTS")
    assert Settings.from_env().login_rate_limit_attempts == 7  # override file


def test_apply_startup_overrides_injects_only_missing_names(tmp_path: Path, clean_env) -> None:
    clean_env.setenv("MRK_DATA_DIR", str(tmp_path))
    clean_env.setenv("MRK_PYPI_ROUTER_COOLDOWN", "45")
    _write_overrides(
        tmp_path, {"MRK_CATALOG_CACHE_SECONDS": "5", "MRK_PYPI_ROUTER_COOLDOWN": "99"}
    )
    clean_env.setenv("MRK_CATALOG_CACHE_SECONDS", "placeholder")
    clean_env.delenv("MRK_CATALOG_CACHE_SECONDS")  # registers cleanup with monkeypatch
    try:
        applied = config.apply_startup_overrides(tmp_path)
        assert applied == {"MRK_CATALOG_CACHE_SECONDS"}
        assert os.environ["MRK_CATALOG_CACHE_SECONDS"] == "5"
        assert os.environ["MRK_PYPI_ROUTER_COOLDOWN"] == "45"
        # Injected names are not reported as operator environment.
        assert config.explicit_env("MRK_CATALOG_CACHE_SECONDS") is None
        from mrk_control_plane.pypi_router import RouterSettings

        assert RouterSettings.from_env().cooldown_seconds == 45.0
    finally:
        config.INJECTED_ENV_NAMES.discard("MRK_CATALOG_CACHE_SECONDS")


def test_invalid_override_file_falls_back_to_defaults(tmp_path: Path, clean_env) -> None:
    clean_env.setenv("MRK_DATA_DIR", str(tmp_path))
    path = config.overrides_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")
    assert config.load_overrides(path) == {}
    assert Settings.from_env().login_rate_limit_attempts == 5


# ---- API ---------------------------------------------------------------------------------


@pytest.fixture
def app_env(tmp_path: Path, clean_env):
    data_dir = tmp_path / "cp"
    clean_env.setenv("MRK_DATA_DIR", str(data_dir))
    clean_env.setenv("MRK_BACKUP_PASSPHRASE", SECRET_PASSPHRASE)
    app = create_app(Settings.for_test(data_dir))
    return app, data_dir, clean_env


def test_registry_listing_hides_secrets_and_reports_sources(app_env) -> None:
    app, _data_dir, env = app_env
    env.setenv("MRK_CATALOG_CACHE_SECONDS", "10")
    with TestClient(app) as owner:
        login_owner(owner)
        response = owner.get("/api/v1/settings/registry")
        assert response.status_code == 200
        payload = response.json()
        assert SECRET_PASSPHRASE not in response.text
        assert len(payload["groups"]) == 17
        group = payload["groups"][0]
        assert {"id", "name_fa", "name_en", "items"} <= set(group)
        items = items_by_key(payload)
        secret = items["backup.passphrase"]
        assert secret["value"] is None and secret["secret_configured"] is True
        assert secret["editable"] is False and secret["env_only_note"]["fa"]
        cache = items["catalog.cache_seconds"]
        assert cache["value"] == 10.0 and cache["effective_source"] == "env"
        assert cache["locked_by_env"] is True and cache["editable"] is False
        ttl = items["auth.session_ttl_seconds"]
        assert ttl["effective_source"] == "default" and ttl["editable"] is True
        assert ttl["description_fa"] and ttl["description_en"]
        cpu = items["monitoring.alerts.cpu_percent"]
        assert cpu["value"] == 90 and cpu["effective_source"] == "runtime"
        assert items["firewall.mode"]["editable"] is False  # typed confirmation on its page
        assert items["auth.argon2.time_cost"]["source"] == "constant"
        assert items["network.proxies"]["value"] is None  # collections never echoed
        assert anonymous_status(app) == 401


def anonymous_status(app) -> int:
    return TestClient(app).get("/api/v1/settings/registry").status_code


def test_startup_override_write_precedence_restart_and_reset(app_env) -> None:
    app, data_dir, env = app_env
    with TestClient(app) as owner:
        headers = {"X-CSRF-Token": str(login_owner(owner)["csrf_token"])}
        key = "auth.login_rate_limit.attempts"
        assert owner.put(f"/api/v1/settings/registry/{key}", json={"value": 7}).status_code == 403
        response = owner.put(
            f"/api/v1/settings/registry/{key}", headers=headers, json={"value": 7}
        )
        assert response.status_code == 200, response.text
        item = response.json()["item"]
        assert item["value"] == 7 and item["effective_source"] == "override"
        assert item["pending_restart"] is True
        path = config.overrides_path(data_dir)
        stored = json.loads(path.read_text(encoding="utf-8"))
        assert stored["values"] == {"MRK_LOGIN_RATE_LIMIT_ATTEMPTS": "7"}
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
        restart = owner.get("/api/v1/settings/registry/restart").json()
        assert restart["pending"] is True and restart["keys"] == [key]
        assert restart["processes"] == ["control-plane"]
        # The next process start reads it (MRK_DATA_DIR points at the same data dir).
        assert Settings.from_env().login_rate_limit_attempts == 7

        # Explicit env locks the key.
        env.setenv("MRK_LOGIN_RATE_LIMIT_ATTEMPTS", "3")
        locked = owner.put(f"/api/v1/settings/registry/{key}", headers=headers, json={"value": 8})
        assert locked.status_code == 409
        assert locked.json()["error"]["code"] == "setting_locked_by_env"
        env.delenv("MRK_LOGIN_RATE_LIMIT_ATTEMPTS")

        reset = owner.delete(f"/api/v1/settings/registry/{key}", headers=headers)
        assert reset.status_code == 200
        assert reset.json()["item"]["effective_source"] == "default"
        assert reset.json()["item"]["value"] == 5
        assert owner.get("/api/v1/settings/registry/restart").json()["pending"] is False


def test_api_validation_and_read_only_entries(app_env) -> None:
    app, _data_dir, _env = app_env
    with TestClient(app) as owner:
        headers = {"X-CSRF-Token": str(login_owner(owner)["csrf_token"])}

        def put(key: str, value) -> tuple[int, str]:
            response = owner.put(
                f"/api/v1/settings/registry/{key}", headers=headers, json={"value": value}
            )
            return response.status_code, response.json().get("error", {}).get("code", "")

        assert put("auth.session_ttl_seconds", 60) == (422, "invalid_setting_value")
        assert put("system.log_level", "LOUD") == (422, "invalid_setting_value")
        assert put("npm.enabled", "true") == (422, "invalid_setting_value")
        assert put("web.trusted_hosts", ["panel.example.com"]) == (422, "invalid_setting_value")
        assert put("no.such.key", 1) == (404, "unknown_setting")
        assert put("system.data_dir", "/tmp/x") == (409, "setting_env_only")  # noqa: S108
        assert put("backup.passphrase", "x") == (409, "setting_env_only")
        assert put("auth.argon2.time_cost", 4) == (409, "setting_read_only")
        assert put("firewall.mode", "enforce") == (409, "setting_edited_elsewhere")
        raw = owner.put(
            "/api/v1/settings/registry/system.log_level", headers=headers, content=b"{nope"
        )
        assert raw.status_code == 422
        missing = owner.put(
            "/api/v1/settings/registry/system.log_level", headers=headers, json={"other": 1}
        )
        assert missing.status_code == 422
        # The module's own cross-field validator still runs.
        assert put("monitoring.hour_retention_days", 3) == (422, "invalid_settings")


def test_runtime_keys_delegate_to_their_modules(app_env) -> None:
    from mrk_control_plane.modules import dbadmin, monitoring, notifications, s3, updates

    app, _data_dir, _env = app_env
    with TestClient(app) as owner:
        headers = {"X-CSRF-Token": str(login_owner(owner)["csrf_token"])}

        def put(key: str, value) -> dict:
            response = owner.put(
                f"/api/v1/settings/registry/{key}", headers=headers, json={"value": value}
            )
            assert response.status_code == 200, (key, response.text)
            return response.json()["item"]

        assert put("monitoring.alerts.cpu_percent", 70)["value"] == 70
        assert monitoring.ACTIVE_SERVICE.settings["alerts"]["cpu_percent"] == 70
        assert monitoring.ACTIVE_SERVICE.settings["alerts"]["mem_percent"] == 90
        put("updates.concurrency", 8)
        assert updates.ACTIVE_SERVICE.settings["concurrency"] == 8
        put("notifications.quiet_hours.start", "22:30")
        quiet = notifications.ACTIVE_CENTER.get_settings()["quiet_hours"]
        assert quiet["start"] == "22:30" and quiet["end"] == "07:00"
        put("s3.region", "ir-thr-1")
        assert s3.ACTIVE_STORE.get_settings()["region"] == "ir-thr-1"
        put("dbadmin.max_rows", 50)
        assert dbadmin.ACTIVE_SERVICE.settings()["max_rows"] == 50
        put("network.dns.timeout_seconds", 3.5)
        network = owner.get("/api/v1/settings/network").json()
        assert network["dns"]["timeout_seconds"] == 3.5
        put("network.allow_private_upstreams", True)
        assert owner.get("/api/v1/settings/network").json()["upstream_policy"] == {
            "allow_private_upstreams": True
        }
        put("firewall.notify", False)
        assert owner.get("/api/v1/firewall/settings").json()["notify"] is False
        put("server_backups.timezone", "UTC")
        assert owner.get("/api/v1/server-backups/settings").json()["timezone"] == "UTC"
        put("auth.registration.enabled", True)
        assert owner.get("/api/v1/settings/registration").json()["enabled"] is True

        reset = owner.delete(
            "/api/v1/settings/registry/monitoring.alerts.cpu_percent", headers=headers
        )
        assert reset.status_code == 200 and reset.json()["item"]["value"] == 90
        assert monitoring.ACTIVE_SERVICE.settings["alerts"]["cpu_percent"] == 90
        # Dokploy tunables need a connection first.
        response = owner.put(
            "/api/v1/settings/registry/dokploy.cache_seconds", headers=headers, json={"value": 5}
        )
        assert response.status_code == 409


def test_permission_filtering_and_audit(app_env) -> None:
    app, _data_dir, _env = app_env
    with TestClient(app) as owner:
        headers = {"X-CSRF-Token": str(login_owner(owner)["csrf_token"])}
        viewer, viewer_headers = role_client(owner, headers, "viewer")
        admin, admin_headers = role_client(owner, headers, "admin")

        viewer_items = items_by_key(viewer.get("/api/v1/settings/registry").json())
        assert "notifications.max_attempts" not in viewer_items  # notification:read
        assert "dbadmin.max_rows" not in viewer_items  # db:read
        assert "monitoring.enabled" in viewer_items  # metrics:read
        assert all(not item["editable"] for item in viewer_items.values())
        denied = viewer.put(
            "/api/v1/settings/registry/monitoring.enabled", headers=viewer_headers,
            json={"value": False},
        )
        assert denied.status_code == 403
        hidden = viewer.put(
            "/api/v1/settings/registry/notifications.max_attempts", headers=viewer_headers,
            json={"value": 3},
        )
        assert hidden.status_code == 403

        admin_items = items_by_key(admin.get("/api/v1/settings/registry").json())
        assert admin_items["monitoring.enabled"]["editable"] is True
        assert admin_items["auth.session_ttl_seconds"]["editable"] is False  # owner only
        startup = admin.put(
            "/api/v1/settings/registry/auth.session_ttl_seconds", headers=admin_headers,
            json={"value": 3600},
        )
        assert startup.status_code == 403
        runtime = admin.put(
            "/api/v1/settings/registry/monitoring.interval_seconds", headers=admin_headers,
            json={"value": 30},
        )
        assert runtime.status_code == 200

        owner.put(
            "/api/v1/settings/registry/backup.retain_count", headers=headers, json={"value": 12345}
        )
        owner.put(
            "/api/v1/settings/registry/backup.retain_count", headers=headers, json={"value": 3}
        )
        events = app.state.auth_store.list_audit(200)
        registry_events = [e for e in events if str(e["action"]).startswith("settings.registry")]
        assert {
            (e["object_id"], e["result"]) for e in registry_events
        } >= {
            ("monitoring.interval_seconds", "success"),
            ("backup.retain_count", "success"),
            ("backup.retain_count", "failure"),
        }
        for event in registry_events:
            assert event["object_type"] == "setting"
            assert "12345" not in json.dumps(event) and "3600" not in str(event["object_id"])
