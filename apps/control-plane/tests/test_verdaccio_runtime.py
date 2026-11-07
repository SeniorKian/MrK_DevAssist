from pathlib import Path

from mrk_control_plane.secret_store import SecretStore
from mrk_control_plane.upstream_store import UpstreamStore
from mrk_control_plane.verdaccio_runtime import build_runtime_config


def test_verdaccio_runtime_uses_dynamic_uplinks_and_secret_environment(tmp_path: Path) -> None:
    upstreams = UpstreamStore(tmp_path)
    upstreams.ensure_defaults(
        "https://pypi.org/simple/",
        "https://package-mirror.liara.ir/repository/pypi/simple/",
    )
    npmjs = next(
        item
        for item in upstreams.raw_list()
        if item["ecosystem"] == "npm" and item["name"] == "npmjs.org"
    )
    reference, updated_at = SecretStore(tmp_path).replace(
        None, {"token": "private-npm-token"}
    )
    upstreams.update(
        str(npmjs["id"]),
        {
            "credential_ref": reference,
            "credential_type": "bearer",
            "credential_updated_at": updated_at,
        },
    )

    config_path, environment = build_runtime_config(tmp_path)
    config = config_path.read_text(encoding="utf-8")
    env_name = f"MRK_NPM_UPLINK_TOKEN_{str(npmjs['id']).upper()}"

    assert "registry.npmjs.org" in config
    assert "package-mirror.liara.ir/repository/npm" in config
    assert f"token_env: {env_name}" in config
    assert "private-npm-token" not in config
    assert environment[env_name] == "private-npm-token"
    assert config_path.stat().st_size > 0


def test_verdaccio_offline_mode_removes_all_proxy_routes(tmp_path: Path) -> None:
    upstreams = UpstreamStore(tmp_path)
    upstreams.ensure_defaults(
        "https://pypi.org/simple/",
        "https://package-mirror.liara.ir/repository/pypi/simple/",
    )
    upstreams.set_offline("npm", True)

    config_path, _environment = build_runtime_config(tmp_path)
    config = config_path.read_text(encoding="utf-8")

    assert "uplinks:\n  {}" in config
    assert "proxy:" not in config
