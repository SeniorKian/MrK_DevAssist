from __future__ import annotations

from mrk_control_plane.modules import build_mirror_env as env

NPM = "https://npm.example.com/"
PYPI = "https://pypi.example.com/root/pypi/+simple/"


def test_block_is_added_replaced_and_removed_without_touching_the_rest() -> None:
    wanted = env.wanted_values(NPM, PYPI, ("npm", "pypi"))
    assert wanted == {"NPM_CONFIG_REGISTRY": NPM, "YARN_NPM_REGISTRY_SERVER": NPM,
                      "PIP_INDEX_URL": PYPI, "UV_DEFAULT_INDEX": PYPI}
    original = "DATABASE_URL=postgres://x\r\nNODE_ENV=production\n\n"
    applied = env.apply_block(original, wanted)
    assert applied.startswith("DATABASE_URL=postgres://x\nNODE_ENV=production\n\n" + env.BEGIN)
    assert applied.endswith(env.END)
    assert env.env_state(applied, wanted)["state"] == "applied"
    # Applying again replaces the block instead of adding a second one.
    again = env.apply_block(applied, env.wanted_values(NPM, None, ("npm",)))
    assert again.count(env.BEGIN) == 1 and "PIP_INDEX_URL" not in again
    assert env.env_state(again, wanted)["state"] == "outdated"
    assert env.strip_block(again) == "DATABASE_URL=postgres://x\nNODE_ENV=production"
    assert env.env_state("A=1", wanted)["state"] == "missing"
    assert env.strip_block(None) == ""


def test_names_set_outside_the_block_are_reported() -> None:
    wanted = env.wanted_values(NPM, None, ("npm",))
    text = env.apply_block("NPM_CONFIG_REGISTRY=https://registry.npmjs.org/\n# X=1", wanted)
    state = env.env_state(text, wanted)
    assert state["state"] == "applied" and state["overridden"] == ["NPM_CONFIG_REGISTRY"]


def test_plain_http_mirrors_are_marked_trusted() -> None:
    values = env.wanted_values("http://10.0.0.5:4873/", "http://10.0.0.5:3141/root/pypi/+simple/",
                               ("npm", "pypi"))
    assert values["PIP_TRUSTED_HOST"] == values["UV_INSECURE_HOST"] == "10.0.0.5"
    assert values["YARN_UNSAFE_HTTP_WHITELIST"] == "10.0.0.5"


def test_eligibility_by_build_type() -> None:
    assert env.eligibility({"buildType": "nixpacks", "sourceType": "github"}, "application") == (
        True, None)
    assert env.eligibility({"buildType": "railpack"}, "application")[0] is True
    assert env.eligibility({"buildType": "dockerfile"}, "application") == (
        False, "dockerfile_build")
    assert env.eligibility({"sourceType": "docker"}, "application") == (False, "no_build")
    assert env.eligibility({}, "compose") == (False, "compose_build")
    assert env.eligibility({"buildType": "nixpacks"}, "postgres") == (False, "not_buildable")
