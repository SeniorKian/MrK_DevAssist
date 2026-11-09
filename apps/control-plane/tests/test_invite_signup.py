"""«My space» invite-driven sign-up (docs/43 §0.1): an invite to an email without an
account lets that person create one from the link and join with the invited role."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from .test_my_space import (  # noqa: F401 - env/space are fixtures
    MY,
    PASSWORD,
    Space,
    User,
    code,
    env,
    space,
    unlimited,
)

PREVIEW = "/api/v1/auth/workspace-invite"
REGISTER = "/api/v1/auth/workspace-invite/register"


def _team(space: Space) -> tuple[User, str]:  # noqa: F811
    alice = space.user("alice")
    unlimited(space, alice)
    team = alice.post("/workspaces", {"name": "Alice team"})
    assert team.status_code == 201, team.text
    return alice, team.json()["id"]


def _invite(owner: User, team: str, email: str, role: str = "member") -> str:
    made = owner.post(f"/workspaces/{team}/invites", {"email": email, "role": role})
    assert made.status_code == 201, made.text
    return str(made.json()["token"])


def _form(token: str, **extra: Any) -> dict[str, Any]:
    return {"token": token, "display_name": "New Person", "password": PASSWORD,
            "password_confirmation": PASSWORD, **extra}


def test_invite_signup_open(space: Space) -> None:  # noqa: F811
    alice, team = _team(space)
    token = _invite(alice, team, "New@Example.test", role="member")
    anon = TestClient(space.client.app)
    preview = anon.post(PREVIEW, json={"token": token})
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["email"] == "new@example.test" and body["role"] == "member"
    assert body["workspace"]["name"] == "Alice team" and body["account_exists"] is False
    assert body["signup"] == "off" and "min_length" in str(body["password_policy"])
    # Default: invites follow tenancy.signup (off) — no account.
    refused = anon.post(REGISTER, json=_form(token))
    assert refused.status_code == 403 and code(refused) == "invite_signup_off"
    space.settings(invite_signup="open")
    assert anon.post(PREVIEW, json={"token": token}).json()["signup"] == "open"
    short = "short"
    weak = anon.post(REGISTER, json={**_form(token), "password": short,
                                     "password_confirmation": short})
    assert weak.status_code == 422, weak.text
    mismatch = anon.post(REGISTER, json=_form(token, password_confirmation=PASSWORD + "x"))
    assert mismatch.status_code == 422 and code(mismatch) == "password_mismatch"
    created = anon.post(REGISTER, json=_form(token))
    assert created.status_code == 201, created.text
    joined = created.json()
    assert joined["workspace_id"] == team and joined["role"] == "member"
    assert joined["user"]["role"] == "customer" and joined["invite_error"] is None
    assert joined["user"]["email"] == "new@example.test"
    me = anon.get(f"{MY}/me").json()
    roles = {item["id"]: item["role"] for item in me["workspaces"]}
    assert roles[team] == "member" and len(roles) == 2  # team + own personal space
    # The invite is used up; the same link cannot make a second account.
    again = TestClient(space.client.app).post(REGISTER, json=_form(token))
    assert again.status_code == 404
    assert TestClient(space.client.app).post(PREVIEW, json={"token": token}).status_code \
        == 404
    members = alice.get(f"/workspaces/{team}/members").json()["items"]
    assert any(item.get("role") == "member" and item.get("user_id") != alice.id
               for item in members)


def test_invite_signup_with_approval_and_reject(space: Space) -> None:  # noqa: F811
    alice, team = _team(space)
    space.settings(signup="approval")  # invite_signup "follow" → approval
    anon = TestClient(space.client.app)
    token = _invite(alice, team, "wait@example.test", role="viewer")
    pending = anon.post(REGISTER, json=_form(token))
    assert pending.status_code == 202, pending.text
    assert pending.json()["status"] == "pending_approval"
    assert pending.json()["workspace_id"] == team
    login = {"username": "wait@example.test", "password": PASSWORD}
    assert anon.post("/api/v1/auth/login", json=login).status_code == 401
    signups = space.admin("GET", "/signups").json()["items"]
    first = next(item for item in signups if item["user"]["email"] == "wait@example.test")
    assert space.admin("POST", f"/signups/{first['id']}/approve", json={}).status_code == 200
    assert anon.post("/api/v1/auth/login", json=login).status_code == 200
    roles = {item["id"]: item["role"] for item in anon.get(f"{MY}/me").json()["workspaces"]}
    assert roles[team] == "viewer"

    # A rejected invite sign-up also leaves the team.
    other = _invite(alice, team, "nope@example.test")
    assert TestClient(space.client.app).post(REGISTER, json=_form(other)).status_code == 202
    signups = space.admin("GET", "/signups").json()["items"]
    second = next(item for item in signups if item["user"]["email"] == "nope@example.test")
    before = len(alice.get(f"/workspaces/{team}/members").json()["items"])
    assert space.admin("POST", f"/signups/{second['id']}/reject", json={}).status_code == 200
    assert len(alice.get(f"/workspaces/{team}/members").json()["items"]) == before - 1


def test_invite_signup_guards(space: Space) -> None:  # noqa: F811
    alice, team = _team(space)
    space.settings(signup="open", invite_signup="off")
    anon = TestClient(space.client.app)
    token = _invite(alice, team, "x@example.test")
    blocked = anon.post(REGISTER, json=_form(token))
    assert blocked.status_code == 403 and code(blocked) == "invite_signup_off"
    space.settings(invite_signup="open")
    # An existing account must sign in and accept instead.
    space.user("frank", email="frank@example.test")
    existing = _invite(alice, team, "frank@example.test")
    assert anon.post(PREVIEW, json={"token": existing}).json()["account_exists"] is True
    clash = anon.post(REGISTER, json=_form(existing))
    assert clash.status_code == 409 and code(clash) == "account_exists"
    # Unknown or malformed tokens look the same.
    assert anon.post(PREVIEW, json={"token": "x" * 40}).status_code == 404
    assert anon.post(REGISTER, json=_form("x" * 40)).status_code == 404
    bad = space.admin("PUT", "/tenancy/settings", json={"invite_signup": "always"})
    assert bad.status_code == 422
    # Members quota is checked before the account is made.
    space.workspace_patch(team, quota_overrides={"members": 1})
    full = anon.post(REGISTER, json=_form(token))
    assert full.status_code == 409 and code(full) == "quota_exceeded"
    assert anon.post("/api/v1/auth/login", json={"username": "x@example.test",
                                                 "password": PASSWORD}).status_code == 401
    # «My space» off: the routes are not there.
    space.settings(enabled=False)
    assert anon.post(PREVIEW, json={"token": token}).status_code == 404
