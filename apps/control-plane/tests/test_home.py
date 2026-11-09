"""Home summary rules, permission filtering and resilience (docs/33 §1.2)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient
from mrk_control_plane.auth import ROLE_PERMISSIONS, Principal
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import home

from .helpers import login_owner

NOW = 1_800_000_000.0
DAY = 86400
PASSWORD = "a-strong-password-123"  # noqa: S105 - test-only fixture


def principal(role: str) -> Principal:
    return Principal(1, role, role, ROLE_PERMISSIONS[role], 1, "")


def broken_facts() -> dict:
    """Facts that trip every one of the 13 rules."""
    return {
        "core": {"components": {"npm_registry": "unavailable", "pypi_registry": "ready",
                                "database": "ready"},
                 "storage_used_percent": 91.0},
        "monitoring": {"disk_threshold": 85, "host_disk_percent": 97.2},
        "upstreams": {"ecosystems": {
            "npm": {"offline": True, "enabled_count": 2, "usable_count": 2},
            "pypi": {"offline": False, "enabled_count": 2, "usable_count": 0,
                     "blocked_count": 1, "failing_count": 1},
        }},
        "agent": {"configured": True, "reachable": False, "last_checked_at": NOW - 60},
        "backups": {"jobs": [
            {"id": "j1", "name": "DB main", "enabled": True, "last_state": "failed",
             "last_run_at": NOW - 3600, "last_error_code": "dump_failed",
             "last_success_at": NOW - 3 * DAY, "interval_seconds": DAY, "created_at": 0},
            {"id": "j2", "name": "Files", "enabled": True, "last_state": "succeeded",
             "last_success_at": NOW - 3 * DAY, "interval_seconds": DAY, "created_at": 0},
            {"id": "j3", "name": "Paused", "enabled": False, "last_state": "failed"},
        ]},
        "updates": {"available": 3},
        "vuln": {"critical": 1, "high": 1},
        "firewall": {"configured": True, "mode": "dry_run", "since": NOW - 10 * DAY},
        "notifications": {"channels": 0},
        "tasks": {"failed_24h": 1},
        "s3": {"buckets": 2, "public_endpoint": False},
        "people": {"users": 1, "cached_packages": 0},
        "domains": {"count": 1, "problems": [{"id": "d1", "host": "npm.example.com",
                                              "service_id": "npm", "problem_code": "dns_missing"}]},
        "dns": {"installed": True, "reachable": False, "error_code": "dns_unreachable",
                "checked_at": NOW - 30, "setup_complete": False},
    }


def healthy_facts() -> dict:
    return {
        "core": {"components": {"npm_registry": "ready", "database": "ready"},
                 "storage_used_percent": 40.0},
        "monitoring": {"disk_threshold": 85, "host_disk_percent": 50.0},
        "upstreams": {"ecosystems": {"npm": {"offline": False, "enabled_count": 2,
                                             "usable_count": 1}}},
        "agent": {"configured": True, "reachable": True},
        "backups": {"jobs": [{"id": "j1", "name": "DB", "enabled": True,
                              "last_state": "succeeded", "last_success_at": NOW - 3600,
                              "interval_seconds": DAY, "created_at": 0}]},
        "updates": {"available": 0},
        "vuln": {"critical": 0, "high": 0},
        "firewall": {"configured": True, "mode": "dry_run", "since": NOW - 2 * DAY},
        "notifications": {"channels": 1},
        "tasks": {"failed_24h": 0},
        "s3": {"buckets": 2, "public_endpoint": True},
        "people": {"users": 3, "cached_packages": 1},
        "dns": {"installed": True, "reachable": True, "setup_complete": True},
    }


def test_every_rule_triggers() -> None:
    items = home.evaluate(broken_facts(), NOW)
    by_id = {item["id"]: item for item in items}
    assert set(by_id) == {
        "component_unavailable:npm_registry", "disk_almost_full", "ecosystem_offline:npm",
        "upstreams_all_failing:pypi", "agent_unreachable", "backup_failed:j1",
        "backup_overdue:j2", "updates_available", "vulnerabilities_found",
        "firewall_dry_run", "no_notification_channel", "jobs_failed",
        "s3_public_endpoint_missing", "domain_problem:d1", "dns_unreachable",
    }
    assert by_id["dns_unreachable"]["severity"] == "error"
    assert by_id["dns_unreachable"]["params"] == {"error_code": "dns_unreachable",
                                                  "since": NOW - 30}
    assert by_id["domain_problem:d1"]["action"]["route"] == "#/services?domain=d1"
    assert by_id["domain_problem:d1"]["params"] == {
        "host": "npm.example.com", "problem_code": "dns_missing", "service_id": "npm"}
    assert {item["rule"] for item in items} | {
        "agent_not_paired", "no_backup_jobs",
        # need a reachable engine; covered in test_dns_d2.py
        "dns_under_pressure", "dns_attack_detected",
        # need a reachable engine; covered in test_dns_d4.py
        "dns_certificate_expiring", "dns_trust_anchor_problem",
    } == set(
        home.ATTENTION_RULES
    )
    disk = by_id["disk_almost_full"]
    assert disk["severity"] == "critical"
    assert disk["params"] == {"percent": 97, "threshold": 85, "source": "host"}
    assert by_id["updates_available"]["params"] == {"count": 3}
    assert by_id["vulnerabilities_found"]["params"] == {"count": 2, "critical": 1, "high": 1}
    assert by_id["firewall_dry_run"]["params"]["days"] == 10
    assert by_id["backup_failed:j1"]["params"]["job_name"] == "DB main"
    assert by_id["upstreams_all_failing:pypi"]["action"] == {"kind": "retry",
                                                             "route": "#/packages/sources"}
    for item in items:
        assert item["title_key"] == item["rule"]
        assert item["action"]["route"].startswith("#/")
    order = [home.SEVERITY_ORDER[item["severity"]] for item in items]
    assert order == sorted(order)
    assert items[0]["severity"] == "critical"


def test_first_run_rules_and_healthy_state() -> None:
    assert home.evaluate(healthy_facts(), NOW) == []
    facts = healthy_facts()
    facts["agent"] = {"configured": False, "reachable": None}
    facts["backups"] = {"jobs": []}
    rules = [item["rule"] for item in home.evaluate(facts, NOW)]
    assert rules == ["no_backup_jobs", "agent_not_paired"]
    # A probe that has not happened yet (reachable None) is not "unreachable".
    facts = healthy_facts()
    facts["agent"] = {"configured": True, "reachable": None}
    assert home.evaluate(facts, NOW) == []


def test_dns_rule_only_when_installed_and_not_answering() -> None:
    facts = healthy_facts()
    facts["dns"] = {"installed": False, "reachable": False, "setup_complete": False}
    assert home.evaluate(facts, NOW) == []
    facts["dns"] = {"installed": True, "reachable": None}
    assert home.evaluate(facts, NOW) == []
    facts["dns"] = {"installed": True, "reachable": False, "error_code": "dns_unreachable"}
    assert [item["rule"] for item in home.evaluate(facts, NOW)] == ["dns_unreachable"]
    assert home.checklist_done(facts)["setup_dns"] is False
    assert home.checklist_done({})["setup_dns"] is None


def test_missing_sources_produce_no_items() -> None:
    facts = {name: None for name in broken_facts()}
    assert home.evaluate(facts, NOW) == []
    assert home.evaluate({}, NOW) == []


def test_backup_overdue_uses_twice_the_schedule() -> None:
    def jobs(last_success: float | None, created: float) -> dict:
        facts = healthy_facts()
        facts["backups"] = {"jobs": [{"id": "j", "name": "J", "enabled": True,
                                      "last_state": "succeeded" if last_success else None,
                                      "last_success_at": last_success,
                                      "interval_seconds": DAY, "created_at": created}]}
        return facts

    assert home.evaluate(jobs(NOW - 1.9 * DAY, 0), NOW) == []
    assert [item["rule"] for item in home.evaluate(jobs(NOW - 2.1 * DAY, 0), NOW)] == [
        "backup_overdue"
    ]
    # A brand-new job is not overdue; one that never succeeded in 2x is.
    assert home.evaluate(jobs(None, NOW - DAY), NOW) == []
    assert home.evaluate(jobs(None, NOW - 3 * DAY), NOW)[0]["rule"] == "backup_overdue"


def test_disk_threshold_and_source() -> None:
    facts = healthy_facts()
    facts["core"]["storage_used_percent"] = 88.0
    facts["monitoring"] = {"disk_threshold": 90, "host_disk_percent": None}
    assert home.evaluate(facts, NOW) == []
    facts["monitoring"]["disk_threshold"] = 80
    [item] = home.evaluate(facts, NOW)
    assert item["params"]["source"] == "storage" and item["severity"] == "warning"
    assert item["_any_of"] == ["system:read"]


def test_filtering_by_permission() -> None:
    facts = broken_facts()
    viewer = home.build_summary(facts, principal("viewer"), {}, NOW)
    seen = {item["rule"] for item in viewer["attention"]}
    # viewer: system, upstream, metrics, updates, vuln, task read only
    assert seen == {"component_unavailable", "disk_almost_full", "ecosystem_offline",
                    "upstreams_all_failing", "updates_available", "vulnerabilities_found",
                    "jobs_failed", "domain_problem", "dns_unreachable"}
    assert all("_any_of" not in item for item in viewer["attention"])
    assert [action["id"] for action in viewer["quick_actions"]] == [
        "connect_project", "search_package", "view_server_usage", "my_services"
    ]
    assert [step["id"] for step in viewer["checklist"]] == ["owner_account", "connect_project"]
    assert viewer["verdict"] == {"level": "problem", "count": len(viewer["attention"])}

    owner = home.build_summary(facts, principal("owner"), {}, NOW)
    assert len(owner["attention"]) == 15
    assert [step["id"] for step in owner["checklist"]] == [
        step["id"] for step in home.CHECKLIST_STEPS
    ]
    assert len(owner["quick_actions"]) == len(home.QUICK_ACTIONS)

    operator = home.build_summary(facts, principal("operator"), {}, NOW)
    operator_rules = {item["rule"] for item in operator["attention"]}
    assert "agent_unreachable" in operator_rules and "backup_failed" in operator_rules
    assert "no_notification_channel" not in operator_rules  # needs notification:write
    assert "s3_public_endpoint_missing" not in operator_rules  # needs s3:admin
    assert "firewall_dry_run" in operator_rules


def test_checklist_detection_and_manual_ticks() -> None:
    facts = healthy_facts()
    facts["agent"] = {"configured": False}
    owner = principal("owner")
    summary = home.build_summary(facts, owner, {"done": {"connect_agent": True}}, NOW)
    steps = {step["id"]: step for step in summary["checklist"]}
    assert all(step["done"] for step in steps.values())
    assert steps["connect_agent"]["detected"] is False
    assert summary["checklist_progress"] == {"done": 6, "total": 6}
    assert summary["verdict"]["level"] == "attention"  # agent_not_paired is info
    empty = home.build_summary({}, owner, {"dismissed": True}, NOW)
    assert empty["checklist_dismissed"] is True
    assert {step["id"]: step["done"] for step in empty["checklist"]}["owner_account"] is True


def test_home_endpoint_on_a_fresh_install(tmp_path: Path) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        assert client.get("/api/v1/home").status_code == 401
        csrf = str(login_owner(client)["csrf_token"])
        response = client.get("/api/v1/home")
        assert response.status_code == 200, response.text
        body = response.json()
        rules = {item["rule"] for item in body["attention"]}
        assert {"no_backup_jobs", "no_notification_channel", "agent_not_paired"} <= rules
        assert home.LAST_SERVICE is not None
        assert set(body["sources"]) == set(home.LAST_SERVICE.collectors)
        assert all(status == "ok" for status in body["sources"].values()), body["sources"]
        steps = {step["id"]: step["done"] for step in body["checklist"]}
        assert steps["owner_account"] is True and steps["invite_teammate"] is False
        assert client.get("/api/v1/home/summary").json()["attention"] == body["attention"]
        ids = client.get("/api/v1/home/rules").json()
        assert set(ids["attention"]) == set(home.ATTENTION_RULES)

        # Per-user checklist state.
        patched = client.patch("/api/v1/home/checklist", headers={"X-CSRF-Token": csrf},
                               json={"dismissed": True, "steps": {"connect_project": True}})
        assert patched.status_code == 200
        after = client.get("/api/v1/home").json()
        assert after["checklist_dismissed"] is True
        assert {s["id"]: s["done"] for s in after["checklist"]}["connect_project"] is True
        bad = client.patch("/api/v1/home/checklist", headers={"X-CSRF-Token": csrf},
                           json={"steps": {"make_coffee": True}})
        assert bad.status_code == 422
        assert bad.json()["error"]["fields"] == [
            {"field": "steps.make_coffee", "reason_code": "unknown_step"}
        ]
        assert client.patch("/api/v1/home/checklist", json={"dismissed": True}).status_code \
            == 403  # CSRF

        # A viewer gets a filtered view and no source diagnostics... unless system:read.
        client.post("/api/v1/users", headers={"X-CSRF-Token": csrf},
                    json={"username": "viewer1", "password": PASSWORD, "role": "viewer"})
        viewer = TestClient(client.app)
        viewer.post("/api/v1/auth/login", json={"username": "viewer1", "password": PASSWORD})
        seen = viewer.get("/api/v1/home").json()
        assert not {"no_backup_jobs", "no_notification_channel", "agent_not_paired"} & {
            item["rule"] for item in seen["attention"]
        }
        assert seen["checklist_dismissed"] is False  # prefs are per person


def test_failing_or_slow_sources_never_fail_the_response(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(home, "SOURCE_TIMEOUT_SECONDS", 0.2)
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        login_owner(client)
        service = home.LAST_SERVICE
        assert service is not None
        calls = {"count": 0}

        async def boom() -> dict:
            raise RuntimeError("module exploded")

        async def slow() -> dict:
            await asyncio.sleep(5)
            return {"available": 9}

        async def counted() -> dict:
            calls["count"] += 1
            return {"failed_24h": 2}

        service.collectors.update({"vuln": boom, "updates": slow, "tasks": counted})
        service.invalidate()
        body = client.get("/api/v1/home").json()
        assert body["sources"]["vuln"] == "error"
        assert body["sources"]["updates"] == "timeout"
        assert body["sources"]["tasks"] == "ok"
        rules = {item["rule"] for item in body["attention"]}
        assert "jobs_failed" in rules and "updates_available" not in rules
        # Cached for 15 s: a second request does not ask the modules again.
        client.get("/api/v1/home")
        assert calls["count"] == 1
        service.invalidate()
        client.get("/api/v1/home")
        assert calls["count"] == 2
