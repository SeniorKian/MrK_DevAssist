"""SBOM export (docs/28 Advanced mode): CycloneDX 1.5 / SPDX 2.3, purls, ignores, RBAC."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import vuln, vuln_sbom
from mrk_control_plane.modules.vuln_inventory import Inventory, Package

from .helpers import login_owner
from .test_vuln import (  # noqa: F401 - feed_server is a fixture
    IMG_DEB,
    IMG_NODE,
    FakeAgent,
    allowed,
    feed_server,
    make_service,
    role_client,
    run,
)


def by_purl(components):
    return {c["purl"]: c for c in components}


def test_purls_for_every_ecosystem() -> None:
    inventory = Inventory(
        os={"id": "debian", "version_id": "12", "name": "Debian 12", "ecosystem": "Debian:12"},
        packages=[
            Package("Debian:12", "openssl", "3.0.11-1~deb12u2", "libssl3"),
            Package("Debian:12", "openssl", "3.0.11-1~deb12u2"),
            Package("Debian:12", "openssl", "3.0.11-1~deb12u2", "openssl-provider-legacy"),
            Package("Ubuntu:22.04:LTS", "bash", "5.1-6ubuntu1"),
            Package("Alpine:v3.19", "busybox", "1.36.1-r15", "ssl_client"),
            Package("Alpine:v3.19", "musl", "1.2.4_git20230717-r4"),
            Package("Rocky Linux:9", "openssl-libs", "1:3.0.7-24.el9"),
            Package("Rocky Linux:9", "openssl", "1:3.0.7-24.el9", "openssl-libs"),
            Package("npm", "@babel/core", "7.24.0", location="/app/package-lock.json"),
            Package("npm", "lodash", "4.17.20"),
            Package("PyPI", "requests", "2.31.0"),
        ],
    )
    components, index = vuln_sbom.package_components(inventory, "x:")
    purls = by_purl(components)
    assert set(purls) == {
        "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=source&distro=debian-12",
        "pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12",
        "pkg:deb/ubuntu/bash@5.1-6ubuntu1?distro=ubuntu-22.04",
        "pkg:apk/alpine/ssl_client@1.36.1-r15?distro=alpine-3.19&upstream=busybox",
        "pkg:apk/alpine/musl@1.2.4_git20230717-r4?distro=alpine-3.19",
        "pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?distro=rocky-9&epoch=1&upstream=openssl",
        "pkg:npm/%40babel/core@7.24.0",
        "pkg:npm/lodash@4.17.20",
        "pkg:pypi/requests@2.31.0",
    }
    source = purls["pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=source&distro=debian-12"]
    assert {"name": "mrk:binaries", "value": "libssl3,openssl-provider-legacy"} in (
        source["properties"]
    )
    assert all(c["bom-ref"] == "x:" + c["purl"] for c in components)
    # Findings keyed by OSV (source) name resolve to the right components.
    assert index[("Rocky Linux:9", "openssl", "1:3.0.7-24.el9")] == [
        "x:pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?distro=rocky-9&epoch=1&upstream=openssl"
    ]
    assert index[("Alpine:v3.19", "busybox", "1.36.1-r15")] == [
        "x:pkg:apk/alpine/ssl_client@1.36.1-r15?distro=alpine-3.19&upstream=busybox"
    ]
    assert vuln_sbom.purl("oci", "nginx", "sha256:ab", None,
                          {"repository_url": "docker.io/library/nginx", "tag": "1.25"}) == (
        "pkg:oci/nginx@sha256%3Aab?repository_url=docker.io/library/nginx&tag=1.25"
    )
    assert vuln_sbom._image_reference("ghcr.io/a/b:1@sha256:00") == ("ghcr.io/a/b", "1", "b")
    assert vuln_sbom._image_reference("localhost:5000/app") == ("localhost:5000/app", None, "app")
    assert vuln_sbom._image_reference("nginx:1.25")[0] == "docker.io/library/nginx"


@pytest.mark.usefixtures("feed_server")
def test_service_documents_and_ignored_mapping(tmp_path: Path) -> None:
    service, _events, _clock = make_service(tmp_path, FakeAgent())
    assert service.sbom_document(None, "cyclonedx", True) is None  # nothing scanned yet
    run(service.run_scan("manual"))
    rule = service.add_ignore({"advisory": "CVE-2023-0002", "reason": "zlib unused here"}, None)

    host, name = service.sbom_document(None, "cyclonedx", True)
    assert name.startswith("mrk-sbom-server-") and name.endswith(".cdx.json")
    assert host["bomFormat"] == "CycloneDX" and host["specVersion"] == "1.5"
    assert host["serialNumber"].startswith("urn:uuid:") and host["version"] == 1
    assert host["metadata"]["tools"]["components"][0]["name"] == "DevAssist"
    assert host["metadata"]["timestamp"].endswith("Z")
    assert host["metadata"]["component"]["type"] == "device"
    images = {c["name"]: c for c in host["components"]}
    assert set(images) == {"app:1", "node-app:2"} and all(
        c["type"] == "container" for c in images.values()
    )
    app = images["app:1"]
    assert app["purl"] == ("pkg:oci/app@sha256%3A" + "d" * 64
                           + "?repository_url=docker.io/library/app&tag=1")
    nested = by_purl(c for c in app["components"] if "purl" in c)
    assert "pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12" in nested
    assert "pkg:deb/debian/zlib@1%3A1.2.13.dfsg-1?arch=source&distro=debian-12" in nested
    assert any(c["type"] == "operating-system" and c["name"] == "debian"
               for c in app["components"])
    refs = [c["bom-ref"] for c in host["components"]] + [
        c["bom-ref"] for image in host["components"] for c in image["components"]
    ]
    assert len(refs) == len(set(refs))  # bom-refs are unique across the document
    vulns = {v["id"]: v for v in host["vulnerabilities"]}
    assert set(vulns) == {"DEBIAN-CVE-2023-0001", "DEBIAN-CVE-2023-0002", "GHSA-aaaa-bbbb-cccc"}
    critical = vulns["DEBIAN-CVE-2023-0001"]
    assert critical["ratings"][0]["severity"] == "critical"
    assert critical["recommendation"] == "Upgrade openssl to 3.0.13-1~deb12u1"
    assert len(critical["affects"]) == 2  # binary openssl + source openssl (libssl3)
    assert all(a["ref"] in refs for a in critical["affects"]) and "analysis" not in critical
    assert critical["references"][0]["id"] == "CVE-2023-0001"
    ignored = vulns["DEBIAN-CVE-2023-0002"]
    assert ignored["analysis"] == {"state": "not_affected", "detail": rule["reason"]}
    assert ignored["affects"][0]["ref"].endswith("zlib@1%3A1.2.13.dfsg-1?arch=source"
                                                 "&distro=debian-12")
    assert vulns["GHSA-aaaa-bbbb-cccc"]["affects"][0]["ref"].endswith("pkg:npm/lodash@4.17.20")

    # Per-target: only that image, image as metadata.component, flat components.
    node, node_name = service.sbom_document(IMG_NODE.removeprefix("sha256:"), "cyclonedx", True)
    assert node_name.startswith("mrk-sbom-node-app-2-")
    assert node["metadata"]["component"]["name"] == "node-app:2"
    assert [c["purl"] for c in node["components"]] == ["pkg:npm/lodash@4.17.20"]
    assert [v["id"] for v in node["vulnerabilities"]] == ["GHSA-aaaa-bbbb-cccc"]
    plain, _ = service.sbom_document(IMG_NODE, "cyclonedx", False)
    assert "vulnerabilities" not in plain
    assert service.sbom_document("sha256:" + "f" * 64, "cyclonedx", True) is None

    spdx, spdx_name = service.sbom_document(IMG_DEB, "spdx", True)
    assert spdx_name.endswith(".spdx.json")
    assert spdx["spdxVersion"] == "SPDX-2.3" and spdx["dataLicense"] == "CC0-1.0"
    assert spdx["creationInfo"]["creators"][0].startswith("Tool: DevAssist")
    ids = [p["SPDXID"] for p in spdx["packages"]]
    assert len(ids) == len(set(ids)) and all(i.startswith("SPDXRef-") for i in ids)
    locators = {r["referenceLocator"] for p in spdx["packages"] for r in p.get("externalRefs", [])}
    assert "pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12" in locators
    assert not any("lodash" in locator for locator in locators)
    assert spdx["relationships"][0]["relationshipType"] == "DESCRIBES"
    host_spdx, _ = service.sbom_document(None, "spdx", True)
    assert any("lodash" in r["referenceLocator"]
               for p in host_spdx["packages"] for r in p.get("externalRefs", []))


@pytest.mark.usefixtures("feed_server")
def test_sbom_api_rbac_headers_and_audit(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("MRK_AGENT_URL", raising=False)
    monkeypatch.delenv("MRK_AGENT_KEY_FILE", raising=False)
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as owner:
        headers = {"X-CSRF-Token": str(login_owner(owner)["csrf_token"])}
        service = vuln.ACTIVE_SERVICE
        assert service is not None
        service.agent = FakeAgent()
        assert owner.get("/api/v1/vuln/sbom").json()["error"]["code"] == "no_scan_results"
        assert owner.post("/api/v1/vuln/scan", headers=headers).status_code == 202
        deadline = time.time() + 15
        view = owner.get("/api/v1/vuln/images").json()
        while (view["running"] or not view["items"]) and time.time() < deadline:
            time.sleep(0.05)
            view = owner.get("/api/v1/vuln/images").json()
        assert view["items"]

        response = owner.get("/api/v1/vuln/sbom")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/vnd.cyclonedx+json")
        assert response.headers["content-disposition"].startswith(
            'attachment; filename="mrk-sbom-server-')
        assert response.json()["bomFormat"] == "CycloneDX"
        spdx = owner.get(f"/api/v1/vuln/images/{IMG_DEB}/sbom?format=spdx")
        assert spdx.status_code == 200 and spdx.json()["spdxVersion"] == "SPDX-2.3"
        assert spdx.headers["content-type"].startswith("application/spdx+json")
        assert owner.get("/api/v1/vuln/sbom?format=xml").status_code == 422
        missing = owner.get("/api/v1/vuln/images/sha256:" + "f" * 64 + "/sbom")
        assert missing.status_code == 404
        assert TestClient(app).get("/api/v1/vuln/sbom").status_code == 401

        for role in ("admin", "operator", "developer", "viewer"):
            client, _role_headers = role_client(owner, headers, role)
            expected = 200 if allowed(role, "vuln:read") else 403
            assert client.get("/api/v1/vuln/sbom").status_code == expected, role
            assert client.get(f"/api/v1/vuln/images/{IMG_NODE}/sbom").status_code == expected

        audit = owner.get("/api/v1/audit-events?action=vuln.sbom.export&limit=500")
        assert audit.status_code == 200
        results = {(item.get("object_id"), item.get("result")) for item in audit.json()["items"]}
        assert ("server:cyclonedx", "success") in results
        assert (f"{IMG_DEB}:spdx", "success") in results
        assert ("server", "failure") in results
