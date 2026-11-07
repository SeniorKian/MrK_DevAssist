from __future__ import annotations

import json
import re
from pathlib import Path

import yaml


def _require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "deploy/appliance/Dockerfile").read_text(encoding="utf-8")
    compose: dict[str, object] = yaml.safe_load(
        (root / "deploy/appliance/compose.production.yaml").read_text(encoding="utf-8")
    )
    versions = (root / "versions.lock.yaml").read_text(encoding="utf-8")
    license_text = (root / "LICENSE").read_text(encoding="utf-8")
    publish = (root / ".github/workflows/publish-image.yml").read_text(encoding="utf-8")
    first_time_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            root / "apps/control-plane/src/mrk_control_plane/config.py",
            root / "apps/control-plane/src/mrk_control_plane/main.py",
            root / ".env.example",
            root / "deploy/appliance/compose.production.yaml",
        )
    )
    failures: list[str] = []

    from_lines = re.findall(r"^FROM\s+(\S+)", dockerfile, flags=re.MULTILINE)
    _require(bool(from_lines), "Dockerfile has no FROM lines", failures)
    _require(
        all("@sha256:" in image for image in from_lines),
        "every Dockerfile base image must be digest-pinned",
        failures,
    )
    _require(
        "TO_BE_RESOLVED" not in versions,
        "versions.lock.yaml contains an unresolved release value",
        failures,
    )
    _require(
        license_text.startswith("MIT License\n")
        and "Copyright (c) 2026 Mohammad Kiani" in license_text,
        "the owner-approved MIT LICENSE is missing or changed",
        failures,
    )
    _require(
        'org.opencontainers.image.licenses="MIT"' in dockerfile
        and "COPY LICENSE /opt/mrk/LICENSE" in dockerfile,
        "the image must retain MIT license metadata and text",
        failures,
    )
    _require(
        "MRK_INITIAL_ADMIN" not in first_time_sources
        and "initial-admin-password" not in first_time_sources,
        "legacy file-based initial administrator bootstrap is forbidden",
        failures,
    )

    services = compose.get("services", {})
    service = services.get("mrk-mirror", {}) if isinstance(services, dict) else {}
    _require(isinstance(service, dict), "production service is missing", failures)
    if isinstance(service, dict):
        _require("build" not in service, "production Compose must pull, not build", failures)
        _require("ports" not in service, "production Compose must not publish host ports", failures)
        _require(service.get("read_only") is True, "root filesystem must be read-only", failures)
        _require(service.get("user") == "10001:10001", "runtime user must be 10001", failures)
        _require(
            service.get("cap_drop") == ["ALL"],
            "all Linux capabilities must be dropped",
            failures,
        )
        _require(
            str(service.get("image", "")).startswith("${MRK_IMAGE:?"),
            "MRK_IMAGE must be mandatory and supplied as a digest",
            failures,
        )
        environment = service.get("environment", {})
        if isinstance(environment, dict):
            _require(
                not any(key.startswith("MRK_INITIAL_ADMIN") for key in environment),
                "production Compose must not contain initial-admin credentials",
                failures,
            )
        security_options = service.get("security_opt", [])
        _require(
            "no-new-privileges:true" in security_options,
            "no-new-privileges must be enabled",
            failures,
        )

    for marker in (
        "sbom: true",
        "provenance: mode=max",
        "actions/attest-build-provenance@v3",
        "aquasecurity/trivy-action@v0.36.0",
    ):
        _require(marker in publish, f"release workflow is missing: {marker}", failures)
    print(json.dumps({"status": "passed" if not failures else "failed", "failures": failures}))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
