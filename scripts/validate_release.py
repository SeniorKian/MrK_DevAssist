from __future__ import annotations

import json
import re
from pathlib import Path

import yaml


def _require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


_DURATION = re.compile(r"^(?:(\d+)m)?(?:(\d+)s)?$")


def _seconds(value: object) -> int:
    """Parse a Compose duration such as ``180s`` or ``3m``; unknown forms give -1."""
    match = _DURATION.match(str(value).strip())
    if not match or not any(match.groups()):
        return -1
    minutes, seconds = (int(group or 0) for group in match.groups())
    return minutes * 60 + seconds


def _check_workflows(root: Path, dockerfile: str, failures: list[str]) -> None:
    """Every action in every workflow is SHA-pinned (with a version comment), and
    container images run by workflows use the Dockerfile's digest for that tag."""
    base_images = dict(
        image.split("@", 1)
        for image in re.findall(r"^FROM\s+(\S+@sha256:[0-9a-f]{64})", dockerfile, re.MULTILINE)
    )
    workflows = sorted((root / ".github/workflows").glob("*.y*ml"))
    _require(bool(workflows), "no GitHub workflows found", failures)
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        name = workflow.relative_to(root).as_posix()
        for line in re.findall(r"^\s*-?\s*uses:\s*(.+)$", text, re.MULTILINE):
            reference = line.strip()
            if reference.startswith(("./", "docker://")):
                continue
            _require(
                re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}\s+#\s+v\S+", reference) is not None,
                f"{name}: action not pinned by full SHA with a version comment: {reference}",
                failures,
            )
        for image, digest in re.findall(
            r"\b((?:node|python|golang):[\w.-]+)(?:@(sha256:[0-9a-f]{64}))?(?=\s|$)", text
        ):
            _require(
                bool(digest), f"{name}: container image {image} is not digest-pinned", failures
            )
            expected = base_images.get(image)
            if digest and expected:
                _require(
                    digest == expected,
                    f"{name}: {image} digest differs from deploy/appliance/Dockerfile",
                    failures,
                )


# (Compose file, service holding PGlite). The root compose.yaml is the panel-only
# stack (docs/44); the deploy/appliance files are the legacy all-in-one stack.
_DATABASE_SERVICES = (
    ("compose.yaml", "mrk-panel"),
    ("deploy/appliance/compose.yaml", "mrk-mirror"),
    ("deploy/appliance/compose.production.yaml", "mrk-mirror"),
)
_LEGACY_COMPOSE = ("deploy/appliance/compose.yaml", "deploy/appliance/compose.production.yaml")


def _check_runtime_limits(root: Path, failures: list[str]) -> None:
    for relative, name in _DATABASE_SERVICES:
        document = yaml.safe_load((root / relative).read_text(encoding="utf-8"))
        services = document.get("services", {}) if isinstance(document, dict) else {}
        service = services.get(name) if isinstance(services, dict) else None
        if not isinstance(service, dict):
            failures.append(f"{relative}: service {name} is missing")
            continue
        for key in ("mem_limit", "cpus", "pids_limit"):
            _require(key in service, f"{relative}: resource limit {key} is missing", failures)
        _require(
            _seconds(service.get("stop_grace_period", "")) >= 180,
            f"{relative}: stop_grace_period must be >= 180s (PGlite is stopped last)",
            failures,
        )
        healthcheck = service.get("healthcheck", {})
        start_period = healthcheck.get("start_period", "") if isinstance(healthcheck, dict) else ""
        _require(
            _seconds(start_period) >= 300,
            f"{relative}: healthcheck start_period must be >= 300s for first boot",
            failures,
        )


def _check_runtime_pins(root: Path, failures: list[str]) -> None:
    requirements = root / "deploy/appliance/requirements.txt"
    lines = [
        line.strip()
        for line in requirements.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    _require(bool(lines), "deploy/appliance/requirements.txt is empty", failures)
    loose = [line for line in lines if not re.fullmatch(r"[A-Za-z0-9_.-]+==[\w.]+", line)]
    _require(not loose, f"runtime requirements must be exact == pins: {loose}", failures)


def _check_line_endings(root: Path, failures: list[str]) -> None:
    attributes = root / ".gitattributes"
    text = attributes.read_text(encoding="utf-8") if attributes.is_file() else ""
    _require(
        re.search(r"^\*\.sh\s+.*eol=lf", text, re.MULTILINE) is not None,
        ".gitattributes must force LF for *.sh",
        failures,
    )
    for path in sorted(
        [*(root / "deploy/appliance").glob("*"), *(root / "deploy/images").rglob("*")]
    ):
        if path.is_file() and path.suffix in {".sh", ".conf", ".py", ""}:
            _require(
                b"\r\n" not in path.read_bytes(),
                f"{path.relative_to(root).as_posix()} has CRLF line endings",
                failures,
            )


# Host networking is reserved for the two services whose job needs the host
# network namespace: mrk-firewall (nftables rules are per namespace) and mrk-dns
# (docker-proxy is slow for UDP and hides the client address that DNS ACLs, rate
# limiting and RRL depend on). Both bind nothing beyond what their settings name
# and publish no ports; every other service must stay on bridge networks.
_HOST_NETWORK_ALLOWED = {"mrk-firewall", "mrk-dns"}


def _check_dns_service(root: Path, dockerfile: str, failures: list[str]) -> None:
    """The optional DNS engine (docs/37) runs hardened, unprivileged and opt-in."""
    _require(
        "AS dns-builder" in dockerfile, "Dockerfile is missing the dns-builder stage", failures
    )
    _require(
        "COPY --from=dns-builder /out/mrk-dns" in dockerfile,
        "Dockerfile must copy the mrk-dns binary into the runtime image",
        failures,
    )
    # File capabilities are ignored under no-new-privileges; mrk-dns gets its bind
    # capability by starting as root with three capabilities and dropping itself.
    _require(
        "setcap" not in dockerfile,
        "Dockerfile must not set file capabilities (no-new-privileges ignores them)",
        failures,
    )
    _require(
        (root / "apps/dns-engine/go.sum").is_file(), "apps/dns-engine/go.sum is missing", failures
    )
    for relative in ("compose.yaml", *_LEGACY_COMPOSE):
        document = yaml.safe_load((root / relative).read_text(encoding="utf-8"))
        services = document.get("services", {}) if isinstance(document, dict) else {}
        if not isinstance(services, dict):
            continue
        for name, svc in services.items():
            if isinstance(svc, dict) and svc.get("network_mode") == "host":
                _require(
                    name in _HOST_NETWORK_ALLOWED,
                    f"{relative}: service {name} must not use network_mode host",
                    failures,
                )
            if isinstance(svc, dict):
                _require(
                    svc.get("privileged") is not True,
                    f"{relative}: service {name} is privileged",
                    failures,
                )
        if relative not in _LEGACY_COMPOSE:
            continue  # the panel stack has no DNS service; the wizard adds it (docs/44)
        dns = services.get("mrk-dns")
        if not isinstance(dns, dict):
            failures.append(f"{relative}: service mrk-dns is missing")
            continue
        where = f"{relative}: mrk-dns"
        _require(
            dns.get("profiles") == ["dns"], f"{where} must be opt-in (profiles: [dns])", failures
        )
        _require(
            dns.get("entrypoint") == ["mrk-dns"], f"{where} entrypoint must be mrk-dns", failures
        )
        _require(dns.get("command") == ["serve"], f"{where} command must be serve", failures)
        # Starts as root only to drop to MRK_DNS_RUN_AS with NET_BIND_SERVICE alone.
        _require(dns.get("user") == "0:10001", f"{where} must start as 0:10001", failures)
        env = dns.get("environment") or {}
        run_as = str(env.get("MRK_DNS_RUN_AS", "")) if isinstance(env, dict) else ""
        _require(
            run_as.endswith("10001:10001}") or run_as == "10001:10001",
            f"{where} must drop to MRK_DNS_RUN_AS 10001:10001 by default",
            failures,
        )
        _require(dns.get("cap_drop") == ["ALL"], f"{where} must drop all capabilities", failures)
        _require(
            sorted(dns.get("cap_add") or []) == ["NET_BIND_SERVICE", "SETGID", "SETUID"],
            f"{where} may add only NET_BIND_SERVICE, SETUID and SETGID",
            failures,
        )
        _require(
            dns.get("read_only") is True, f"{where} root filesystem must be read-only", failures
        )
        _require(
            "no-new-privileges:true" in (dns.get("security_opt") or []),
            f"{where} must set no-new-privileges",
            failures,
        )
        _require("ports" not in dns, f"{where} must not publish ports", failures)
        _require("build" not in dns, f"{where} must use the appliance image", failures)
        for key in ("mem_limit", "cpus", "pids_limit"):
            _require(key in dns, f"{where} resource limit {key} is missing", failures)
        health = dns.get("healthcheck", {})
        test = health.get("test", []) if isinstance(health, dict) else []
        _require(
            test[:3] == ["CMD", "mrk-dns", "health"],
            f"{where} healthcheck must run mrk-dns health",
            failures,
        )
        mirror = services.get("mrk-mirror", {})
        if isinstance(mirror, dict):
            _require(
                str(dns.get("image")) == str(mirror.get("image")),
                f"{where} must use the same image as mrk-mirror",
                failures,
            )
            _require(
                "mrk-dns-run:/run/mrk-dns:ro" in (mirror.get("volumes") or []),
                f"{relative}: mrk-mirror must mount mrk-dns-run read-only at /run/mrk-dns",
                failures,
            )


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

    split_dockerfile = (root / "deploy/images/Dockerfile").read_text(encoding="utf-8")
    for target in ("panel", "agent", "firewall", "dns", "s3"):
        _require(
            re.search(rf"^FROM\s+\S+\s+AS\s+{target}$", split_dockerfile, re.MULTILINE)
            is not None,
            f"deploy/images/Dockerfile is missing the {target} target",
            failures,
        )
    split_bases = re.findall(r"^FROM\s+(\S+:\S+)\s", split_dockerfile, flags=re.MULTILINE)
    _require(
        all("@sha256:" in image for image in split_bases),
        "every deploy/images/Dockerfile base image must be digest-pinned",
        failures,
    )
    _require(
        "COPY LICENSE /opt/mrk/LICENSE" in split_dockerfile
        and "setcap" not in split_dockerfile,
        "split images must carry the MIT license text and set no file capabilities",
        failures,
    )

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

    for marker in ("sbom: true", "provenance: mode=max"):
        _require(marker in publish, f"release workflow is missing: {marker}", failures)
    # Actions must be pinned by full commit SHA, with the release tag as a comment.
    for action, version in (
        ("actions/attest-build-provenance", "v3"),
        ("aquasecurity/trivy-action", "v0.36.0"),
    ):
        pinned = re.search(rf"{re.escape(action)}@[0-9a-f]{{40}} # {re.escape(version)}", publish)
        _require(
            pinned is not None,
            f"release workflow is missing a SHA-pinned {action} {version}",
            failures,
        )
    _check_workflows(root, dockerfile, failures)
    _check_runtime_limits(root, failures)
    _check_runtime_pins(root, failures)
    _check_line_endings(root, failures)
    _check_dns_service(root, dockerfile, failures)
    print(json.dumps({"status": "passed" if not failures else "failed", "failures": failures}))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
