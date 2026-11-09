"""SBOM export for the vulnerability scanner (docs/28 "SBOM export", Advanced mode).

Builds CycloneDX 1.5 JSON and SPDX 2.3 JSON documents from the per-image package
inventories ``vuln.py`` already caches (``results.sqlite``). The whole-server document
nests one ``container`` component per scanned image; the per-image document describes
that image alone. CycloneDX documents can embed the matched advisories; findings an
active ignore rule covers are marked ``analysis.state = not_affected`` with the
rule's reason as the detail.

Purls follow the package-url spec: ``pkg:deb`` (Debian/Ubuntu), ``pkg:apk``
(Alpine/Wolfi/Chainguard), ``pkg:rpm`` (Rocky/AlmaLinux), ``pkg:npm``, ``pkg:pypi`` and
``pkg:oci`` for the images. The inventory keeps dpkg packages under their *source*
name/version (that is how OSV keys them); when the binary name differs, the
component is the source package (``arch=source``) with the binaries listed in the
``mrk:binaries`` property, so no binary is paired with a version it may not have.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from .. import __version__
from .vuln_inventory import Inventory

FORMATS = ("cyclonedx", "spdx")
TOOL_NAME = "DevAssist"
CDX_MEDIA_TYPE = "application/vnd.cyclonedx+json"
SPDX_MEDIA_TYPE = "application/spdx+json"
SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


# ----- purl -------------------------------------------------------------------------------


def _seg(value: str) -> str:
    return quote(value, safe="")


def purl(
    kind: str,
    name: str,
    version: str | None,
    namespace: str | None = None,
    qualifiers: dict[str, str | None] | None = None,
) -> str:
    text = f"pkg:{kind}/"
    if namespace:
        text += "/".join(_seg(part) for part in namespace.split("/") if part) + "/"
    text += _seg(name)
    if version:
        text += "@" + _seg(version)
    pairs = sorted((k, v) for k, v in (qualifiers or {}).items() if v)
    if pairs:
        text += "?" + "&".join(f"{k}={quote(v, safe='/')}" for k, v in pairs)
    return text


def _os_flavor(ecosystem: str) -> tuple[str, str, str | None] | None:
    """(purl type, namespace, distro qualifier) for an OS ecosystem, None for languages."""
    head, _, rest = ecosystem.partition(":")
    if head == "Debian":
        return "deb", "debian", f"debian-{rest}" if rest else None
    if head == "Ubuntu":
        version = rest.split(":", 1)[0]
        return "deb", "ubuntu", f"ubuntu-{version}" if version else None
    if head == "Alpine":
        return "apk", "alpine", f"alpine-{rest.removeprefix('v')}" if rest else None
    if head in {"Wolfi", "Chainguard"}:
        return "apk", head.lower(), None
    if head == "Rocky Linux":
        return "rpm", "rocky", f"rocky-{rest}" if rest else None
    if head == "AlmaLinux":
        return "rpm", "almalinux", f"almalinux-{rest}" if rest else None
    return None


def _npm_purl(name: str, version: str) -> str:
    if name.startswith("@") and "/" in name:
        scope, _, bare = name.partition("/")
        return purl("npm", bare, version, namespace=scope)
    return purl("npm", name, version)


def _rpm_version(version: str) -> tuple[str, str | None]:
    epoch, sep, rest = version.partition(":")
    if sep and epoch.isdigit():
        return rest, epoch
    return version, None


# ----- components ---------------------------------------------------------------------------


def package_components(
    inventory: Inventory, ref_prefix: str
) -> tuple[list[dict[str, Any]], dict[tuple[str, str, str], list[str]]]:
    """CycloneDX components for one inventory plus a finding-key -> bom-refs index.

    The index key is ``(ecosystem, name, version)`` as stored on findings (OSV name).
    """
    components: list[dict[str, Any]] = []
    index: dict[tuple[str, str, str], list[str]] = {}
    seen: set[str] = set()

    def add(component: dict[str, Any], keys: list[tuple[str, str, str]]) -> None:
        ref = f"{ref_prefix}{component['purl']}"
        for key in keys:
            refs = index.setdefault(key, [])
            if ref not in refs:
                refs.append(ref)
        if ref in seen:
            return
        seen.add(ref)
        component["bom-ref"] = ref
        components.append(component)

    def base(kind: str, name: str, version: str, package_url: str) -> dict[str, Any]:
        return {"type": kind, "name": name, "version": version, "purl": package_url}

    # dpkg: a row without ``binary`` is an installed package whose name and version are
    # its own; rows with ``binary`` are grouped under one source component.
    deb_groups: dict[tuple[str, str, str], list[str]] = {}
    deb_self: set[tuple[str, str, str]] = set()
    rpm_sources: dict[tuple[str, str, str], str] = {}
    for package in inventory.packages:
        flavor = _os_flavor(package.ecosystem)
        if flavor and flavor[0] == "deb":
            key = (package.ecosystem, package.name, package.version)
            if not package.binary:
                deb_self.add(key)
                continue
            binaries = deb_groups.setdefault(key, [])
            if package.binary not in binaries:
                binaries.append(package.binary)
        elif flavor and flavor[0] == "rpm" and package.binary:
            rpm_sources[(package.ecosystem, package.binary, package.version)] = package.name

    for key in sorted(deb_self):
        ecosystem, name, version = key
        flavor = _os_flavor(ecosystem)
        assert flavor is not None
        add(base("library", name, version,
                 purl("deb", name, version, flavor[1], {"distro": flavor[2]})), [key])
    for key, binaries in sorted(deb_groups.items()):
        ecosystem, name, version = key
        flavor = _os_flavor(ecosystem)
        assert flavor is not None
        _kind, namespace, distro = flavor
        component = base("library", name, version, purl(
            "deb", name, version, namespace, {"arch": "source", "distro": distro}))
        component["properties"] = [
            {"name": "mrk:package_kind", "value": "source"},
            {"name": "mrk:binaries", "value": ",".join(sorted(binaries))},
        ]
        add(component, [key])

    for package in inventory.packages:
        key = (package.ecosystem, package.name, package.version)
        flavor = _os_flavor(package.ecosystem)
        if flavor is not None:
            kind, namespace, distro = flavor
            if kind == "deb":
                continue
            if kind == "apk":
                name = package.binary or package.name
                upstream = package.name if package.binary else None
                add(base("library", name, package.version, purl(
                    "apk", name, package.version, namespace,
                    {"distro": distro, "upstream": upstream})), [key])
                continue
            # rpm: source rows (binary set) only feed the index of their binary package.
            version, epoch = _rpm_version(package.version)
            name = package.binary or package.name
            upstream = rpm_sources.get((package.ecosystem, name, package.version))
            add(base("library", name, package.version, purl(
                "rpm", name, version, namespace,
                {"distro": distro, "epoch": epoch, "upstream": upstream})), [key])
            continue
        if package.ecosystem == "npm":
            package_url = _npm_purl(package.name, package.version)
        elif package.ecosystem == "PyPI":
            package_url = purl("pypi", package.name, package.version)
        else:
            package_url = purl("generic", package.name, package.version)
        component = base("library", package.name, package.version, package_url)
        if package.location:
            component["properties"] = [{"name": "mrk:location", "value": package.location}]
        add(component, [key])
    return components, index


def _image_reference(image: str) -> tuple[str, str | None, str | None]:
    """(repository, tag, name) for an image reference like ``ghcr.io/a/b:1``."""
    text = image.split("@", 1)[0].strip()
    if not text or text.startswith("sha256:"):
        return "", None, None
    repo, tag = text, None
    head, sep, tail = text.rpartition(":")
    if sep and "/" not in tail:
        repo, tag = head, tail
    first = repo.split("/", 1)[0]
    if "/" not in repo or not ("." in first or ":" in first or first == "localhost"):
        repo = "docker.io/" + (repo if "/" in repo else f"library/{repo}")
    return repo, tag, repo.rsplit("/", 1)[-1]


def image_component(payload: dict[str, Any], ref: str) -> dict[str, Any]:
    image = str(payload.get("image") or "")
    image_id = str(payload["image_id"])
    repo, tag, name = _image_reference(image)
    digest = payload.get("digest") or image_id
    component: dict[str, Any] = {
        "type": "container",
        "bom-ref": ref,
        "name": image or image_id,
        "version": tag or digest,
        "purl": purl("oci", name or image_id.removeprefix("sha256:")[:12], digest, None,
                     {"repository_url": repo or None, "tag": tag}),
        "hashes": [{"alg": "SHA-256", "content": image_id.removeprefix("sha256:")}]
        if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) else [],
        "properties": [
            {"name": "mrk:image_id", "value": image_id},
            *(
                {"name": "mrk:container", "value": str(c.get("name") or c.get("id"))}
                for c in payload.get("containers") or []
            ),
        ],
    }
    if not component["hashes"]:
        del component["hashes"]
    return component


def os_component(os_info: dict[str, Any] | None, ref: str) -> dict[str, Any] | None:
    if not os_info or not os_info.get("id"):
        return None
    component: dict[str, Any] = {
        "type": "operating-system",
        "bom-ref": ref,
        "name": str(os_info["id"]),
    }
    if os_info.get("version_id"):
        component["version"] = str(os_info["version_id"])
    if os_info.get("name"):
        component["description"] = str(os_info["name"])
    return component


# ----- documents ----------------------------------------------------------------------------


def _timestamp(now: float) -> str:
    return datetime.fromtimestamp(now, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _image_prefix(image_id: str) -> str:
    return image_id.removeprefix("sha256:")[:12]


def _vulnerability(
    finding: dict[str, Any], refs: list[str], number: int
) -> dict[str, Any]:
    advisory = str(finding["id"])
    entry: dict[str, Any] = {
        "bom-ref": f"vuln-{number}-{advisory}",
        "id": advisory,
        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{quote(advisory)}"},
        "references": [
            {"id": alias, "source": {"name": "OSV",
                                     "url": f"https://osv.dev/vulnerability/{quote(alias)}"}}
            for alias in finding.get("aliases") or []
        ],
        "ratings": [
            {
                "source": {"name": "OSV"},
                "severity": SEVERITY_MAP.get(finding.get("severity") or "", "unknown"),
                **({"score": finding["score"], "method": "CVSSv31"}
                   if isinstance(finding.get("score"), int | float) else {}),
            }
        ],
        "affects": [
            {"ref": ref, "versions": [{"version": finding["installed"], "status": "affected"}]}
            for ref in refs
        ],
    }
    if finding.get("summary"):
        entry["description"] = str(finding["summary"])
    if finding.get("fixed"):
        entry["recommendation"] = f"Upgrade {finding['package']} to {finding['fixed']}"
    if not entry["references"]:
        del entry["references"]
    if finding.get("ignored"):
        entry["analysis"] = {
            "state": "not_affected",
            "detail": str(finding.get("ignore_reason") or "Ignored by an DevAssist rule"),
        }
    return entry


def cyclonedx(
    targets: list[tuple[dict[str, Any], Inventory | None, list[dict[str, Any]]]],
    *,
    now: float,
    whole_host: bool,
    include_vulns: bool,
    host_name: str = "DevAssist server",
) -> dict[str, Any]:
    """CycloneDX 1.5 document. ``targets``: (image payload, inventory, annotated findings)."""
    components: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    metadata_component: dict[str, Any]
    for payload, inventory, findings in targets:
        prefix = _image_prefix(payload["image_id"])
        image_ref = f"image:{prefix}"
        image = image_component(payload, image_ref)
        packages, index = (
            package_components(inventory, f"{prefix}:") if inventory else ([], {})
        )
        os_part = os_component(inventory.os if inventory else None, f"{prefix}:os")
        children = ([os_part] if os_part else []) + packages
        if whole_host:
            image["components"] = children
            components.append(image)
        else:
            metadata_component = image
            components.extend(children)
        dependencies.append({"ref": image_ref, "dependsOn": [c["bom-ref"] for c in children]})
        if include_vulns:
            for finding in findings:
                refs = index.get((finding.get("ecosystem") or "", finding["package"],
                                  finding["installed"]), [])
                vulnerabilities.append(_vulnerability(finding, refs, len(vulnerabilities) + 1))
    if whole_host or not targets:
        metadata_component = {
            "type": "device",
            "bom-ref": "host",
            "name": host_name,
            "description": "All scanned container images on this server",
        }
        dependencies.insert(
            0, {"ref": "host", "dependsOn": [c["bom-ref"] for c in components]}
        )
    document: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(now),
            "tools": {
                "components": [
                    {"type": "application", "name": TOOL_NAME, "version": __version__,
                     "publisher": "DevAssist DevAssist"}
                ]
            },
            "component": metadata_component,
        },
        "components": components,
        "dependencies": dependencies,
    }
    if include_vulns:
        document["vulnerabilities"] = vulnerabilities
    return document


def _spdx_id(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]+", "-", text).strip("-")[:120] or "x"


def spdx(
    targets: list[tuple[dict[str, Any], Inventory | None, list[dict[str, Any]]]],
    *,
    now: float,
    whole_host: bool,
    host_name: str = "DevAssist server",
) -> dict[str, Any]:
    """SPDX 2.3 JSON document (packages + CONTAINS relationships; no vulnerabilities)."""
    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    used: set[str] = set()

    def spdx_package(component: dict[str, Any], hint: str) -> str:
        base = f"SPDXRef-{_spdx_id(hint)}"
        identifier, counter = base, 1
        while identifier in used:
            counter += 1
            identifier = f"{base}-{counter}"
        used.add(identifier)
        package: dict[str, Any] = {
            "SPDXID": identifier,
            "name": component["name"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if component.get("version"):
            package["versionInfo"] = component["version"]
        if component.get("purl"):
            package["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": component["purl"],
            }]
        if component.get("type") == "container":
            package["primaryPackagePurpose"] = "CONTAINER"
        elif component.get("type") == "operating-system":
            package["primaryPackagePurpose"] = "OPERATING-SYSTEM"
        else:
            package["primaryPackagePurpose"] = "LIBRARY"
        packages.append(package)
        return identifier

    roots: list[str] = []
    for payload, inventory, _findings in targets:
        prefix = _image_prefix(payload["image_id"])
        image_id = spdx_package(image_component(payload, ""), f"Image-{prefix}")
        roots.append(image_id)
        os_part = os_component(inventory.os if inventory else None, "")
        children = ([os_part] if os_part else []) + (
            package_components(inventory, "")[0] if inventory else []
        )
        for child in children:
            child_id = spdx_package(child, f"{prefix}-{child['name']}-{child.get('version', '')}")
            relationships.append({"spdxElementId": image_id, "relationshipType": "CONTAINS",
                                  "relatedSpdxElement": child_id})
    if whole_host or not targets:
        host_id = spdx_package({"name": host_name, "type": "device"}, "Host")
        packages[-1]["primaryPackagePurpose"] = "DEVICE"
        for root in roots:
            relationships.append({"spdxElementId": host_id, "relationshipType": "CONTAINS",
                                  "relatedSpdxElement": root})
        roots = [host_id]
    for root in roots:
        relationships.insert(0, {"spdxElementId": "SPDXRef-DOCUMENT",
                                 "relationshipType": "DESCRIBES", "relatedSpdxElement": root})
    name = host_name if whole_host or not targets else str(
        targets[0][0].get("image") or targets[0][0]["image_id"]
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"SBOM {name}",
        "documentNamespace": f"https://spdx.mrk.invalid/sbom/{uuid.uuid4()}",
        "creationInfo": {
            "created": _timestamp(now),
            "creators": [f"Tool: {TOOL_NAME}-{__version__}", "Organization: DevAssist DevAssist"],
        },
        "documentDescribes": roots,
        "packages": packages,
        "relationships": relationships,
    }


def filename(target: str, fmt: str, now: float) -> str:
    stamp = datetime.fromtimestamp(now, UTC).strftime("%Y%m%d")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", target).strip("-.")[:60] or "image"
    suffix = "cdx.json" if fmt == "cyclonedx" else "spdx.json"
    return f"mrk-sbom-{slug}-{stamp}.{suffix}"


__all__ = [
    "CDX_MEDIA_TYPE",
    "FORMATS",
    "SPDX_MEDIA_TYPE",
    "cyclonedx",
    "filename",
    "package_components",
    "purl",
    "spdx",
]
