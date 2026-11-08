"""Package inventory parsers for the vulnerability scanner (Gate 19 S8).

Input is the agent's ``package-files`` payload (fixed paths, raw bytes); output is
an ``Inventory``: the OS (``/etc/os-release``) mapped to an OSV ecosystem plus a
deduplicated package list. Only names and versions are kept; raw file content is
never stored (``requirements.txt`` index URLs can carry credentials).

OS packages are matched by *source* package (Debian ``Source:``, Alpine origin
``o:``) because OSV's Debian/Ubuntu/Alpine records are keyed that way.
"""

from __future__ import annotations

import base64
import json
import re
import sqlite3
import struct
import tempfile
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_PACKAGES = 20000


@dataclass(frozen=True, slots=True)
class Package:
    ecosystem: str  # OSV ecosystem, e.g. "Debian:12", "npm"
    name: str  # name matched against OSV (source package for OS packages)
    version: str  # version matched against OSV (source version for dpkg)
    binary: str | None = None  # installed binary package name when different
    location: str | None = None  # lockfile the package came from

    def public(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "binary": self.binary,
            "location": self.location,
        }


@dataclass(slots=True)
class Inventory:
    os: dict[str, Any] | None = None  # {id, version_id, name, ecosystem}
    packages: list[Package] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def ecosystems(self) -> set[str]:
        return {package.ecosystem for package in self.packages}

    def public(self) -> dict[str, Any]:
        return {
            "os": self.os,
            "packages": [package.public() for package in self.packages],
            "notes": self.notes,
        }

    @classmethod
    def from_public(cls, payload: dict[str, Any]) -> Inventory:
        packages = [
            Package(
                str(item["ecosystem"]),
                str(item["name"]),
                str(item["version"]),
                item.get("binary"),
                item.get("location"),
            )
            for item in payload.get("packages") or []
            if isinstance(item, dict) and {"ecosystem", "name", "version"} <= set(item)
        ]
        os_info = payload.get("os") if isinstance(payload.get("os"), dict) else None
        notes = [str(note) for note in payload.get("notes") or []]
        return cls(os_info, packages, notes)


# ----- os-release ----------------------------------------------------------------------


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def os_ecosystem(release: dict[str, str]) -> str | None:
    """OSV ecosystem for an os-release mapping, or None if unsupported."""
    distro = release.get("ID", "").lower()
    version = release.get("VERSION_ID", "")
    if distro == "debian":
        major = version.split(".", 1)[0]
        return f"Debian:{major}" if major.isdigit() else None
    if distro == "ubuntu":
        match = re.fullmatch(r"([0-9]{2})\.([0-9]{2})", version)
        if not match:
            return None
        lts = int(match.group(1)) % 2 == 0 and match.group(2) == "04"
        return f"Ubuntu:{version}:LTS" if lts else f"Ubuntu:{version}"
    if distro == "alpine":
        match = re.match(r"([0-9]+)\.([0-9]+)", version)
        return f"Alpine:v{match.group(1)}.{match.group(2)}" if match else None
    if distro in {"rocky", "almalinux"}:
        major = version.split(".", 1)[0]
        if not major.isdigit():
            return None
        return f"{'Rocky Linux' if distro == 'rocky' else 'AlmaLinux'}:{major}"
    if distro == "wolfi":
        return "Wolfi"
    if distro == "chainguard":
        return "Chainguard"
    return None


# ----- dpkg -----------------------------------------------------------------------------


def _paragraphs(text: str) -> Iterator[dict[str, str]]:
    fields: dict[str, str] = {}
    key: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if fields:
                yield fields
            fields, key = {}, None
            continue
        if line[0] in " \t":
            if key is not None and key in {"Package", "Version", "Source", "Status"}:
                fields[key] += " " + line.strip()
            continue
        name, sep, value = line.partition(":")
        if not sep:
            continue
        key = name.strip()
        fields[key] = value.strip()
    if fields:
        yield fields


def parse_dpkg_status(text: str, ecosystem: str) -> list[Package]:
    packages: list[Package] = []
    for fields in _paragraphs(text):
        name = fields.get("Package")
        version = fields.get("Version")
        if not name or not version:
            continue
        status = fields.get("Status")
        if status is not None and status.split()[-1:] != ["installed"]:
            continue
        source, source_version = name, version
        raw_source = fields.get("Source")
        if raw_source:
            match = re.fullmatch(r"(\S+)(?:\s+\((\S+)\))?", raw_source.strip())
            if match:
                source = match.group(1)
                source_version = match.group(2) or version
        packages.append(
            Package(ecosystem, source, source_version, None if source == name else name)
        )
    return packages


# ----- apk -------------------------------------------------------------------------------


def parse_apk_installed(text: str, ecosystem: str) -> list[Package]:
    packages: list[Package] = []
    record: dict[str, str] = {}

    def flush() -> None:
        name, version = record.get("P"), record.get("V")
        if name and version:
            origin = record.get("o") or name
            packages.append(Package(ecosystem, origin, version, None if origin == name else name))

    for line in text.splitlines():
        if not line.strip():
            flush()
            record = {}
            continue
        if len(line) >= 2 and line[1] == ":" and line[0] in "PVo":
            record[line[0]] = line[2:].strip()
    flush()
    return packages


# ----- rpm (sqlite rpmdb) --------------------------------------------------------------

_RPM_TAGS = {1000: "name", 1001: "version", 1002: "release", 1003: "epoch", 1044: "sourcerpm"}


def parse_rpm_header(blob: bytes) -> dict[str, Any]:
    """Decode the tags we need from an RPM header blob (rpmdb ``Packages.blob``)."""
    if len(blob) < 8:
        raise ValueError("short header")
    count, data_len = struct.unpack(">II", blob[:8])
    if count > 100000 or 8 + count * 16 + data_len > len(blob):
        raise ValueError("bad header sizes")
    data_start = 8 + count * 16
    store = blob[data_start : data_start + data_len]
    result: dict[str, Any] = {}
    for index in range(count):
        tag, kind, offset, items = struct.unpack(">iIiI", blob[8 + index * 16 : 24 + index * 16])
        name = _RPM_TAGS.get(tag)
        if name is None or offset < 0 or offset >= len(store):
            continue
        if kind == 6 or kind == 8 or kind == 9:  # STRING, STRING_ARRAY, I18NSTRING
            end = store.find(b"\0", offset)
            if end < 0:
                continue
            result[name] = store[offset:end].decode("utf-8", errors="replace")
        elif kind == 4 and items >= 1 and offset + 4 <= len(store):  # INT32
            result[name] = struct.unpack(">I", store[offset : offset + 4])[0]
    return result


def _srpm_name(sourcerpm: str) -> str | None:
    match = re.fullmatch(r"(.+)-[^-]+-[^-]+\.(?:no)?src\.rpm", sourcerpm)
    return match.group(1) if match else None


def parse_rpmdb_sqlite(data: bytes, ecosystem: str) -> list[Package]:
    with tempfile.TemporaryDirectory(prefix="mrk-rpmdb-") as directory:
        path = Path(directory) / "rpmdb.sqlite"
        path.write_bytes(data)
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            rows = connection.execute("SELECT blob FROM Packages").fetchall()
        finally:
            connection.close()
    packages: list[Package] = []
    for (blob,) in rows:
        try:
            header = parse_rpm_header(bytes(blob))
        except (ValueError, struct.error):
            continue
        name, version = header.get("name"), header.get("version")
        if not name or not version or name == "gpg-pubkey":
            continue
        full = f"{version}-{header['release']}" if header.get("release") else version
        if header.get("epoch"):
            full = f"{header['epoch']}:{full}"
        packages.append(Package(ecosystem, name, full))
        source = _srpm_name(str(header.get("sourcerpm") or ""))
        if source and source != name:
            packages.append(Package(ecosystem, source, full, name))
    return packages


# ----- language lockfiles -----------------------------------------------------------------


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_package_lock(text: str, location: str) -> list[Package]:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        return []
    packages: list[Package] = []
    entries = payload.get("packages")
    if isinstance(entries, dict):
        for key, value in entries.items():
            if not key or not isinstance(value, dict) or value.get("link"):
                continue
            name = value.get("name") or key.rsplit("node_modules/", 1)[-1]
            version = value.get("version")
            if isinstance(name, str) and isinstance(version, str) and name:
                packages.append(Package("npm", name, version, location=location))
        return packages

    def walk(deps: Any, depth: int) -> None:
        if not isinstance(deps, dict) or depth > 64:
            return
        for name, value in deps.items():
            if not isinstance(value, dict):
                continue
            version = value.get("version")
            if isinstance(version, str) and not version.startswith(("file:", "git", "http")):
                packages.append(Package("npm", str(name), version, location=location))
            walk(value.get("dependencies"), depth + 1)

    walk(payload.get("dependencies"), 0)
    return packages


_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)\s*$")


def parse_requirements(text: str, location: str) -> list[Package]:
    packages: list[Package] = []
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        line = line.split(";", 1)[0].strip()
        line = re.sub(r"\s+--hash=\S+", "", line).rstrip("\\ ").strip()
        match = _REQ_LINE.match(line)
        if match:
            packages.append(
                Package("PyPI", normalize_pypi(match.group(1)), match.group(2), location=location)
            )
    return packages


def parse_poetry_lock(text: str, location: str) -> list[Package]:
    payload = tomllib.loads(text)
    packages: list[Package] = []
    for item in payload.get("package") or []:
        if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(
            item.get("version"), str
        ):
            packages.append(
                Package("PyPI", normalize_pypi(item["name"]), item["version"], location=location)
            )
    return packages


def parse_pipfile_lock(text: str, location: str) -> list[Package]:
    payload = json.loads(text)
    packages: list[Package] = []
    section = payload.get("default") if isinstance(payload, dict) else None
    if isinstance(section, dict):
        for name, value in section.items():
            version = value.get("version") if isinstance(value, dict) else None
            if isinstance(version, str) and version.startswith("=="):
                packages.append(
                    Package("PyPI", normalize_pypi(name), version[2:], location=location)
                )
    return packages


_LOCK_PARSERS = {
    "package-lock.json": parse_package_lock,
    ".package-lock.json": parse_package_lock,
    "requirements.txt": parse_requirements,
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
}


# ----- agent payload -> Inventory ----------------------------------------------------------


def _files(payload: dict[str, Any]) -> dict[str, list[tuple[str, bytes]]]:
    result: dict[str, list[tuple[str, bytes]]] = {}
    for item in payload.get("files") or []:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        entries: list[tuple[str, bytes]] = []
        for entry in item.get("entries") or []:
            if not isinstance(entry, dict):
                continue
            try:
                data = base64.b64decode(str(entry.get("data_b64") or ""), validate=True)
            except ValueError:
                continue
            entries.append((str(entry.get("name") or ""), data))
        result[item["path"]] = entries
    return result


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _dedupe(packages: Iterable[Package]) -> list[Package]:
    seen: dict[tuple[str, str, str, str], Package] = {}
    for package in packages:
        key = (package.ecosystem, package.name, package.version, package.binary or "")
        if key not in seen:
            seen[key] = package
    return sorted(seen.values(), key=lambda p: (p.ecosystem, p.name, p.version, p.binary or ""))


def build_inventory(payload: dict[str, Any]) -> Inventory:
    files = _files(payload)
    inventory = Inventory()
    release_entries = files.get("/etc/os-release") or files.get("/usr/lib/os-release") or []
    release = parse_os_release(_text(release_entries[0][1])) if release_entries else {}
    ecosystem = os_ecosystem(release) if release else None
    if release:
        inventory.os = {
            "id": release.get("ID", "")[:64] or None,
            "version_id": release.get("VERSION_ID", "")[:64] or None,
            "name": release.get("PRETTY_NAME", "")[:128] or None,
            "ecosystem": ecosystem,
        }
    packages: list[Package] = []

    def os_packages(kind: str) -> str | None:
        if ecosystem is None:
            inventory.notes.append(
                f"{kind} packages found but the OS "
                f"({release.get('ID') or 'unknown'} {release.get('VERSION_ID') or ''}".rstrip()
                + ") has no supported vulnerability feed"
            )
            return None
        return ecosystem

    dpkg = files.get("/var/lib/dpkg/status")
    status_d = files.get("/var/lib/dpkg/status.d")
    if dpkg or status_d:
        target = os_packages("dpkg")
        if target is not None:
            for _name, data in dpkg or []:
                packages.extend(parse_dpkg_status(_text(data), target))
            for name, data in status_d or []:
                if not name.endswith((".md5sums", ".list")):
                    packages.extend(parse_dpkg_status(_text(data), target))
    apk = files.get("/lib/apk/db/installed")
    if apk:
        target = os_packages("apk")
        if target is not None:
            for _name, data in apk:
                packages.extend(parse_apk_installed(_text(data), target))
    rpm = files.get("/var/lib/rpm/rpmdb.sqlite") or files.get(
        "/usr/lib/sysimage/rpm/rpmdb.sqlite"
    )
    if rpm:
        target = os_packages("rpm")
        if target is not None:
            for _name, data in rpm:
                try:
                    packages.extend(parse_rpmdb_sqlite(data, target))
                except sqlite3.Error:
                    inventory.notes.append("rpm database could not be read")
    elif "/var/lib/rpm/Packages" in files:
        inventory.notes.append(
            "rpm BerkeleyDB database (/var/lib/rpm/Packages) is not supported; "
            "only the SQLite rpmdb is scanned"
        )
    hidden_dirs = {
        path.removesuffix("/node_modules/.package-lock.json")
        for path in files
        if path.endswith("/node_modules/.package-lock.json") and files[path]
    }
    for path, entries in sorted(files.items()):
        filename = path.rsplit("/", 1)[-1]
        parser = _LOCK_PARSERS.get(filename)
        if parser is None or not entries:
            continue
        if filename == "package-lock.json" and path.removesuffix("/package-lock.json") in (
            hidden_dirs
        ):
            continue  # node_modules/.package-lock.json lists what is really installed
        for _name, data in entries:
            try:
                packages.extend(parser(_text(data), path))
            except (ValueError, tomllib.TOMLDecodeError, AttributeError, TypeError):
                inventory.notes.append(f"{path} could not be parsed")
    for item in payload.get("errors") or []:
        if isinstance(item, dict) and item.get("error") == "too_large":
            inventory.notes.append(f"{item.get('path')} exceeds the size limit and was skipped")
    deduped = _dedupe(packages)
    if len(deduped) > MAX_PACKAGES:
        inventory.notes.append(f"only the first {MAX_PACKAGES} packages were scanned")
        deduped = deduped[:MAX_PACKAGES]
    inventory.packages = deduped
    return inventory
