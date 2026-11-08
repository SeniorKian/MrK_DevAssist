"""Gate 19 S8: package inventory parsers (fixed agent paths -> packages)."""

from __future__ import annotations

import base64
import json
import sqlite3
import struct
from pathlib import Path

from mrk_control_plane.modules.vuln_inventory import (
    build_inventory,
    os_ecosystem,
    parse_apk_installed,
    parse_dpkg_status,
    parse_os_release,
    parse_package_lock,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_requirements,
    parse_rpm_header,
)

DPKG_STATUS = """\
Package: libssl3
Status: install ok installed
Priority: optional
Architecture: amd64
Source: openssl
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 multi-line description that mentions Version: 9.9

Package: openssl
Status: install ok installed
Version: 3.0.11-1~deb12u2

Package: zlib1g
Status: install ok installed
Source: zlib (1:1.2.13.dfsg-1)
Version: 1:1.2.13.dfsg-1+b1

Package: removed-thing
Status: deinstall ok config-files
Version: 1.0-1
"""

APK_INSTALLED = """\
C:Q1abc=
P:libcrypto3
V:3.1.4-r0
A:x86_64
o:openssl
T:Crypto library

P:busybox
V:1.36.1-r15
o:busybox
"""

OS_RELEASE_DEBIAN = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n'
OS_RELEASE_ALPINE = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\n"


def test_os_release_to_ecosystem() -> None:
    assert os_ecosystem(parse_os_release(OS_RELEASE_DEBIAN)) == "Debian:12"
    assert os_ecosystem(parse_os_release(OS_RELEASE_ALPINE)) == "Alpine:v3.20"
    assert os_ecosystem({"ID": "ubuntu", "VERSION_ID": "22.04"}) == "Ubuntu:22.04:LTS"
    assert os_ecosystem({"ID": "ubuntu", "VERSION_ID": "23.10"}) == "Ubuntu:23.10"
    assert os_ecosystem({"ID": "rocky", "VERSION_ID": "9.4"}) == "Rocky Linux:9"
    assert os_ecosystem({"ID": "almalinux", "VERSION_ID": "8.10"}) == "AlmaLinux:8"
    assert os_ecosystem({"ID": "wolfi"}) == "Wolfi"
    assert os_ecosystem({"ID": "fedora", "VERSION_ID": "40"}) is None
    assert os_ecosystem({"ID": "debian"}) is None  # sid/testing without VERSION_ID


def test_dpkg_status_uses_source_package_and_version() -> None:
    packages = parse_dpkg_status(DPKG_STATUS, "Debian:12")
    found = {(p.name, p.version, p.binary) for p in packages}
    assert found == {
        ("openssl", "3.0.11-1~deb12u2", "libssl3"),
        ("openssl", "3.0.11-1~deb12u2", None),
        ("zlib", "1:1.2.13.dfsg-1", "zlib1g"),  # binNMU: source version is what OSV knows
    }


def test_apk_uses_origin() -> None:
    packages = parse_apk_installed(APK_INSTALLED, "Alpine:v3.20")
    assert {(p.name, p.version, p.binary) for p in packages} == {
        ("openssl", "3.1.4-r0", "libcrypto3"),
        ("busybox", "1.36.1-r15", None),
    }


def test_package_lock_v3_v1_and_requirements() -> None:
    v3 = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/@scope/pkg": {"version": "2.0.0"},
                "node_modules/a/node_modules/lodash": {"version": "3.10.1"},
                "node_modules/local": {"link": True, "resolved": "../local"},
            },
        }
    )
    assert {(p.name, p.version) for p in parse_package_lock(v3, "/app/package-lock.json")} == {
        ("lodash", "4.17.20"), ("@scope/pkg", "2.0.0"), ("lodash", "3.10.1"),
    }
    v1 = json.dumps(
        {"dependencies": {"minimist": {"version": "0.0.8", "dependencies": {
            "deep": {"version": "1.0.0"}}}, "gitdep": {"version": "git+https://x/y.git"}}}
    )
    assert {(p.name, p.version) for p in parse_package_lock(v1, "x")} == {
        ("minimist", "0.0.8"), ("deep", "1.0.0"),
    }
    requirements = (
        "--index-url https://user:secret@pypi.example/simple\n"
        "Django==4.2.1  # pinned\n"
        "requests[socks]==2.31.0 ; python_version > '3.8'\n"
        "PyYAML===6.0 \\\n    --hash=sha256:abc\n"
        "flask>=2.0\n"
        "-r other.txt\n"
        "-e git+https://github.com/x/y.git#egg=y\n"
    )
    assert {(p.name, p.version) for p in parse_requirements(requirements, "r")} == {
        ("django", "4.2.1"), ("requests", "2.31.0"), ("pyyaml", "6.0"),
    }


def test_poetry_and_pipfile_lock() -> None:
    poetry = '[[package]]\nname = "Jinja2"\nversion = "3.1.2"\n\n[[package]]\nname = "x"\n'
    assert [(p.name, p.version) for p in parse_poetry_lock(poetry, "p")] == [("jinja2", "3.1.2")]
    pipfile = json.dumps(
        {"default": {"urllib3": {"version": "==1.26.5"}, "editable": {"path": "."}},
         "develop": {"pytest": {"version": "==7.0.0"}}}
    )
    assert [(p.name, p.version) for p in parse_pipfile_lock(pipfile, "p")] == [
        ("urllib3", "1.26.5")
    ]


def rpm_header(tags: dict[int, str | int]) -> bytes:
    index = b""
    store = b""
    for tag, value in tags.items():
        if isinstance(value, int):
            while len(store) % 4:
                store += b"\0"
            index += struct.pack(">iIiI", tag, 4, len(store), 1)
            store += struct.pack(">I", value)
        else:
            index += struct.pack(">iIiI", tag, 6, len(store), 1)
            store += value.encode() + b"\0"
    return struct.pack(">II", len(tags), len(store)) + index + store


def rpmdb_bytes(tmp_path: Path) -> bytes:
    path = tmp_path / "rpmdb.sqlite"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB)")
    rows = [
        {1000: "openssl-libs", 1001: "3.0.7", 1002: "25.el9_3", 1003: 1,
         1044: "openssl-3.0.7-25.el9_3.src.rpm"},
        {1000: "bash", 1001: "5.1.8", 1002: "6.el9", 1044: "bash-5.1.8-6.el9.src.rpm"},
        {1000: "gpg-pubkey", 1001: "abc", 1002: "1"},
    ]
    db.executemany("INSERT INTO Packages (blob) VALUES (?)", [(rpm_header(r),) for r in rows])
    db.commit()
    db.close()
    return path.read_bytes()


def test_rpm_header_parser() -> None:
    header = parse_rpm_header(rpm_header({1000: "bash", 1001: "5.1", 1003: 2}))
    assert header == {"name": "bash", "version": "5.1", "epoch": 2}


def _file(path: str, *entries: tuple[str, bytes], note: str | None = None) -> dict:
    return {
        "path": path,
        "note": note,
        "entries": [
            {"name": name, "size": len(data), "data_b64": base64.b64encode(data).decode()}
            for name, data in entries
        ],
    }


def test_build_inventory_debian_distroless_and_lockfiles() -> None:
    hidden = json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.21"}}})
    full = json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.20"}}})
    payload = {
        "files": [
            _file("/etc/os-release", ("os-release", OS_RELEASE_DEBIAN.encode())),
            _file("/var/lib/dpkg/status.d",
                  ("status.d/base", b"Package: base-files\nVersion: 12.4\n"),
                  ("status.d/base.md5sums", b"abc  /etc/x\n")),
            _file("/app/package-lock.json", ("package-lock.json", full.encode())),
            _file("/app/node_modules/.package-lock.json", (".package-lock.json", hidden.encode())),
            _file("/srv/requirements.txt", ("requirements.txt", b"django==4.2\n")),
            _file("/srv/poetry.lock", ("poetry.lock", b"not = [valid")),
        ],
        "errors": [{"path": "/var/lib/rpm/rpmdb.sqlite", "error": "too_large"}],
    }
    inventory = build_inventory(payload)
    assert inventory.os["ecosystem"] == "Debian:12"
    assert inventory.os["name"] == "Debian GNU/Linux 12 (bookworm)"
    assert {(p.ecosystem, p.name, p.version) for p in inventory.packages} == {
        ("Debian:12", "base-files", "12.4"),
        ("npm", "lodash", "4.17.21"),  # hidden lockfile wins over package-lock.json
        ("PyPI", "django", "4.2"),
    }
    assert any("poetry.lock could not be parsed" in note for note in inventory.notes)
    assert any("size limit" in note for note in inventory.notes)


def test_build_inventory_alpine_rpm_and_unsupported(tmp_path: Path) -> None:
    alpine = build_inventory({"files": [
        _file("/usr/lib/os-release", ("os-release", OS_RELEASE_ALPINE.encode())),
        _file("/lib/apk/db/installed", ("installed", APK_INSTALLED.encode())),
    ]})
    assert alpine.ecosystems() == {"Alpine:v3.20"}
    assert len(alpine.packages) == 2

    rocky = build_inventory({"files": [
        _file("/etc/os-release", ("os-release", b"ID=rocky\nVERSION_ID=9.3\n")),
        _file("/var/lib/rpm/rpmdb.sqlite", ("rpmdb.sqlite", rpmdb_bytes(tmp_path))),
    ]})
    assert {(p.name, p.version, p.binary) for p in rocky.packages} == {
        ("openssl-libs", "1:3.0.7-25.el9_3", None),
        ("openssl", "1:3.0.7-25.el9_3", "openssl-libs"),
        ("bash", "5.1.8-6.el9", None),
    }
    assert rocky.ecosystems() == {"Rocky Linux:9"}

    bdb = build_inventory({"files": [
        _file("/etc/os-release", ("os-release", b"ID=centos\nVERSION_ID=7\n")),
        _file("/var/lib/rpm/Packages", note="present"),
    ]})
    assert bdb.packages == []
    assert any("BerkeleyDB" in note for note in bdb.notes)

    fedora_dpkg = build_inventory({"files": [
        _file("/etc/os-release", ("os-release", b"ID=fedora\nVERSION_ID=40\n")),
        _file("/lib/apk/db/installed", ("installed", APK_INSTALLED.encode())),
    ]})
    assert fedora_dpkg.packages == []
    assert any("no supported vulnerability feed" in note for note in fedora_dpkg.notes)
