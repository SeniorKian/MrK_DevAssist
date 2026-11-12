"""Read-only import of the firewalls that exist before MRK manages ports (docs/45 §migration).

* UFW: ``/etc/ufw/user.rules`` + ``user6.rules`` (mounted read-only under the host etc
  root) -> one proposal per ``### tuple ###`` line.
* The legacy Docker chain ``PAASIFY-DOCKER-FW`` (and whether ``DOCKER-USER`` jumps to it)
  via ``iptables -S <chain>`` with a fixed argv; listing only, never a write.
* ``sshd_config`` ``Port`` lines, so the lockout check knows the real SSH port.

Proposals use the panel's port-rule shape and are imported as DISABLED rules; nothing
here deletes or changes UFW or the PAASIFY chain.
"""

from __future__ import annotations

import os
import re
import subprocess  # noqa: S404 - fixed argv only, see IptablesRunner
from pathlib import Path
from typing import Any

from .addresses import AddressError, parse_network
from .ports import PortError, format_ports, parse_ports

LEGACY_CHAIN = "PAASIFY-DOCKER-FW"
DOCKER_USER = "DOCKER-USER"
IPTABLES_BINARIES = (
    "/usr/sbin/iptables-nft", "/usr/sbin/iptables-legacy",
    "/usr/sbin/ip6tables-nft", "/usr/sbin/ip6tables-legacy",
)
_CHAINS = (LEGACY_CHAIN, DOCKER_USER)
MAX_FILE_BYTES = 1024 * 1024
MAX_PROPOSALS = 256
_ANY = {"0.0.0.0/0", "::/0", "any"}


def _read(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            return handle.read(MAX_FILE_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None


def _source(value: str | None) -> dict[str, Any] | None:
    """UFW/iptables source text -> panel source; None when unusable."""
    if value is None or value in _ANY:
        return {"kind": "public"}
    try:
        network = parse_network(value)
    except AddressError:
        return None
    if network.prefixlen == 0:
        return {"kind": "public"}
    return {"kind": "cidrs", "cidrs": [str(network)]}


def _ports(text: str | None) -> list[str] | None:
    if text is None or text == "any":
        return None
    try:
        return format_ports(parse_ports(text.replace(":", "-")))
    except PortError:
        return None


def _proposal(origin: str, *, action: str, protocol: str, ports: list[str],
              source: dict[str, Any], scope: str, raw: str, note: str = "") -> dict[str, Any]:
    verb = "allow" if action == "accept" else "deny"
    where = "any" if source["kind"] == "public" else ",".join(source.get("cidrs", []))
    name = f"{origin.upper()} {verb} {protocol} {','.join(ports)} from {where}"
    return {
        "name": name[:80],
        "description": note[:500],
        "protocol": protocol,
        "ports": ports,
        "source": source,
        "scope": scope,
        "action": action,
        "log": False,
        "origin": origin,
        "raw": raw[:300],
    }


# ----- UFW -----------------------------------------------------------------------

_TUPLE = "### tuple ###"
_DPORT = re.compile(r"--dports?\s+(\S+)")
_PROTO = re.compile(r"(?:^|\s)-p\s+(\S+)")


def parse_ufw_rules(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse ufw user.rules / user6.rules. Returns (proposals, skipped raw tuples)."""
    proposals: list[dict[str, Any]] = []
    skipped: list[str] = []
    blocks: list[tuple[str, list[str]]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(_TUPLE):
            blocks.append((line, []))
        elif line.startswith("-A ") and blocks:
            blocks[-1][1].append(line)
    for tuple_line, commands in blocks:
        fields = tuple_line[len(_TUPLE):].split()
        comment = ""
        if fields and fields[-1].startswith("comment="):
            try:
                comment = bytes.fromhex(fields.pop()[8:]).decode("utf-8", "replace")
            except ValueError:
                comment = ""
        if len(fields) not in (7, 9):
            skipped.append(tuple_line)
            continue
        action, protocol, dport, dst, _sport, src = fields[:6]
        direction = fields[-1]
        route = action.startswith("route:")
        action = action.removeprefix("route:")
        if direction.startswith("out") or action not in {"allow", "deny", "reject", "limit"}:
            skipped.append(tuple_line)
            continue
        source = _source(src)
        ports = _ports(dport)
        protocols = [protocol] if protocol in {"tcp", "udp"} else ["tcp", "udp"]
        if len(fields) == 9 or ports is None:
            # Application profiles ("OpenSSH") or no port: take ports from the iptables
            # lines UFW generated for this tuple.
            found: dict[str, list[str]] = {}
            for command in commands:
                port_match = _DPORT.search(command)
                proto_match = _PROTO.search(command)
                if port_match and proto_match and proto_match.group(1) in {"tcp", "udp"}:
                    found.setdefault(proto_match.group(1), []).append(port_match.group(1))
            if not found:
                skipped.append(tuple_line)
                continue
            groups = {proto: _ports(",".join(items)) for proto, items in found.items()}
        else:
            groups = {proto: ports for proto in protocols}
        if source is None or any(value is None for value in groups.values()):
            skipped.append(tuple_line)
            continue
        notes = [comment] if comment else []
        if dst not in _ANY:
            notes.append(f"UFW destination {dst} (not imported: the panel matches sources only)")
        if "_" in direction:
            notes.append(f"UFW interface rule ({direction})")
        if action == "limit":
            notes.append("UFW rate limit (limit) imported as allow")
        verdict = "accept" if action in {"allow", "limit"} else "drop"
        same = [items for items in groups.values()]
        if len(groups) == 2 and same[0] == same[1]:
            groups = {"both": same[0]}
        for proto, items in groups.items():
            assert items is not None
            proposals.append(_proposal(
                "ufw", action=verdict, protocol=proto, ports=items, source=source,
                scope="docker" if route else "host", raw=tuple_line, note="; ".join(notes)))
    return proposals, skipped


def parse_ufw_enabled(text: str | None) -> bool | None:
    if text is None:
        return None
    for line in text.splitlines():
        key, _, value = line.strip().partition("=")
        if key == "ENABLED":
            return value.strip().strip("\"'").lower() == "yes"
    return None


def merge_families(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge the IPv4 and IPv6 copy of the same public rule into one proposal."""
    merged: list[dict[str, Any]] = []
    seen: dict[tuple[Any, ...], dict[str, Any]] = {}
    for item in items:
        if item["source"]["kind"] == "public":
            key = (item["origin"], item["action"], item["protocol"], tuple(item["ports"]),
                   item["scope"])
            if key in seen:
                continue
            seen[key] = item
        merged.append(item)
    return merged[:MAX_PROPOSALS]


# ----- iptables (legacy PAASIFY chain) -------------------------------------------

_OPTION = re.compile(r"(!\s+)?(-{1,2}[A-Za-z][\w-]*)(?:\s+(\"[^\"]*\"|[^\s-][^\s]*))?")


def _options(line: str) -> list[tuple[bool, str, str | None]]:
    return [(bool(match.group(1)), match.group(2), match.group(3))
            for match in _OPTION.finditer(line)]


def parse_iptables_chain(text: str, chain: str = LEGACY_CHAIN
                         ) -> tuple[list[dict[str, Any]], list[str], bool]:
    """Parse ``iptables -S <chain>``. Returns (proposals, skipped lines, ends_with_drop)."""
    proposals: list[dict[str, Any]] = []
    skipped: list[str] = []
    final_drop = False
    prefix = f"-A {chain} "
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith(prefix):
            continue
        options = _options(line[len(prefix):])
        values: dict[str, str | None] = {}
        negated = False
        for neg, name, value in options:
            negated = negated or neg
            values[name] = value
        target = values.get("-j")
        if negated or target is None:
            skipped.append(line)
            continue
        if "--ctstate" in values or "--state" in values or target == "LOG":
            continue  # established/related and logging are part of every MRK chain
        verdict = {"ACCEPT": "accept", "RETURN": "accept", "DROP": "drop",
                   "REJECT": "drop"}.get(target)
        protocol = values.get("-p")
        port_text = values.get("--dport") or values.get("--dports") \
            or values.get("--ctorigdstport")
        source = _source(values.get("-s") or values.get("--source"))
        if verdict is None or source is None:
            skipped.append(line)
            continue
        if port_text is None:
            if verdict == "drop" and protocol is None and source["kind"] == "public" \
                    and "-i" not in values:
                final_drop = True
                continue
            if "-i" in values and values["-i"] == "lo":
                continue
            skipped.append(line)
            continue
        ports = _ports(port_text)
        if ports is None or protocol not in {"tcp", "udp"}:
            skipped.append(line)
            continue
        notes = []
        if "-i" in values:
            notes.append(f"interface {values['-i']} (not imported)")
        if "-d" in values:
            notes.append(f"destination {values['-d']} (not imported)")
        proposals.append(_proposal("paasify", action=verdict, protocol=protocol, ports=ports,
                                   source=source, scope="docker", raw=line,
                                   note="; ".join(notes)))
    # tcp+udp twins of the same ports/source become one "both" proposal.
    combined: list[dict[str, Any]] = []
    for item in proposals:
        twin = next((other for other in combined if other["protocol"] != item["protocol"]
                     and other["protocol"] != "both" and other["ports"] == item["ports"]
                     and other["source"] == item["source"]
                     and other["action"] == item["action"]), None)
        if twin is not None:
            twin["protocol"] = "both"
            twin["name"] = twin["name"].replace(" tcp ", " both ").replace(" udp ", " both ")
        else:
            combined.append(item)
    return combined, skipped, final_drop


def jumps_to(text: str, target: str = LEGACY_CHAIN, chain: str = DOCKER_USER) -> bool:
    return any(line.strip().startswith(f"-A {chain} ") and f"-j {target}" in line
               for line in text.splitlines())


class IptablesRunner:
    """``<iptables binary> -S <chain>`` only; read-only by construction."""

    def available(self, binary: str) -> bool:
        return os.path.isfile(binary) and os.access(binary, os.X_OK)

    def list_chain(self, binary: str, chain: str) -> tuple[int, str]:
        if binary not in IPTABLES_BINARIES or chain not in _CHAINS:
            raise ValueError("iptables argv is not on the allowlist")
        if not self.available(binary):
            return 127, ""
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False
                [binary, "-S", chain], capture_output=True, text=True, timeout=10, check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                     "XTABLES_LOCKFILE": "/tmp/xtables.lock"},  # noqa: S108 - private tmpfs
            )
        except (OSError, subprocess.TimeoutExpired):
            return 126, ""
        return completed.returncode, completed.stdout[:MAX_FILE_BYTES]


def read_legacy_chain(runner: IptablesRunner) -> dict[str, Any]:
    proposals: list[dict[str, Any]] = []
    skipped: list[str] = []
    found_backend: str | None = None
    final_drop = False
    jump: bool | None = None
    any_binary = False
    for family in ("iptables", "ip6tables"):
        for backend in ("nft", "legacy"):
            binary = f"/usr/sbin/{family}-{backend}"
            if not runner.available(binary):
                continue
            any_binary = True
            code, text = runner.list_chain(binary, LEGACY_CHAIN)
            if code != 0:
                continue
            found_backend = found_backend or backend
            items, rest, drop = parse_iptables_chain(text)
            proposals.extend(items)
            skipped.extend(rest)
            final_drop = final_drop or drop
            jump_code, jump_text = runner.list_chain(binary, DOCKER_USER)
            if jump_code == 0:
                jump = bool(jump) or jumps_to(jump_text)
            break
    return {
        "available": any_binary,
        "present": found_backend is not None,
        "backend": found_backend,
        "rules": merge_families(proposals),
        "skipped": skipped[:100],
        "default_drop": final_drop,
        "docker_user_jump": jump,
    }


def read_ufw(etc_root: Path) -> dict[str, Any]:
    root = etc_root / "ufw"
    proposals: list[dict[str, Any]] = []
    skipped: list[str] = []
    present = False
    for name in ("user.rules", "user6.rules"):
        text = _read(root / name)
        if text is None:
            continue
        present = True
        items, rest = parse_ufw_rules(text)
        proposals.extend(items)
        skipped.extend(rest)
    return {
        "present": present,
        "enabled": parse_ufw_enabled(_read(root / "ufw.conf")),
        "rules": merge_families(proposals),
        "skipped": skipped[:100],
    }


# ----- sshd ------------------------------------------------------------------------


_SSHD_LINE = re.compile(r"^\s*([A-Za-z]+)(?:\s*=\s*|\s+)(.*?)\s*$")
_MAX_INCLUDES = 32


def _sshd_directives(text: str) -> list[tuple[str, str]]:
    """(lower-case keyword, value) of the global part (before the first Match)."""
    out: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0]
        match = _SSHD_LINE.match(line)
        if match is None:
            continue
        key = match.group(1).lower()
        if key == "match":
            break  # Port is not allowed inside Match blocks anyway
        out.append((key, match.group(2).strip().strip('"')))
    return out


def _port_value(value: str) -> int | None:
    return int(value) if value.isdigit() and 1 <= int(value) <= 65535 else None


def parse_sshd_ports(text: str) -> list[int]:
    ports: list[int] = []
    for key, value in _sshd_directives(text):
        port: int | None = None
        if key == "port":
            port = _port_value(value)
        elif key == "listenaddress":
            match = re.search(r":(\d{1,5})$", value)
            port = _port_value(match.group(1)) if match else None
        if port is not None and port not in ports:
            ports.append(port)
    return ports


def _host_path(etc_root: Path, value: str, base: str = "/etc/ssh") -> Path | None:
    """Map a host path (absolute, or relative to /etc/ssh) onto the read-only mount."""
    path = value if value.startswith("/") else f"{base}/{value}"
    parts = [part for part in path.split("/") if part]
    if len(parts) < 2 or parts[0] != "etc" or any(part in {".", ".."} for part in parts):
        return None
    return etc_root.joinpath(*parts[1:])


def _expand(pattern: Path) -> list[Path]:
    if not any(char in pattern.name for char in "*?["):
        return [pattern]
    try:
        return sorted(pattern.parent.glob(pattern.name)) if pattern.parent.is_dir() else []
    except OSError:
        return []


def read_sshd_config(etc_root: Path) -> dict[str, Any]:
    """Ports of ``/etc/ssh/sshd_config`` with its ``Include`` files (Port is cumulative;
    no Port line at all means sshd's default 22)."""
    main = etc_root / "ssh" / "sshd_config"
    text = _read(main)
    if text is None:
        return {"readable": False, "ports": [], "files": 0}
    ports: list[int] = []
    seen: set[Path] = set()

    def walk(content: str, depth: int) -> None:
        for key, value in _sshd_directives(content):
            if key == "include" and depth < 3:
                for item in value.split():
                    pattern = _host_path(etc_root, item)
                    if pattern is None:
                        continue
                    for path in _expand(pattern):
                        if path in seen or len(seen) >= _MAX_INCLUDES:
                            continue
                        seen.add(path)
                        included = _read(path)
                        if included:
                            walk(included, depth + 1)
        ports.extend(port for port in parse_sshd_ports(content) if port not in ports)

    seen.add(main)
    walk(text, 0)
    return {"readable": True, "ports": ports or [22], "files": len(seen)}


def read_sshd_ports(etc_root: Path) -> dict[str, Any]:
    config = read_sshd_config(etc_root)
    if not config["readable"]:
        return {"detected": False, "ports": [22]}
    return {"detected": True, "ports": config["ports"]}


# ----- systemd socket activation (Ubuntu 22.10+: ssh.socket) ------------------------

_SOCKET_UNITS = ("ssh.socket", "sshd.socket")


def parse_listen_streams(text: str, current: list[int] | None = None) -> list[int] | None:
    """Apply one unit file's ``[Socket] ListenStream=`` lines to ``current``; an empty
    ``ListenStream=`` resets the list (systemd semantics). None = the file sets none."""
    result = None if current is None else list(current)
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        key, sep, value = line.partition("=")
        if section != "socket" or not sep or key.strip().lower() != "listenstream":
            continue
        value = value.strip()
        if not value:
            result = []
            continue
        if value.startswith(("/", "@")) or "vsock:" in value:
            result = result if result is not None else []
            continue  # unix / abstract / vsock sockets are not TCP ports
        match = re.search(r"(?:^|:|\])(\d{1,5})$", value)
        port = _port_value(match.group(1)) if match else None
        result = result if result is not None else []
        if port is not None and port not in result:
            result.append(port)
    return result


def read_ssh_socket(etc_root: Path) -> dict[str, Any]:
    """``ssh.socket`` facts from ``/etc/systemd/system`` (needs /etc/systemd mounted).

    ``explicit`` = an override in /etc sets ListenStream; without one, the stock unit in
    /lib (22) or the sshd_config generator of Ubuntu 24.04+ decides, so sshd_config wins.
    """
    system = etc_root / "systemd" / "system"
    try:
        readable = system.is_dir()
    except OSError:
        readable = False
    if not readable:
        return {"readable": False, "enabled": None, "explicit": False, "ports": []}
    wants = system / "sockets.target.wants"
    enabled = any((wants / name).is_symlink() or (wants / name).exists()
                  for name in _SOCKET_UNITS)
    ports: list[int] | None = None
    for name in _SOCKET_UNITS:
        text = _read(system / name)
        if text is not None:
            ports = parse_listen_streams(text, ports)
        dropins = system / f"{name}.d"
        try:
            files = sorted(dropins.glob("*.conf")) if dropins.is_dir() else []
        except OSError:
            files = []
        for path in files[:32]:
            content = _read(path)
            if content is not None:
                ports = parse_listen_streams(content, [22] if ports is None else ports)
    explicit = ports is not None
    return {"readable": True, "enabled": enabled, "explicit": explicit,
            "ports": ports if ports else []}
