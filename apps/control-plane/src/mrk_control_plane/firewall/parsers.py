"""Log line parsers: sshd (syslog text) and Traefik access logs (JSON or CLF).

Each parser turns one line into zero or more compact signals ``{kind, ip, detail}``.
Rules, thresholds and decisions are applied by the control plane, not here.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass

from .addresses import parse_ip

SIGNAL_KINDS = (
    "ssh_failed_password",
    "ssh_invalid_user",
    "mrk_login_failure",
    "http_401",
    "http_403",
    "http_404",
    "http_sensitive_path",
)
SOURCE_KINDS = ("sshd", "traefik")
DEFAULT_SENSITIVE_PATHS = (
    "/.env",
    "/.git/",
    "/.aws/",
    "/.ssh/",
    "/wp-login.php",
    "/wp-admin/",
    "/xmlrpc.php",
    "/phpmyadmin/",
    "/pma/",
    "/vendor/phpunit/",
    "/cgi-bin/",
    "/boaform/",
    "/server-status",
    "/actuator/",
    "/config.json",
    "/.DS_Store",
)
MAX_PATTERNS = 100
MAX_DETAIL = 120
_PATTERN = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,127}$")
_IP = r"([0-9A-Fa-f:.]{2,45})"
_SSHD = re.compile(r"\bsshd(?:-session)?\[\d+\]: (?P<msg>.*)$")
_SSH_FAILED = re.compile(
    r"^Failed (?:password|publickey|keyboard-interactive/pam|none) for "
    r"(?P<invalid>invalid user )?(?P<user>\S{0,64}) from " + _IP + r" port \d+"
)
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>\S{0,64}) from " + _IP + r"(?: port \d+)?")
_CLF = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]{1,64}\] "(?P<method>[A-Z]{1,16}) (?P<path>\S{1,4096})'
    r'(?: [^"]{0,32})?" (?P<status>\d{3}) '
)
_SAFE_DETAIL = re.compile(r"[^A-Za-z0-9._~/@:=+,-]")


@dataclass(frozen=True, slots=True)
class Signal:
    kind: str
    ip: str
    detail: str = ""

    def to_dict(self, source: str, ts: float) -> dict[str, object]:
        return {"source": source, "kind": self.kind, "ip": self.ip, "detail": self.detail,
                "ts": round(ts, 3)}


def clean_detail(text: str) -> str:
    return _SAFE_DETAIL.sub("_", text)[:MAX_DETAIL]


def validate_patterns(patterns: Iterable[object]) -> list[str]:
    result: list[str] = []
    for item in patterns:
        if not isinstance(item, str) or not _PATTERN.fullmatch(item.strip()):
            raise ValueError("sensitive paths must start with / and use URL path characters")
        value = item.strip().lower()
        if value not in result:
            result.append(value)
    if len(result) > MAX_PATTERNS:
        raise ValueError(f"at most {MAX_PATTERNS} sensitive paths are allowed")
    return result


class PathMatcher:
    """Match a pattern as a whole run of path segments anywhere in the request path.

    ``/.env`` matches ``/.env`` and ``/app/.env`` but not ``/.envoy``; a pattern ending
    in ``/`` (``/.git/``) matches everything below it.
    """

    def __init__(self, patterns: Iterable[str]) -> None:
        self.needles = [p.lower().rstrip("/") + "/" for p in patterns if p.strip("/")]

    def match(self, path: str) -> str | None:
        clean = path.split("?", 1)[0].split("#", 1)[0].lower()
        haystack = "/" + clean.strip("/") + "/"
        for needle in self.needles:
            if needle in haystack:
                return needle.rstrip("/")
        return None


def parse_sshd(line: str) -> Signal | None:
    match = _SSHD.search(line)
    if match is None:
        return None
    message = match.group("msg")
    failed = _SSH_FAILED.match(message)
    if failed is not None:
        ip = parse_ip(failed.group(3))
        if ip is None:
            return None
        kind = "ssh_invalid_user" if failed.group("invalid") else "ssh_failed_password"
        return Signal(kind, str(ip), clean_detail(failed.group("user")))
    invalid = _SSH_INVALID.match(message)
    if invalid is not None:
        ip = parse_ip(invalid.group(2))
        if ip is None:
            return None
        return Signal("ssh_invalid_user", str(ip), clean_detail(invalid.group("user")))
    return None


def _split_host_port(value: str) -> str:
    text = value.strip()
    if text.startswith("["):
        return text[1:].split("]", 1)[0]
    if text.count(":") == 1:
        return text.split(":", 1)[0]
    return text


def _http_signals(ip_text: str, status: int, path: str, matcher: PathMatcher) -> list[Signal]:
    ip = parse_ip(ip_text)
    if ip is None:
        return []
    signals: list[Signal] = []
    detail = clean_detail(path.split("?", 1)[0])
    if status in (401, 403, 404):
        signals.append(Signal(f"http_{status}", str(ip), detail))
    hit = matcher.match(path)
    if hit is not None:
        signals.append(Signal("http_sensitive_path", str(ip), clean_detail(hit)))
    return signals


def parse_traefik(line: str, matcher: PathMatcher) -> list[Signal]:
    text = line.strip()
    if not text:
        return []
    if text.startswith("{"):
        try:
            record = json.loads(text)
        except ValueError:
            return []
        if not isinstance(record, dict):
            return []
        host = record.get("ClientHost")
        if not isinstance(host, str) or not host:
            addr = record.get("ClientAddr")
            host = _split_host_port(addr) if isinstance(addr, str) else ""
        status = record.get("DownstreamStatus")
        path = record.get("RequestPath")
        if isinstance(status, str) and status.isdigit():
            status = int(status)
        if not isinstance(status, int) or not isinstance(path, str):
            return []
        return _http_signals(host, status, path[:4096], matcher)
    match = _CLF.match(text)
    if match is None:
        return []
    return _http_signals(match.group("ip"), int(match.group("status")), match.group("path"),
                         matcher)


def parse_lines(kind: str, lines: Iterable[str], matcher: PathMatcher) -> list[Signal]:
    out: list[Signal] = []
    for line in lines:
        if kind == "sshd":
            signal = parse_sshd(line)
            if signal is not None:
                out.append(signal)
        elif kind == "traefik":
            out.extend(parse_traefik(line, matcher))
    return out
