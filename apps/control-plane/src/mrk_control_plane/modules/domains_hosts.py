"""Host-name rules for service domains (docs/35 §3).

A stored host is canonical: IDNA (punycode) A-labels, lowercase, no trailing dot,
no scheme, port, path, wildcard or IP literal. ``canonical_host`` raises
``HostError`` with a field ``reason_code`` the panel maps to plain text.
"""

from __future__ import annotations

import ipaddress
import re

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOST_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})+$")
_RESERVED_SUFFIXES = (".localhost", ".invalid")


class HostError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


def canonical_host(raw: object) -> str:
    if not isinstance(raw, str):
        raise HostError("invalid_type", "host must be text")
    text = raw.strip()
    if not text:
        raise HostError("required", "host is required")
    if len(text) > 300:
        raise HostError("too_long", "host is too long")
    if "://" in text or "/" in text or "?" in text or "#" in text or "@" in text:
        raise HostError("invalid_format", "enter only the host name (no http://, path or query)")
    if "*" in text:
        raise HostError("wildcard_not_allowed", "wildcard domains are not supported")
    if any(char.isspace() or ord(char) < 32 for char in text):
        raise HostError("invalid_format", "host must not contain spaces")
    if text.startswith("[") or _is_ip(text):
        raise HostError("ip_not_allowed", "use a domain name, not an IP address")
    if ":" in text:
        raise HostError("port_not_allowed", "do not add a port; Pishkar picks the service port")
    text = text.rstrip(".").lower()
    labels = text.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        raise HostError("invalid_format", "host must look like name.example.com")
    encoded: list[str] = []
    for label in labels:
        if label.isascii():
            encoded.append(label)
            continue
        try:
            encoded.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            raise HostError("invalid_format", "host contains an invalid label") from None
    host = ".".join(encoded)
    if not HOST_RE.fullmatch(host):
        raise HostError("invalid_format", "host must look like name.example.com")
    if labels[-1].isdigit():
        raise HostError("invalid_format", "the last label must not be a number")
    if host == "localhost" or host.endswith(_RESERVED_SUFFIXES):
        raise HostError("reserved_name", "this name cannot be reached from the internet")
    return host


def display_host(host: str) -> str:
    """Unicode form for showing (best effort; the stored canonical form never changes)."""
    try:
        return ".".join(
            label.encode("ascii").decode("idna") if label.startswith("xn--") else label
            for label in host.split(".")
        )
    except UnicodeError:
        return host


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return False
    return True
