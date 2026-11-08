"""Safe XML parsing and minimal XML writing for S3 bodies (docs/30 §9 "XML parsing")."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET  # noqa: S405 - DTDs/entities are rejected below
from collections.abc import Iterable
from datetime import UTC, datetime
from xml.parsers import expat

from .errors import S3Error

S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"
XML_HEADER = '<?xml version="1.0" encoding="UTF-8"?>\n'
_INVALID_XML = re.compile("[^\u0009\u000a\u000d -퟿-�\U00010000-\U0010ffff]")
MAX_DEPTH = 32
MAX_ELEMENTS = 50_000


def has_invalid_xml_chars(value: str) -> bool:
    return bool(_INVALID_XML.search(value))


def escape(value: str) -> str:
    """Escape text for XML 1.0; characters XML cannot represent become U+FFFD."""
    value = _INVALID_XML.sub("�", value)
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def iso8601(timestamp_ns: int) -> str:
    moment = datetime.fromtimestamp(timestamp_ns / 1e9, UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def http_date(timestamp_ns: int) -> str:
    moment = datetime.fromtimestamp(timestamp_ns // 1_000_000_000, UTC)
    return moment.strftime("%a, %d %b %Y %H:%M:%S GMT")


class XmlWriter:
    """Tiny streaming-free XML builder that keeps element order exactly as written."""

    def __init__(self) -> None:
        self._parts: list[str] = [XML_HEADER]

    def open(self, tag: str, *, xmlns: bool = False) -> XmlWriter:
        self._parts.append(f'<{tag} xmlns="{S3_NS}">' if xmlns else f"<{tag}>")
        return self

    def close(self, tag: str) -> XmlWriter:
        self._parts.append(f"</{tag}>")
        return self

    def elem(self, tag: str, value: object | None) -> XmlWriter:
        if value is None:
            return self
        if isinstance(value, bool):
            text = "true" if value else "false"
        else:
            text = str(value)
        self._parts.append(f"<{tag}>{escape(text)}</{tag}>" if text != "" else f"<{tag}></{tag}>")
        return self

    def empty(self, tag: str, *, xmlns: bool = False) -> XmlWriter:
        self._parts.append(f'<{tag} xmlns="{S3_NS}"/>' if xmlns else f"<{tag}/>")
        return self

    def raw(self, text: str) -> XmlWriter:
        self._parts.append(text)
        return self

    def to_bytes(self) -> bytes:
        return "".join(self._parts).encode("utf-8")


def error_xml(
    code: str, message: str, request_id: str, host_id: str, details: dict[str, str]
) -> bytes:
    writer = XmlWriter().open("Error").elem("Code", code).elem("Message", message)
    for key, value in details.items():
        writer.elem(key, value)
    writer.elem("RequestId", request_id).elem("HostId", host_id).close("Error")
    return writer.to_bytes()


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_xml(body: bytes) -> ET.Element:
    """Parse an S3 request body. DOCTYPE/ENTITY declarations are refused (no XXE, no bombs)."""
    if not body.strip():
        raise S3Error("MalformedXML")
    # Pass 1: a bare expat scan that refuses any DTD/entity declaration.
    scanner = expat.ParserCreate()

    def _forbid(*_args: object) -> None:
        raise S3Error("MalformedXML", "DTDs and entities are not allowed.")

    scanner.StartDoctypeDeclHandler = _forbid
    scanner.EntityDeclHandler = _forbid
    scanner.ExternalEntityRefHandler = _forbid
    try:
        scanner.Parse(body, True)
    except S3Error:
        raise
    except expat.ExpatError as exc:
        raise S3Error("MalformedXML") from exc
    # Pass 2: the document is now known to have no DTD, so ElementTree is safe.
    try:
        root = ET.fromstring(body)  # noqa: S314 - DTDs were rejected above
    except ET.ParseError as exc:
        raise S3Error("MalformedXML") from exc
    count = 0
    stack: list[tuple[ET.Element, int]] = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_ELEMENTS:
            raise S3Error("MalformedXML", "The XML document is too complex.")
        element.tag = _local(element.tag) if isinstance(element.tag, str) else element.tag
        stack.extend((child, depth + 1) for child in element)
    return root


def child_text(element: ET.Element, name: str) -> str | None:
    for child in element:
        if child.tag == name:
            return child.text or ""
    return None


def children(element: ET.Element, name: str) -> Iterable[ET.Element]:
    return (child for child in element if child.tag == name)
