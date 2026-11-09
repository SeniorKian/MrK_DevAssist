"""Object and bucket tag sets (docs/30 §1.3: ≤ 10 object tags, ≤ 50 bucket tags).

Object tags are stored in the object's metadata as the URL-encoded query string
S3 uses for ``x-amz-tagging`` (``meta["tagging"]``), so tags set on PUT, on
CopyObject and via PutObjectTagging share one representation. Bucket tags are a
JSON list of ``[key, value]`` pairs in the bucket index ``settings`` table.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, quote

from .errors import S3Error
from .xmlio import XmlWriter, child_text, children, parse_xml

MAX_OBJECT_TAGS = 10
MAX_BUCKET_TAGS = 50
MAX_KEY_CHARS = 128
MAX_VALUE_CHARS = 256

Tags = list[tuple[str, str]]


def validate(tags: Tags, limit: int) -> Tags:
    if len(tags) > limit:
        raise S3Error("InvalidTag", f"Object tags cannot be greater than {limit}")
    seen: set[str] = set()
    for key, value in tags:
        if not key or len(key) > MAX_KEY_CHARS:
            raise S3Error("InvalidTag", "The TagKey you have provided is invalid")
        if len(value) > MAX_VALUE_CHARS:
            raise S3Error("InvalidTag", "The TagValue you have provided is invalid")
        if key.lower().startswith("aws:"):
            raise S3Error("InvalidTag", "Your TagKey cannot be prefixed with aws:")
        if key in seen:
            raise S3Error("InvalidTag", "Cannot provide multiple Tags with the same key")
        seen.add(key)
    return tags


def decode(query: str | None, *, strict: bool = True) -> Tags:
    """Parse the stored/``x-amz-tagging`` form (``k1=v1&k2=v2``)."""
    if not query:
        return []
    try:
        return parse_qsl(query, keep_blank_values=True, strict_parsing=strict)
    except ValueError as exc:
        raise S3Error(
            "InvalidArgument",
            "The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query parameters without tag name duplicates.",  # noqa: E501
            ArgumentName="x-amz-tagging",
        ) from exc


def encode(tags: Tags) -> str:
    return "&".join(f"{quote(key, safe='')}={quote(value, safe='')}" for key, value in tags)


def from_header(value: str) -> str:
    """Validate an ``x-amz-tagging`` header and return its normalized stored form."""
    return encode(validate(decode(value), MAX_OBJECT_TAGS))


def parse_xml_tags(body: bytes, limit: int) -> Tags:
    root = parse_xml(body)
    if root.tag != "Tagging":
        raise S3Error("MalformedXML")
    tag_sets = list(children(root, "TagSet"))
    if len(tag_sets) != 1:
        raise S3Error("MalformedXML")
    tags: Tags = []
    for tag in children(tag_sets[0], "Tag"):
        key = child_text(tag, "Key")
        value = child_text(tag, "Value")
        if key is None or value is None:
            raise S3Error("MalformedXML")
        tags.append((key, value))
    return validate(tags, limit)


def to_xml(tags: Tags) -> bytes:
    writer = XmlWriter().open("Tagging", xmlns=True).open("TagSet")
    for key, value in tags:
        writer.open("Tag").elem("Key", key).elem("Value", value).close("Tag")
    return writer.close("TagSet").close("Tagging").to_bytes()


def matches(stored: str | None, required: Tags) -> bool:
    """True when every ``(key, value)`` in ``required`` is among the stored tags."""
    if not required:
        return True
    have = dict(decode(stored, strict=False)) if stored else {}
    return all(have.get(key) == value for key, value in required)
