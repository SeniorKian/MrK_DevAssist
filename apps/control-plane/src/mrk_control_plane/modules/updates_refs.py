"""Pure helpers for image update tracking (docs/31 §5): no I/O here.

* ``parse_reference`` follows Docker's normalisation: no registry component means
  ``docker.io``; single-component Docker Hub names get ``library/``; the tag
  defaults to ``latest``; ``@sha256:...`` pins the image.
* ``local_digests`` picks the RepoDigests that belong to the same registry +
  repository as the reference (RepoDigests are recorded per repository).
* ``parse_challenge`` reads RFC 7235 ``WWW-Authenticate`` (quoted strings,
  commas inside quotes).
* ``parse_rate_limit`` reads Docker Hub's ``ratelimit-*`` headers (``N;w=21600``).
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

DOCKER_HUB = "docker.io"
DOCKER_HUB_API = "registry-1.docker.io"
_HUB_ALIASES = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})

_COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_HOST = re.compile(
    r"^(?:localhost|[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    r"|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?$"
)
_IMAGE_ID = re.compile(r"^(?:sha256:)?[a-f0-9]{12,64}$")

MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


class InvalidReference(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ImageRef:
    registry: str  # normalised host[:port]; "docker.io" for Docker Hub
    repository: str  # path inside the registry, e.g. "library/nginx"
    tag: str  # "latest" when omitted
    digest: str | None = None  # set when the reference is pinned

    @property
    def pinned(self) -> bool:
        return self.digest is not None

    @property
    def familiar(self) -> str:
        """Short repository name as docker shows it (``nginx``, ``ghcr.io/o/app``)."""
        if self.registry == DOCKER_HUB:
            return self.repository.removeprefix("library/")
        return f"{self.registry}/{self.repository}"

    @property
    def canonical_repository(self) -> str:
        return f"{self.registry}/{self.repository}"

    @property
    def canonical(self) -> str:
        text = f"{self.canonical_repository}:{self.tag}"
        return f"{text}@{self.digest}" if self.digest else text

    def match_forms(self) -> tuple[str, ...]:
        """Strings an ignore pattern is matched against."""
        forms = [
            self.familiar,
            f"{self.familiar}:{self.tag}",
            self.canonical_repository,
            f"{self.canonical_repository}:{self.tag}",
        ]
        if self.registry == DOCKER_HUB:
            forms += [self.repository, f"{self.repository}:{self.tag}"]
        return tuple(dict.fromkeys(forms))


def normalize_registry(host: str) -> str:
    value = host.strip().lower()
    return DOCKER_HUB if value in _HUB_ALIASES else value


def _is_registry_component(component: str) -> bool:
    return "." in component or ":" in component or component == "localhost" or (
        component != component.lower()
    )


def parse_reference(value: str) -> ImageRef:
    text = value.strip() if isinstance(value, str) else ""
    if not text or len(text) > 512 or any(ch.isspace() for ch in text):
        raise InvalidReference("empty or malformed image reference")
    if _IMAGE_ID.fullmatch(text) and (text.startswith("sha256:") or len(text) == 64):
        raise InvalidReference("image ID, not a reference")
    digest: str | None = None
    if "@" in text:
        text, digest = text.split("@", 1)
        if not _DIGEST.fullmatch(digest):
            raise InvalidReference("unsupported digest")
    registry = DOCKER_HUB
    remainder = text
    first, sep, rest = text.partition("/")
    if sep and _is_registry_component(first):
        if not _HOST.fullmatch(first):
            raise InvalidReference("invalid registry host")
        registry = normalize_registry(first)
        remainder = rest
    tag = "latest"
    last_slash = remainder.rfind("/")
    colon = remainder.rfind(":")
    if colon > last_slash:
        remainder, tag = remainder[:colon], remainder[colon + 1 :]
        if not _TAG.fullmatch(tag):
            raise InvalidReference("invalid tag")
    components = remainder.split("/")
    if not remainder or not all(_COMPONENT.fullmatch(part) for part in components):
        raise InvalidReference("invalid repository name")
    if registry == DOCKER_HUB and len(components) == 1:
        remainder = f"library/{remainder}"
    if len(remainder) > 255:
        raise InvalidReference("repository name too long")
    return ImageRef(registry=registry, repository=remainder, tag=tag, digest=digest)


def local_digests(ref: ImageRef, repo_digests: Iterable[object]) -> list[str]:
    """Digests from RepoDigests (``repo@sha256:..``) recorded for ref's repository."""
    found: list[str] = []
    for item in repo_digests:
        if not isinstance(item, str) or "@" not in item:
            continue
        name, digest = item.rsplit("@", 1)
        if not _DIGEST.fullmatch(digest):
            continue
        try:
            parsed = parse_reference(name)
        except InvalidReference:
            continue
        if (
            parsed.registry == ref.registry
            and parsed.repository == ref.repository
            and digest not in found
        ):
            found.append(digest)
    return found


def tag_matches(ref: ImageRef, repo_tags: Iterable[object]) -> bool:
    for item in repo_tags:
        if not isinstance(item, str):
            continue
        try:
            parsed = parse_reference(item)
        except InvalidReference:
            continue
        if (parsed.registry, parsed.repository, parsed.tag) == (
            ref.registry,
            ref.repository,
            ref.tag,
        ):
            return True
    return False


def is_ignored(ref: ImageRef, patterns: Iterable[str]) -> bool:
    forms = ref.match_forms()
    return any(fnmatch.fnmatchcase(form, pattern) for pattern in patterns for form in forms)


# --- WWW-Authenticate ----------------------------------------------------------

_CHALLENGE_PARAM = re.compile(r'\s*([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]*))\s*,?')


def parse_challenge(header: str | None) -> tuple[str, dict[str, str]] | None:
    """``Bearer realm="..",service="..",scope=".."`` -> ("bearer", {...})."""
    if not header:
        return None
    scheme, _, params_text = header.strip().partition(" ")
    if not scheme:
        return None
    params: dict[str, str] = {}
    position = 0
    while position < len(params_text):
        match = _CHALLENGE_PARAM.match(params_text, position)
        if match is None or match.end() == position:
            break
        key = match.group(1).lower()
        quoted = match.group(2)
        value = re.sub(r"\\(.)", r"\1", quoted) if quoted is not None else match.group(3)
        params.setdefault(key, value or "")
        position = match.end()
    return scheme.lower(), params


# --- rate limits ---------------------------------------------------------------


def _quota(value: str | None) -> tuple[int | None, int | None]:
    if not value:
        return None, None
    first = value.split(",")[0]
    number, _, rest = first.partition(";")
    try:
        amount = int(number.strip())
    except ValueError:
        return None, None
    window: int | None = None
    match = re.search(r"w=(\d+)", rest)
    if match:
        window = int(match.group(1))
    return amount, window


def parse_rate_limit(headers: Mapping[str, str]) -> dict[str, object] | None:
    lowered = {key.lower(): value for key, value in headers.items()}
    limit, window = _quota(lowered.get("ratelimit-limit"))
    remaining, remaining_window = _quota(lowered.get("ratelimit-remaining"))
    if limit is None and remaining is None:
        return None
    source = lowered.get("docker-ratelimit-source")
    return {
        "limit": limit,
        "remaining": remaining,
        "window_seconds": window or remaining_window,
        "source": source[:64] if source else None,
    }
