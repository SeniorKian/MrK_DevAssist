"""Version ordering per ecosystem and OSV range evaluation (Gate 19 S8).

Clean-room implementations of the published ordering rules:

* Debian/Ubuntu: dpkg ``[epoch:]upstream[-revision]`` with the ``~`` rule
  (deb-version(7)).
* Alpine/Wolfi/Chainguard: apk-tools version ordering (digits, letter,
  ``_suffix[N]``, ``-rN``; pre-release suffixes sort before the bare version).
* RPM (AlmaLinux/Rocky): ``rpmvercmp`` with ``~`` and ``^``.
* PyPI: PEP 440.
* npm and OSV ``SEMVER`` ranges: SemVer 2.0.0 (with npm's loose ``v`` prefix).

``compare(ecosystem, a, b)`` returns -1/0/1. ``evaluate(entry, version, ecosystem)``
applies one OSV ``affected[]`` entry (explicit ``versions`` + ``ranges`` with
``introduced``/``fixed``/``last_affected``/``limit`` events).
"""

from __future__ import annotations

import functools
import re
from collections.abc import Callable
from typing import Any

_DIGITS = frozenset("0123456789")


def _sign(value: int) -> int:
    return (value > 0) - (value < 0)


# ----- dpkg --------------------------------------------------------------------------


def _dpkg_order(char: str | None) -> int:
    if char is None:
        return 0
    if char == "~":
        return -1
    if char in _DIGITS:
        return 0
    if char.isascii() and char.isalpha():
        return ord(char)
    return ord(char) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and a[i] not in _DIGITS) or (j < len(b) and b[j] not in _DIGITS):
            ac = _dpkg_order(a[i] if i < len(a) else None)
            bc = _dpkg_order(b[j] if j < len(b) else None)
            if ac != bc:
                return _sign(ac - bc)
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i] in _DIGITS and j < len(b) and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i] in _DIGITS:
            return 1
        if j < len(b) and b[j] in _DIGITS:
            return -1
        if first_diff:
            return _sign(first_diff)
    return 0


def _dpkg_split(version: str) -> tuple[int, str, str]:
    text = version.strip()
    epoch = 0
    if ":" in text:
        head, _, rest = text.partition(":")
        if head.isdigit():
            epoch, text = int(head), rest
    upstream, sep, revision = text.rpartition("-")
    if not sep:
        upstream, revision = text, ""
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return _sign(ea - eb)
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# ----- apk ---------------------------------------------------------------------------

_T_DIGIT, _T_LETTER, _T_SUFFIX, _T_SUFFIX_NO, _T_REVISION, _T_END = 1, 2, 3, 4, 5, 6
_APK_SUFFIXES = {
    "alpha": -4, "beta": -3, "pre": -2, "rc": -1,
    "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5,
}


def _apk_tokens(version: str) -> list[tuple[int, Any]]:
    text = version.strip()
    text = re.sub(r"~[0-9a-f]+", "", text)  # optional ~commit-hash component
    tokens: list[tuple[int, Any]] = []
    i = 0
    match = re.match(r"[0-9]+", text)
    if not match:
        return [(_T_END, None)] if not text else [(_T_LETTER, text)]
    tokens.append((_T_DIGIT, (match.group(), True)))
    i = match.end()
    while i < len(text):
        rest = text[i:]
        if rest[0] == "." and len(rest) > 1 and rest[1] in _DIGITS:
            number = re.match(r"\.([0-9]+)", rest)
            assert number is not None
            tokens.append((_T_DIGIT, (number.group(1), False)))
            i += number.end()
        elif rest[0].isascii() and rest[0].islower() and tokens[-1][0] == _T_DIGIT:
            tokens.append((_T_LETTER, rest[0]))
            i += 1
        elif rest[0] == "_":
            suffix = re.match(r"_([a-z]+)([0-9]*)", rest)
            if not suffix or suffix.group(1) not in _APK_SUFFIXES:
                tokens.append((_T_LETTER, rest))  # invalid tail: compare as text
                break
            tokens.append((_T_SUFFIX, _APK_SUFFIXES[suffix.group(1)]))
            if suffix.group(2):
                tokens.append((_T_SUFFIX_NO, int(suffix.group(2))))
            i += suffix.end()
        elif rest.startswith("-r") and rest[2:3].isdigit():
            revision = re.match(r"-r([0-9]+)", rest)
            assert revision is not None
            tokens.append((_T_REVISION, int(revision.group(1))))
            i += revision.end()
        else:
            tokens.append((_T_LETTER, rest))
            break
    tokens.append((_T_END, None))
    return tokens


def _apk_digit_cmp(a: tuple[str, bool], b: tuple[str, bool]) -> int:
    (da, first_a), (db, first_b) = a, b
    if not (first_a or first_b) and (da.startswith("0") or db.startswith("0")):
        # Leading zero after a dot: compared like a decimal fraction.
        return _sign((da > db) - (da < db))
    return _sign(int(da) - int(db))


def apk_compare(a: str, b: str) -> int:
    ta, tb = _apk_tokens(a), _apk_tokens(b)
    index = 0
    while index < len(ta) and index < len(tb):
        (kind_a, value_a), (kind_b, value_b) = ta[index], tb[index]
        if kind_a != kind_b or kind_a == _T_END:
            break
        if kind_a == _T_DIGIT:
            result = _apk_digit_cmp(value_a, value_b)
        else:
            result = (value_a > value_b) - (value_a < value_b)
        if result:
            return _sign(result)
        index += 1
    kind_a, value_a = ta[min(index, len(ta) - 1)]
    kind_b, value_b = tb[min(index, len(tb) - 1)]
    if kind_a == kind_b:
        return 0
    if kind_a == _T_SUFFIX and value_a < 0:
        return -1
    if kind_b == _T_SUFFIX and value_b < 0:
        return 1
    return -1 if kind_a > kind_b else 1


# ----- rpm ---------------------------------------------------------------------------


def _alnum(char: str) -> bool:
    return char.isascii() and char.isalnum()


def rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        ca = a[i] if i < len(a) else ""
        cb = b[j] if j < len(b) else ""
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i += 1
            j += 1
            continue
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i += 1
            j += 1
            continue
        if not ca or not cb:
            break
        numeric = ca in _DIGITS
        test: Callable[[str], bool] = (
            (lambda c: c in _DIGITS) if numeric else (lambda c: c.isascii() and c.isalpha())
        )
        si = i
        while i < len(a) and test(a[i]):
            i += 1
        sj = j
        while j < len(b) and test(b[j]):
            j += 1
        seg_a, seg_b = a[si:i], b[sj:j]
        if not seg_b:
            return 1 if numeric else -1
        if numeric:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    rest_a, rest_b = i < len(a), j < len(b)
    if not rest_a and not rest_b:
        return 0
    return 1 if rest_a else -1


def _rpm_split(version: str) -> tuple[int, str, str]:
    text = version.strip()
    epoch = 0
    if ":" in text:
        head, _, rest = text.partition(":")
        if head.isdigit():
            epoch, text = int(head), rest
    ver, sep, release = text.rpartition("-")
    if not sep:
        ver, release = text, ""
    return epoch, ver, release


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    if ea != eb:
        return _sign(ea - eb)
    result = rpmvercmp(va, vb)
    if result or not ra or not rb:
        return result
    return rpmvercmp(ra, rb)


# ----- PEP 440 ----------------------------------------------------------------------

_PEP440 = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}


class InvalidVersion(ValueError):
    pass


@functools.lru_cache(maxsize=65536)
def pep440_key(version: str) -> tuple[Any, ...]:
    match = _PEP440.match(version)
    if not match:
        raise InvalidVersion(version)
    epoch = int(match.group("epoch") or 0)
    release = [int(part) for part in match.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre_l = match.group("pre_l")
    pre = None if pre_l is None else (_PRE_RANK[pre_l.lower()], int(match.group("pre_n") or 0))
    post: int | None = None
    if match.group("post"):
        post = int(match.group("post_n1") or match.group("post_n2") or 0)
    dev = None if match.group("dev") is None else int(match.group("dev_n") or 0)
    if pre is None and post is None and dev is not None:
        pre_key: tuple[Any, ...] = (0,)
    elif pre is None:
        pre_key = (2,)
    else:
        pre_key = (1, *pre)
    post_key = (0,) if post is None else (1, post)
    dev_key = (2,) if dev is None else (1, dev)
    local = match.group("local")
    if local is None:
        local_key: tuple[Any, ...] = (0,)
    else:
        parts = re.split(r"[-_.]", local.lower())
        local_key = (
            1,
            tuple((1, int(part), "") if part.isdigit() else (0, 0, part) for part in parts),
        )
    return (epoch, tuple(release), pre_key, post_key, dev_key, local_key)


def pep440_compare(a: str, b: str) -> int:
    ka, kb = pep440_key(a), pep440_key(b)
    return (ka > kb) - (ka < kb)


# ----- SemVer -------------------------------------------------------------------------

_SEMVER = re.compile(
    r"^\s*[v=]?\s*(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?\s*$"
)


@functools.lru_cache(maxsize=65536)
def semver_key(version: str) -> tuple[Any, ...]:
    match = _SEMVER.match(version)
    if not match:
        # OSV SEMVER ranges may omit components ("1.2"): pad them.
        loose = re.match(r"^\s*[v=]?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:-([0-9A-Za-z.-]+))?"
                         r"(?:\+[0-9A-Za-z.-]+)?\s*$", version)
        if not loose:
            raise InvalidVersion(version)
        major, minor, patch, pre = loose.groups()
        core = (int(major), int(minor or 0), int(patch or 0))
    else:
        core = (int(match["major"]), int(match["minor"]), int(match["patch"]))
        pre = match["pre"]
    if pre is None:
        return (core, (1,))
    identifiers = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split(".")
    )
    return (core, (0, identifiers))


def semver_compare(a: str, b: str) -> int:
    ka, kb = semver_key(a), semver_key(b)
    return (ka > kb) - (ka < kb)


# ----- dispatch -------------------------------------------------------------------------

Comparator = Callable[[str, str], int]


def comparator_for(ecosystem: str) -> Comparator | None:
    base = ecosystem.split(":", 1)[0]
    if base in {"Debian", "Ubuntu"}:
        return dpkg_compare
    if base in {"Alpine", "Wolfi", "Chainguard"}:
        return apk_compare
    if base in {"AlmaLinux", "Rocky Linux", "Red Hat"}:
        return rpm_compare
    if base == "PyPI":
        return pep440_compare
    if base == "npm":
        return semver_compare
    return None


def compare(ecosystem: str, a: str, b: str) -> int:
    comparator = comparator_for(ecosystem)
    if comparator is None:
        raise InvalidVersion(f"no version ordering for {ecosystem}")
    return comparator(a, b)


def _is_zero(value: str) -> bool:
    return value.strip() == "0"


def _range_affected(
    events: list[dict[str, Any]], version: str, cmp: Comparator
) -> tuple[bool, str | None]:
    """OSV evaluation: sort events, walk them. Returns (affected, fixed_version)."""
    parsed: list[tuple[str, str]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            value = event.get(kind)
            if isinstance(value, str) and value:
                parsed.append((kind, value))
    if not parsed:
        return False, None

    def order(a: tuple[str, str], b: tuple[str, str]) -> int:
        if _is_zero(a[1]) and a[0] == "introduced":
            return -1 if not (_is_zero(b[1]) and b[0] == "introduced") else 0
        if _is_zero(b[1]) and b[0] == "introduced":
            return 1
        try:
            return cmp(a[1], b[1])
        except InvalidVersion:
            return 0

    parsed.sort(key=functools.cmp_to_key(order))
    affected = False
    fixed: str | None = None
    for kind, value in parsed:
        if kind == "introduced":
            if _is_zero(value) or cmp(version, value) >= 0:
                affected = True
        elif kind == "fixed":
            if cmp(version, value) >= 0:
                affected = False
            elif affected and fixed is None:
                fixed = value
        elif kind == "last_affected":
            if cmp(version, value) > 0:
                affected = False
        elif kind == "limit" and cmp(version, value) >= 0:
            affected = False
    return affected, fixed if affected else None


def evaluate(entry: dict[str, Any], version: str, ecosystem: str) -> tuple[bool, str | None]:
    """Is ``version`` affected by one OSV ``affected[]`` entry? -> (affected, fixed)."""
    versions = entry.get("versions")
    explicit = isinstance(versions, list) and version in versions
    fixed: str | None = None
    hit = explicit
    eco_cmp = comparator_for(ecosystem)
    for item in entry.get("ranges") or []:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "SEMVER":
            cmp: Comparator | None = semver_compare
        elif kind == "ECOSYSTEM":
            cmp = eco_cmp
        else:
            continue  # GIT ranges need commit data we do not have
        if cmp is None:
            continue
        try:
            affected, range_fixed = _range_affected(item.get("events") or [], version, cmp)
        except InvalidVersion:
            continue
        if affected:
            hit = True
            if range_fixed and (fixed is None or _safe_lt(cmp, range_fixed, fixed)):
                fixed = range_fixed
    if hit and fixed is None and explicit:
        fixed = _first_fixed(entry, eco_cmp)
    return hit, fixed


def _safe_lt(cmp: Comparator, a: str, b: str) -> bool:
    try:
        return cmp(a, b) < 0
    except InvalidVersion:
        return False


def _first_fixed(entry: dict[str, Any], cmp: Comparator | None) -> str | None:
    for item in entry.get("ranges") or []:
        if isinstance(item, dict) and item.get("type") in {"ECOSYSTEM", "SEMVER"}:
            for event in item.get("events") or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    return event["fixed"]
    return None
