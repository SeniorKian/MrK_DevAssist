"""Gate 19 S8: version ordering tables, OSV range evaluation and CVSS scoring."""

from __future__ import annotations

import pytest
from mrk_control_plane.modules.vuln_osv import cvss2_score, cvss3_score, record_severity
from mrk_control_plane.modules.vuln_versions import (
    InvalidVersion,
    apk_compare,
    dpkg_compare,
    evaluate,
    pep440_compare,
    rpm_compare,
    semver_compare,
)


def assert_ordered(compare, versions: list[str]) -> None:
    for index, low in enumerate(versions):
        for high in versions[index + 1 :]:
            assert compare(low, high) == -1, (low, high)
            assert compare(high, low) == 1, (high, low)
        assert compare(low, low) == 0


# ----- dpkg -----------------------------------------------------------------------------


def test_dpkg_ordering_table() -> None:
    assert_ordered(
        dpkg_compare,
        ["1.0~~", "1.0~~a", "1.0~", "1.0", "1.0-1", "1.0-1+b1", "1.0a", "1.0.1", "1.2", "1.10"],
    )
    assert_ordered(
        dpkg_compare,
        ["3.0.11-1~deb12u1", "3.0.11-1", "3.0.13-1~deb12u1", "3.0.13-1", "1:0.1"],
    )


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1:0.1", "2.0", 1),
        ("0:2.0", "2.0", 0),
        ("1.01", "1.1", 0),
        ("2.30-1", "2.4-1", 1),
        ("1.0~rc1-1", "1.0-1", -1),
        ("2.36-9+deb12u4", "2.36-9+deb12u10", -1),
        ("7.88.1-10+deb12u5", "7.88.1-10+deb12u12", -1),
        ("1.2.3-1ubuntu0.22.04.1", "1.2.3-1ubuntu0.22.04.2", -1),
        ("1.0+dfsg-1", "1.0-1", 1),
        ("10", "9", 1),
    ],
)
def test_dpkg_pairs(a: str, b: str, expected: int) -> None:
    assert dpkg_compare(a, b) == expected
    assert dpkg_compare(b, a) == -expected


# ----- apk ------------------------------------------------------------------------------


def test_apk_ordering_table() -> None:
    assert_ordered(
        apk_compare,
        [
            "1.2_alpha", "1.2_beta", "1.2_pre", "1.2_rc", "1.2_rc1", "1.2_rc2", "1.2",
            "1.2-r1", "1.2-r9", "1.2-r10", "1.2_p1", "1.2a", "1.2b", "1.2.1", "1.10",
        ],
    )


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("3.1.4-r1", "3.1.4-r0", 1),
        ("3.0.12-r1", "3.1.4-r1", -1),
        ("1.01", "1.1", -1),  # leading zero after a dot compares like a fraction
        ("1.36.1-r29", "1.36.1-r30", -1),
        ("2.4.58-r0", "2.4.6-r0", 1),
        ("1.0", "1.0", 0),
        ("1.0_git20240101", "1.0", 1),
        ("1.0_cvs", "1.0_p1", -1),
    ],
)
def test_apk_pairs(a: str, b: str, expected: int) -> None:
    assert apk_compare(a, b) == expected
    assert apk_compare(b, a) == -expected


# ----- rpm ------------------------------------------------------------------------------


def test_rpm_ordering_table() -> None:
    assert_ordered(
        rpm_compare,
        ["1.0~rc1", "1.0", "1.0^git1", "1.0a", "1.0.1", "1.5", "1.10", "1:0.1"],
    )


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0-1.el9", "1.0-2.el9", -1),
        ("3.0.7-27.el9", "3.0.7-25.el9_3", 1),
        ("1.a", "1.1", -1),
        ("1.0", "1.0", 0),
        ("1.01", "1.1", 0),
        ("2:1.0-1", "1:9.9-9", 1),
    ],
)
def test_rpm_pairs(a: str, b: str, expected: int) -> None:
    assert rpm_compare(a, b) == expected
    assert rpm_compare(b, a) == -expected


# ----- PEP 440 ---------------------------------------------------------------------------


def test_pep440_ordering_table() -> None:
    assert_ordered(
        pep440_compare,
        [
            "1.0.dev0", "1.0a1.dev1", "1.0a1", "1.0a1.post1", "1.0b1", "1.0rc1", "1.0",
            "1.0+abc.5", "1.0+abc.7", "1.0.post1.dev0", "1.0.post1", "1.0.1", "1.1.dev0",
            "1.1", "2.0", "1!0.1",
        ],
    )


@pytest.mark.parametrize(
    ("a", "b"),
    [("1.0", "1.0.0"), ("1.0rc1", "1.0c1"), ("1.0-1", "1.0.post1"), ("V1.0", "1.0"),
     ("1.0.ALPHA1", "1.0a1"), ("1.0-dev", "1.0.dev0")],
)
def test_pep440_equivalent_spellings(a: str, b: str) -> None:
    assert pep440_compare(a, b) == 0


def test_pep440_rejects_garbage() -> None:
    with pytest.raises(InvalidVersion):
        pep440_compare("not a version", "1.0")


# ----- SemVer ------------------------------------------------------------------------------


def test_semver_ordering_table() -> None:
    assert_ordered(
        semver_compare,
        [
            "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
            "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.9.0", "1.10.0", "2.0.0",
        ],
    )
    assert semver_compare("1.0.0+build.5", "1.0.0") == 0
    assert semver_compare("v1.2.3", "1.2.3") == 0
    assert semver_compare("1.2", "1.2.0") == 0  # loose OSV form


# ----- OSV range evaluation ------------------------------------------------------------------


def _entry(*events, kind="ECOSYSTEM", versions=None):
    entry = {"ranges": [{"type": kind, "events": list(events)}]}
    if versions is not None:
        entry["versions"] = versions
    return entry


def test_evaluate_introduced_fixed() -> None:
    entry = _entry({"introduced": "0"}, {"fixed": "4.17.21"})
    assert evaluate(entry, "4.17.20", "npm") == (True, "4.17.21")
    assert evaluate(entry, "4.17.21", "npm") == (False, None)
    assert evaluate(entry, "5.0.0", "npm") == (False, None)


def test_evaluate_last_affected_and_limit() -> None:
    entry = _entry({"introduced": "1.0"}, {"last_affected": "1.5"})
    assert evaluate(entry, "1.5", "PyPI") == (True, None)
    assert evaluate(entry, "1.5.1", "PyPI")[0] is False
    assert evaluate(entry, "0.9", "PyPI")[0] is False
    limited = _entry({"introduced": "0"}, {"limit": "2.0"})
    assert evaluate(limited, "1.9", "PyPI")[0] is True
    assert evaluate(limited, "2.0", "PyPI")[0] is False


def test_evaluate_multiple_segments_unsorted_events() -> None:
    entry = _entry({"fixed": "2.5.0"}, {"introduced": "2.0.0"}, {"introduced": "0"},
                   {"fixed": "1.0.0"}, kind="SEMVER")
    assert evaluate(entry, "0.5.0", "Go") == (True, "1.0.0")
    assert evaluate(entry, "1.5.0", "Go") == (False, None)
    assert evaluate(entry, "2.1.0", "Go") == (True, "2.5.0")
    assert evaluate(entry, "2.5.0", "Go") == (False, None)


def test_evaluate_debian_tilde_and_explicit_versions() -> None:
    entry = _entry({"introduced": "0"}, {"fixed": "3.0.13-1~deb12u1"},
                   versions=["3.0.9-1"])
    assert evaluate(entry, "3.0.11-1~deb12u2", "Debian:12") == (True, "3.0.13-1~deb12u1")
    assert evaluate(entry, "3.0.13-1~deb12u1", "Debian:12")[0] is False
    assert evaluate(entry, "3.0.13-1", "Debian:12")[0] is False
    only_versions = {"versions": ["1.2.3", "1.2.4"]}
    assert evaluate(only_versions, "1.2.4", "npm") == (True, None)
    assert evaluate(only_versions, "1.2.5", "npm")[0] is False


def test_evaluate_alpine_and_git_ranges_ignored() -> None:
    entry = _entry({"introduced": "0"}, {"fixed": "3.1.4-r1"})
    assert evaluate(entry, "3.1.4-r0", "Alpine:v3.19") == (True, "3.1.4-r1")
    assert evaluate(entry, "3.1.4-r5", "Alpine:v3.19")[0] is False
    git = _entry({"introduced": "0"}, {"fixed": "abc123"}, kind="GIT")
    assert evaluate(git, "1.0", "npm") == (False, None)


def test_evaluate_invalid_versions_do_not_raise() -> None:
    entry = _entry({"introduced": "0"}, {"fixed": "1.0.0"})
    assert evaluate(entry, "not-a-version", "npm") == (False, None)


# ----- severity --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_scores(vector: str, score: float) -> None:
    assert cvss3_score(vector) == score


def test_cvss2_and_severity_fallbacks() -> None:
    assert cvss2_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") == 7.5
    assert record_severity(
        {"severity": [{"type": "CVSS_V3",
                       "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    ) == ("critical", 9.8)
    assert record_severity({"database_specific": {"severity": "MODERATE"}}) == ("medium", None)
    assert record_severity({"severity": [{"type": "Ubuntu", "score": "high"}]}) == ("high", None)
    assert record_severity(
        {"affected": [{"database_specific": {"urgency": "unimportant"}}]}
    ) == ("low", None)
    assert record_severity({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]}) == (
        "unknown", None
    )
