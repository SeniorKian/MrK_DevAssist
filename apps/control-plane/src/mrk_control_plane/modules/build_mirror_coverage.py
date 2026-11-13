"""Estimate from a build log whether a deployment used the mirrors (docs/48).

Pure function, no I/O. It is an estimate: npm prints no host names on success,
so "no direct host seen" is not proof; tools that are known to ignore the
variables are reported as reasons instead.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

DIRECT_HOSTS = {
    "registry.npmjs.org": "npm",
    "registry.yarnpkg.com": "npm",
    "files.pythonhosted.org": "pypi",
    "pypi.org": "pypi",
    "pypi.python.org": "pypi",
}
_HOST_RE = re.compile(
    r"https?://(registry\.npmjs\.org|registry\.yarnpkg\.com|files\.pythonhosted\.org"
    r"|pypi\.org|pypi\.python\.org)\b"
)
# Tools that do not follow the injected variables (docs/48, limits).
GAP_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("yarn_v1_lock", re.compile(r"yarn install v1\.|yarn install --frozen-lockfile")),
    ("poetry", re.compile(r"\bpoetry (install|sync)\b")),
    ("uv_lock", re.compile(r"\buv sync\b")),
    ("pip_index_in_requirements", re.compile(r"--index-url\s+https?://(?!\S*\+simple/)")),
)
_INDEX_RE = re.compile(r"Looking in indexes:\s*(\S+)")
NPM_TOOLS = re.compile(r"\b(npm (ci|install|i)|pnpm (install|i)|yarn( install)?|bun install)\b")
PIP_TOOLS = re.compile(r"\b(pip3? install|uv (pip|sync)|poetry install|pipenv install)\b")
MAX_LINES = 5000


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def analyze(lines: list[str], npm_url: str | None, pypi_url: str | None) -> dict[str, Any]:
    """{result: full|partial|none|unknown, direct: {npm, pypi}, mirror_seen, gaps, tools}."""
    mirror_hosts = {host for host in (_host(npm_url), _host(pypi_url)) if host}
    direct = {"npm": 0, "pypi": 0}
    gaps: list[str] = []
    tools: set[str] = set()
    mirror_seen = False
    for line in lines[-MAX_LINES:]:
        for host in _HOST_RE.findall(line):
            direct[DIRECT_HOSTS[host]] += 1
        index = _INDEX_RE.search(line)
        if index and _host(index.group(1)) in mirror_hosts:
            mirror_seen = True
        if any(host in line for host in mirror_hosts):
            mirror_seen = True
        if NPM_TOOLS.search(line):
            tools.add("npm")
        if PIP_TOOLS.search(line):
            tools.add("pypi")
        for code, pattern in GAP_PATTERNS:
            if code not in gaps and pattern.search(line):
                gaps.append(code)
    if not tools and not any(direct.values()):
        result = "unknown"  # no package install visible in the log
    elif any(direct.values()):
        result = "partial" if mirror_seen else "none"
    elif gaps:
        result = "partial"
    else:
        result = "full"
    return {"result": result, "direct": direct, "mirror_seen": mirror_seen,
            "gaps": gaps, "tools": sorted(tools)}
