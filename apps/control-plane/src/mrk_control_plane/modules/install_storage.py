"""Where each service stack keeps its data: a Docker volume or a folder on the server.

The wizard asks for every storage slot of a service. Two kinds exist:

* own slots (S3 objects, registry images, Gitea repositories...): the admin picks a
  Docker volume (the default) or an absolute host folder.
* shared slots (the registry config, npm/PyPI data, the DNS and firewall sockets): the
  panel writes or reads the same folder, so the service must mount whatever the panel
  mounts. These are never asked; they are taken from the panel's own container (Host
  Agent), or from its compose file in Dokploy, and shown read-only.

Before an install the chosen folders are checked through the Host Agent (exists, owner,
room left), because Docker would create a missing folder owned by root and a service
running as uid 10001 could not write to it.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Any

PATH_RE = re.compile(r"^/[A-Za-z0-9._@%+=:,/-]{0,398}$")


class StorageError(Exception):
    def __init__(self, code: str, status_code: int, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.extra = extra


@dataclass(frozen=True, slots=True)
class Slot:
    key: str
    # Container path inside the service, as written in the template ("<source>:<target>").
    target: str
    # The named volume the template uses for it.
    volume: str
    label_fa: str
    label_en: str
    # uid:gid the folder must belong to when it is a host folder (None = no rule).
    owner: str | None = None
    # The panel's own path for the same data (shared slots only).
    panel_path: str | None = None
    suffix: str = ""  # ":ro" in the template


SLOTS: dict[str, tuple[Slot, ...]] = {
    "agent": (
        Slot("state", "/data", "mrk-agent-state", "وضعیت دستیار سرور", "Server agent state"),
    ),
    "firewall": (
        Slot("state", "/var/lib/mrk-firewall", "mrk-firewall-state", "وضعیت دیوار آتش",
             "Firewall state"),
        Slot("run", "/run/mrk-firewall", "mrk-firewall-run", "سوکت دیوار آتش (مشترک با پنل)",
             "Firewall socket (shared with the panel)", panel_path="/run/mrk-firewall"),
    ),
    "dns": (
        Slot("data", "/var/lib/mrk-dns", "mrk-dns-data", "داده‌های DNS", "DNS data",
             owner="10001:10001"),
        Slot("run", "/run/mrk-dns", "mrk-dns-run", "سوکت DNS (مشترک با پنل)",
             "DNS socket (shared with the panel)", panel_path="/run/mrk-dns"),
    ),
    "s3": (
        Slot("data", "/data", "mrk-s3-data", "فایل‌های S3", "S3 files", owner="10001:10001"),
    ),
    "npm": (
        Slot("data", "/data/npm", "mrk-npm-data", "بسته‌های npm (مشترک با پنل)",
             "npm packages (shared with the panel)", owner="10001:10001",
             panel_path="/data/npm"),
    ),
    "pypi": (
        Slot("data", "/data/pypi", "mrk-pypi-data", "بسته‌های PyPI (مشترک با پنل)",
             "PyPI packages (shared with the panel)", owner="10001:10001",
             panel_path="/data/pypi"),
    ),
    "git": (
        Slot("data", "/var/lib/gitea", "mrk-git-data", "مخزن‌های Git", "Git repositories",
             owner="1000:1000"),
        Slot("config", "/etc/gitea", "mrk-git-config", "تنظیمات Gitea", "Gitea settings",
             owner="1000:1000"),
    ),
    "registry": (
        Slot("config", "/etc/zot", "mrk-registry-config",
             "تنظیمات و کاربرهای مخزن ایمیج (مشترک با پنل)",
             "Image registry settings and users (shared with the panel)",
             owner="10001:10001", panel_path="/data/registry", suffix=":ro"),
        Slot("data", "/var/lib/registry", "mrk-registry-data", "ایمیج‌ها", "Images"),
    ),
}


def slots_for(service_id: str) -> tuple[Slot, ...]:
    return SLOTS.get(service_id, ())


def suggested_path(service_id: str, slot: Slot) -> str:
    return f"/opt/devassist/{service_id}/{slot.key}"


def valid_path(path: str) -> bool:
    if not PATH_RE.fullmatch(path) or path == "/":
        return False
    return posixpath.normpath(path) == path and ".." not in path.split("/")


# ------------------------------------------------------------------ the panel's own mounts
def parse_compose_mounts(compose_file: str, service: str = "mrk-panel") -> list[dict[str, Any]]:
    """``- source:target[:mode]`` lines of one service in a compose file (no YAML library).

    ``${VAR:-default}`` sources use the default; anything else unresolvable is skipped.
    """
    lines = compose_file.splitlines()
    mounts: list[dict[str, Any]] = []
    in_service = in_volumes = False
    service_indent = volumes_indent = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if re.fullmatch(rf"{re.escape(service)}:\s*(#.*)?", stripped):
            in_service, service_indent, in_volumes = True, indent, False
            continue
        if in_service and indent <= service_indent:
            in_service = in_volumes = False
        if not in_service:
            continue
        if stripped.startswith("volumes:"):
            in_volumes, volumes_indent = True, indent
            continue
        if in_volumes and indent <= volumes_indent:
            in_volumes = False
        if not in_volumes or not stripped.startswith("- "):
            continue
        spec = stripped[2:].strip().strip('"').strip("'")
        spec = re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]*)\}", r"\1", spec)
        if "${" in spec:
            continue
        parts = spec.split(":")
        if len(parts) < 2:
            continue
        source, target = parts[0], parts[1]
        mounts.append({
            "type": "bind" if source.startswith("/") else "volume",
            "source": source if source.startswith("/") else "",
            "name": None if source.startswith("/") else source,
            "destination": target,
        })
    return mounts


def shared_source(mounts: list[dict[str, Any]], panel_path: str) -> dict[str, Any]:
    """What the service must mount so it sees the panel's ``panel_path``.

    {kind: path|volume|missing, value, via}. A sub-folder of a bind mount is that host
    folder plus the rest of the path; a sub-folder of a named volume cannot be shared.
    """
    best: dict[str, Any] | None = None
    for mount in mounts:
        destination = str(mount.get("destination") or "").rstrip("/") or "/"
        if panel_path == destination or panel_path.startswith(destination + "/"):
            if best is None or len(destination) > len(str(best.get("destination"))):
                best = mount
    if best is None:
        return {"kind": "missing", "value": None}
    destination = str(best.get("destination") or "").rstrip("/") or "/"
    rest = panel_path[len(destination):].lstrip("/")
    if best.get("type") == "bind" and best.get("source"):
        value = posixpath.join(str(best["source"]), rest) if rest else str(best["source"])
        return {"kind": "path", "value": value}
    if rest:
        return {"kind": "missing", "value": None, "inside_volume": best.get("name")}
    return {"kind": "volume", "value": best.get("name")}


# ------------------------------------------------------------------ compose rewrite
def _line_re(slot: Slot) -> re.Pattern[str]:
    return re.compile(rf"^(\s+- )(\S+?):{re.escape(slot.target)}({re.escape(slot.suffix)})?$",
                      re.MULTILINE)


SHARED_WITH = "panel"
SHARED_SERVICE_NAME = "mrk-panel"


def shared_note(slot: Slot) -> str:
    """The comment written above a shared mount in the generated compose file."""
    return (f"# SHARED: must be the same folder/volume the panel ({SHARED_SERVICE_NAME}) "
            f"mounts at {slot.panel_path}; change both together.")


def _mark_shared(text: str, slot: Slot) -> str:
    note = shared_note(slot)
    if note in text:
        return text
    return _line_re(slot).sub(
        lambda match, comment=note: f"{match.group(1)[:-2]}{comment}\n{match.group(0)}", text)


def apply(compose: str, service_id: str, choices: dict[str, dict[str, str]]) -> str:
    """Point each slot's mount at the chosen volume or folder; drop unused volume entries.

    Shared mounts get a comment naming the panel's matching mount, so whoever edits the
    file later knows the two must stay the same.
    """
    text = compose
    for slot in slots_for(service_id):
        if slot.panel_path is not None:
            text = _mark_shared(text, slot)
    changed = False
    for slot in slots_for(service_id):
        choice = choices.get(slot.key)
        if not choice:
            continue
        source = choice.get("value") or ""
        if choice.get("kind") == "volume" and source in {"", slot.volume}:
            continue
        changed = True
        text = _line_re(slot).sub(
            lambda match, src=source, target=slot.target:
            f"{match.group(1)}{src}:{target}{match.group(3) or ''}", text)
        if choice.get("kind") == "volume":
            # Another existing named volume (the panel's): declare it as external.
            text = _declare_external(text, slot.volume, source)
    return _drop_unused_volumes(text) if changed else text


def _volume_block(text: str) -> tuple[int, int] | None:
    match = re.search(r"(?m)^volumes:\s*$", text)
    if match is None:
        return None
    end = re.search(r"(?m)^\S", text[match.end():])
    return match.start(), match.end() + (end.start() if end else len(text) - match.end())


def _entries(block: str) -> list[tuple[str, str]]:
    """(name, full text) of each top-level volume entry."""
    entries: list[tuple[str, str]] = []
    current_name, current = None, []
    for line in block.splitlines(keepends=True)[1:]:
        entry = re.match(r"^  ([A-Za-z0-9_.-]+):", line)
        if entry:
            if current_name is not None:
                entries.append((current_name, "".join(current)))
            current_name, current = entry.group(1), [line]
        elif current_name is not None:
            current.append(line)
    if current_name is not None:
        entries.append((current_name, "".join(current)))
    return entries


def _declare_external(text: str, template_volume: str, name: str) -> str:
    span = _volume_block(text)
    entry = f"  {name}:\n    name: {name}\n    external: true\n"
    if span is None:
        return text.rstrip("\n") + "\n\nvolumes:\n" + entry
    start, end = span
    block = text[start:end]
    if re.search(rf"(?m)^  {re.escape(name)}:", block):
        return text
    return text[:start] + block.rstrip("\n") + "\n" + entry + text[end:]


def _drop_unused_volumes(text: str) -> str:
    span = _volume_block(text)
    if span is None:
        return text
    start, end = span
    block = text[start:end]
    body = text[:start] + text[end:]
    kept = [chunk for name, chunk in _entries(block)
            if re.search(rf"(?m)^\s+- (?:\$\{{[A-Za-z0-9_]+:-)?{re.escape(name)}\}}?:", body)]
    if not kept:
        return (text[:start].rstrip("\n") + "\n\n" + text[end:].lstrip("\n")).rstrip("\n") + "\n"
    blank = "\n" if text[end:].strip() else ""
    return text[:start] + "volumes:\n" + "".join(kept).rstrip("\n") + "\n" + blank + text[end:]


# ------------------------------------------------------------------ checks
def owner_command(path: str, owner: str | None) -> str:
    chown = f" && sudo chown -R {owner} {path}" if owner else ""
    return f"sudo mkdir -p {path}{chown}"


def evaluate(slot: Slot, path: str, fact: dict[str, Any] | None) -> dict[str, Any]:
    """{status: ok|warn|error|unknown, code, fix} for one chosen host folder."""
    if fact is None:
        return {"status": "unknown", "code": "not_checked",
                "fix": owner_command(path, slot.owner)}
    if not fact.get("valid", True):
        return {"status": "error", "code": "path_refused", "fix": None}
    if not fact.get("exists"):
        # Docker would create it owned by root: fine only for a root service.
        status = "error" if slot.owner else "warn"
        return {"status": status, "code": "path_missing", "fix": owner_command(path, slot.owner)}
    if not fact.get("is_dir"):
        return {"status": "error", "code": "path_not_folder", "fix": None}
    if slot.owner:
        uid, gid = (int(part) for part in slot.owner.split(":"))
        if fact.get("uid") != uid:
            return {"status": "error", "code": "path_wrong_owner",
                    "fix": f"sudo chown -R {slot.owner} {path}",
                    "owner": f"{fact.get('uid')}:{fact.get('gid')}"}
    free = fact.get("free_bytes")
    if isinstance(free, int) and free < 1024 ** 3:
        return {"status": "warn", "code": "low_space", "fix": None, "free_bytes": free}
    return {"status": "ok", "code": None, "fix": None}
