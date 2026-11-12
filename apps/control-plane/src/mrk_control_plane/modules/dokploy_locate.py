"""Where a DevAssist service runs in Dokploy, and how to change it without breaking it.

Dokploy is the source of truth, not the panel's notes in ``install.json``:

* A service's Compose is found by the service it defines (``mrk-<id>:``), because a
  stack may be removed and created again (new id) or pasted into Dokploy by hand.
* An image line may point at a shared variable (``${{project.MRK_VERSION}}``). Then the
  variable changes, never the line, so one version keeps driving every service.
* A Compose file the admin edited (bind mounts, limits) is kept; the panel replaces only
  a file it wrote itself (its sha256 is kept in ``install.json``).
* A deploy is finished only when a *new* deployment of that Compose is done, not when
  the Compose still shows the status of the previous one.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from typing import Any

from .dokploy_client import DokployError

LOGGER = logging.getLogger(__name__)
REFERENCE_RE = re.compile(r"\$\{\{\s*(project|environment)\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
# A Compose still showing the old status this long after a deploy request is treated
# as "started" (Dokploy versions without deployment.allByCompose).
START_GRACE_SECONDS = 20.0


class LocateError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


def _list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def defines_service(compose_file: str, service_name: str) -> bool:
    pattern = rf"(?m)^[ \t]+{re.escape(service_name)}:[ \t]*(#.*)?$"
    return re.search(pattern, compose_file) is not None


def composes(projects: Any) -> list[dict[str, Any]]:
    """Every Compose in project.all: {compose_id, name, app_name, project_id, project_name,
    environment_id, environment_name}."""
    found: list[dict[str, Any]] = []
    for project in _list(projects):
        project_id = project.get("projectId")
        if not isinstance(project_id, str):
            continue
        holders = _list(project.get("environments")) or [project]
        for holder in holders:
            environment_id = holder.get("environmentId") if holder is not project else None
            for item in _list(holder.get("compose")):
                compose_id = item.get("composeId")
                if isinstance(compose_id, str) and compose_id:
                    found.append({
                        "compose_id": compose_id,
                        "name": item.get("name"),
                        "app_name": item.get("appName"),
                        "project_id": project_id,
                        "project_name": project.get("name"),
                        "environment_id": environment_id if isinstance(environment_id, str)
                        else None,
                        "environment_name": holder.get("name") if holder is not project
                        else None,
                    })
    return found


async def compose_detail(dokploy: Any, compose_id: str) -> dict[str, Any] | None:
    """compose.one, or None when Dokploy says the Compose does not exist."""
    try:
        one = await dokploy.call("compose.one", params={"composeId": compose_id})
    except DokployError as exc:
        if is_missing(exc):
            return None
        raise
    return one if isinstance(one, dict) else None


def is_missing(exc: DokployError) -> bool:
    """Dokploy says the thing does not exist (404, or a 400 "... not found")."""
    if exc.code == "dokploy_not_found":
        return True
    return exc.code == "dokploy_rejected" and "not found" in exc.message.lower()


async def compose_runs(dokploy: Any, compose_id: str, service_name: str) -> bool | None:
    """Whether that Compose exists and defines ``service_name``; None if Dokploy is unsure."""
    try:
        one = await compose_detail(dokploy, compose_id)
    except Exception:  # noqa: BLE001 - Dokploy trouble: unknown, not missing
        return None
    if one is None:
        return False
    text = one.get("composeFile")
    del one  # the detail carries the env; keep only the file
    return defines_service(text, service_name) if isinstance(text, str) else None


async def compose_of_container(dokploy: Any, agent: Any, service_name: str) -> str | None:
    """The Compose id of the running ``service_name`` container, from its Docker labels.

    Dokploy runs a Compose as project ``<appName>`` (or stack namespace ``<appName>``), so
    the label maps back to the Compose with no extra Dokploy calls.
    """
    if agent is None:
        return None
    try:
        payload, index = await asyncio.gather(
            agent.call("/v1/docker/containers"), dokploy.app_index())
    except Exception:  # noqa: BLE001 - the other ways below remain
        LOGGER.info("container lookup of a Dokploy Compose skipped", exc_info=True)
        return None
    items = payload.get("items", []) if isinstance(payload, dict) else []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        labels = item.get("labels_subset") or {}
        swarm = str(labels.get("com.docker.swarm.service.name") or "")
        if (labels.get("com.docker.compose.service") != service_name
                and not swarm.endswith(f"_{service_name}")):
            continue
        for app_name in (labels.get("com.docker.stack.namespace"),
                         labels.get("com.docker.compose.project"),
                         swarm.removesuffix(f"_{service_name}") or None):
            ref = index.get(app_name) if isinstance(app_name, str) else None
            if ref and ref.get("type") == "compose" and isinstance(ref.get("id"), str):
                return str(ref["id"])
    return None


async def find_compose(
    dokploy: Any, service_name: str, *, known: list[str | None] | tuple[str | None, ...] = (),
    agent: Any = None,
) -> dict[str, Any] | None:
    """The Compose that runs ``service_name``, or None when none is found.

    In order: the running container's labels; a known id that still defines the service;
    a Compose named after the service. Other people's stacks are never read.
    Returns a :func:`composes` row (only ``compose_id`` when the tree is unavailable).
    """
    try:
        rows = composes(await dokploy._projects_raw())  # noqa: SLF001 - cached loader
    except Exception:  # noqa: BLE001 - without the tree only the known ids can be checked
        rows = []
    by_id = {row["compose_id"]: row for row in rows}
    labelled = await compose_of_container(dokploy, agent, service_name)
    if labelled is not None:
        return by_id.get(labelled) or {"compose_id": labelled}
    for compose_id in dict.fromkeys(item for item in known if item):
        if await compose_runs(dokploy, compose_id, service_name) is not False:
            return by_id.get(compose_id) or {"compose_id": compose_id}
    short = service_name.removeprefix("mrk-")
    skipped = set(item for item in known if item)
    for row in rows:
        names = {str(row.get("name") or "").lower(), str(row.get("app_name") or "").lower()}
        if row["compose_id"] in skipped or not any(
                name == short or service_name in name or name.startswith(f"{short}-")
                or name.startswith(f"devassist-{short}") for name in names):
            continue
        if await compose_runs(dokploy, row["compose_id"], service_name):
            LOGGER.info("found the Dokploy Compose of a service",
                        extra={"service": service_name, "stale": bool(skipped)})
            return row
    return None


# ----------------------------------------------------------------- shared variables
def env_value(env_text: str, name: str) -> str | None:
    pattern = re.compile(rf"^\s*(?:export\s+)?{re.escape(name)}\s*=(.*)$")
    value = None
    for line in env_text.splitlines():
        match = pattern.match(line)
        if match:
            value = match.group(1).strip()
    return value


def set_env_value(env_text: str, name: str, value: str) -> str:
    """Replace ``name=...`` (every occurrence) or append it; nothing else changes."""
    lines = env_text.splitlines()
    found = False
    pattern = re.compile(rf"^\s*(?:export\s+)?{re.escape(name)}\s*=")
    for index, line in enumerate(lines):
        if pattern.match(line):
            lines[index] = f"{name}={value}"
            found = True
    if not found:
        lines.append(f"{name}={value}")
    return "\n".join(lines) + "\n"


def solve_reference(template: str, wanted: str) -> tuple[str, str, str] | None:
    """For ``template`` with one ``${{scope.VAR}}``: (scope, VAR, value) giving ``wanted``.

    ``ghcr.io/o/mrk-s3:${{project.MRK_VERSION}}`` + ``ghcr.io/o/mrk-s3:0.3.0`` ->
    ``("project", "MRK_VERSION", "0.3.0")``. None when the rest of the line differs.
    """
    matches = list(REFERENCE_RE.finditer(template))
    if len(matches) != 1:
        return None
    match = matches[0]
    prefix, suffix = template[:match.start()], template[match.end():]
    if not (wanted.startswith(prefix) and wanted.endswith(suffix)):
        return None
    value = wanted[len(prefix):len(wanted) - len(suffix)] if suffix else wanted[len(prefix):]
    if not value or REFERENCE_RE.search(value):
        return None
    return match.group(1), match.group(2), value


async def set_shared_variable(dokploy: Any, scope: str, name: str, value: str,
                              compose: dict[str, Any]) -> None:
    """Set ``name=value`` in the Compose's project (or environment) variables."""
    environment = compose.get("environment") if isinstance(compose.get("environment"), dict) \
        else {}
    project = environment.get("project") if isinstance(environment.get("project"), dict) else {}
    project_id = compose.get("projectId") or project.get("projectId")
    if scope == "project":
        if not isinstance(project_id, str):
            raise LocateError("project_unknown", 409,
                              "The Dokploy project of this service is not known")
        one = await dokploy.call("project.one", params={"projectId": project_id})
        if not isinstance(one, dict):
            raise LocateError("project_unknown", 409, "The Dokploy project was not found")
        env_text = one.get("env") if isinstance(one.get("env"), str) else ""
        body = {"projectId": project_id, "name": one.get("name") or "DevAssist",
                "description": one.get("description") or "",
                "env": set_env_value(env_text, name, value)}
        del one
        await dokploy.call("project.update", body=body, mutation=True, parse=False)
        return
    environment_id = compose.get("environmentId") or environment.get("environmentId")
    if not isinstance(environment_id, str):
        raise LocateError("environment_unknown", 409,
                          "The Dokploy environment of this service is not known")
    one = await dokploy.call("environment.one", params={"environmentId": environment_id})
    if not isinstance(one, dict):
        raise LocateError("environment_unknown", 409, "The Dokploy environment was not found")
    env_text = one.get("env") if isinstance(one.get("env"), str) else ""
    body = {"environmentId": environment_id, "name": one.get("name") or "production",
            "description": one.get("description") or "",
            "env": set_env_value(env_text, name, value)}
    del one
    await dokploy.call("environment.update", body=body, mutation=True, parse=False)


async def apply_image(dokploy: Any, compose: dict[str, Any], variable: str,
                      image: str) -> tuple[str | None, str | None]:
    """Make the Compose run ``image`` through ``variable`` in its env.

    Returns (new env text or None when unchanged, shared variable changed or None). A line
    that points at a shared variable is left alone and the variable is changed instead.
    """
    env_text = compose.get("env") if isinstance(compose.get("env"), str) else ""
    current = env_value(env_text, variable)
    if current is not None and REFERENCE_RE.search(current):
        solved = solve_reference(current, image)
        if solved is None:
            raise LocateError(
                "image_reference", 409,
                f"{variable} is built from Dokploy variables in a way the panel cannot "
                "update; change it in Dokploy",
            )
        scope, name, value = solved
        await set_shared_variable(dokploy, scope, name, value, compose)
        return None, f"{scope}.{name}"
    if current == image:
        return None, None
    return set_env_value(env_text, variable, image), None


# ----------------------------------------------------------------- deployments
async def _deployments(dokploy: Any, compose_id: str) -> list[dict[str, Any]] | None:
    try:
        payload = await dokploy.call("deployment.allByCompose", params={"composeId": compose_id})
    except DokployError as exc:
        if exc.procedure_missing:
            return None  # older Dokploy: fall back to the Compose status
        raise
    return _list(payload)


async def deploy_mark(dokploy: Any, compose_id: str) -> dict[str, Any]:
    """What the Compose looks like before a deploy: its deployment ids (when Dokploy lists
    them) and its status, so the wait can tell the new deployment from the last one."""
    rows = await _deployments(dokploy, compose_id)
    one = await compose_detail(dokploy, compose_id)
    status = one.get("composeStatus") if one else None
    del one
    ids = None if rows is None else {
        str(row.get("deploymentId")) for row in rows if row.get("deploymentId")}
    return {"ids": ids, "status": status}


async def wait_deployment(
    dokploy: Any, compose_id: str, mark: dict[str, Any], *, timeout: float, poll: float,
) -> None:
    """Wait for the deployment started after ``mark``; raise on its failure."""
    deadline = time.monotonic() + timeout
    started = time.monotonic()
    before: set[str] | None = mark.get("ids")
    previous = mark.get("status")
    seen_running = False
    while True:
        await asyncio.sleep(poll)
        if before is not None:
            rows = await _deployments(dokploy, compose_id) or []
            fresh = [row for row in rows if str(row.get("deploymentId")) not in before]
            if fresh:
                newest = max(fresh, key=lambda row: str(row.get("createdAt") or ""))
                status = newest.get("status")
                if status == "done":
                    return
                if status == "error":
                    detail = newest.get("errorMessage")
                    raise LocateError(
                        "deploy_failed", 502,
                        "Dokploy could not deploy the service"
                        + (f": {str(detail)[:200]}" if detail else "; see its deployment log"),
                    )
        else:
            one = await compose_detail(dokploy, compose_id)
            status = one.get("composeStatus") if one else None
            del one
            # A status equal to the one before the deploy may still be the old deployment's.
            settled = (seen_running or status != previous
                       or time.monotonic() - started > START_GRACE_SECONDS)
            if status == "running":
                seen_running = True
            elif status == "error" and settled:
                raise LocateError("deploy_failed", 502,
                                  "Dokploy could not deploy the service; see its deployment log")
            elif status == "done" and settled:
                return
        if time.monotonic() > deadline:
            raise LocateError("deploy_timeout", 504,
                              "Dokploy is still deploying the service; check it in Dokploy")


async def deployments(dokploy: Any, compose_id: str) -> list[dict[str, Any]] | None:
    """Deployments of a Compose (deployment.allByCompose); None on Dokploy without it."""
    return await _deployments(dokploy, compose_id)
