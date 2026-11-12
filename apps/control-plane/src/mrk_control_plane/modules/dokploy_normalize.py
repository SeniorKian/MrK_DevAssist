"""Turn Dokploy API payloads into the MRK contract shapes (docs/29 §3 "Dokploy").

Everything here is a whitelist: Dokploy's ``*.one`` responses include
environment variables, database passwords and git provider data, so only the
fields named below ever leave this module.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..logging_config import redact_text

# Contract service type -> (Dokploy router, id field, status field)
SERVICE_TYPES: dict[str, tuple[str, str, str]] = {
    "application": ("application", "applicationId", "applicationStatus"),
    "compose": ("compose", "composeId", "composeStatus"),
    "postgres": ("postgres", "postgresId", "applicationStatus"),
    "mysql": ("mysql", "mysqlId", "applicationStatus"),
    "mariadb": ("mariadb", "mariadbId", "applicationStatus"),
    "mongo": ("mongo", "mongoId", "applicationStatus"),
    "redis": ("redis", "redisId", "applicationStatus"),
}
DATABASE_TYPES = frozenset({"postgres", "mysql", "mariadb", "mongo", "redis"})
DEPLOYABLE_TYPES = frozenset({"application", "compose"})
# Dokploy applicationStatus enum (packages/server/src/db/schema/shared.ts).
SERVICE_STATUSES = frozenset({"idle", "running", "done", "error"})
# Dokploy deploymentStatus enum (packages/server/src/db/schema/deployment.ts).
DEPLOYMENT_STATUSES = frozenset({"running", "done", "error", "cancelled"})
MAX_DEPLOYMENTS = 50


def _text(value: Any, limit: int = 255) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    return value[:limit]


def _status(value: Any, allowed: frozenset[str]) -> str:
    text = value.lower() if isinstance(value, str) else ""
    return text if text in allowed else "unknown"


def _sort_key(value: Any) -> float:
    if not isinstance(value, str) or not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def parse_time(value: Any) -> float | None:
    stamp = _sort_key(value)
    return stamp or None


def _list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def format_domain(domain: dict[str, Any]) -> str | None:
    host = domain.get("host")
    if not isinstance(host, str) or not host:
        return None
    path = domain.get("path")
    if isinstance(path, str) and path not in {"", "/"}:
        return f"{host}{path if path.startswith('/') else '/' + path}"[:512]
    return host[:512]


def domain_strings(domains: Any) -> list[str]:
    result: list[str] = []
    for domain in _list(domains):
        text = format_domain(domain)
        if text and text not in result:
            result.append(text)
    return result


def domain_details(domains: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for domain in _list(domains):
        host = domain.get("host")
        if not isinstance(host, str) or not host:
            continue
        port = domain.get("port")
        result.append(
            {
                "host": host[:255],
                "path": _text(domain.get("path")) or "/",
                "https": bool(domain.get("https")),
                "port": port if isinstance(port, int) else None,
            }
        )
    return result


def deployment(item: dict[str, Any]) -> dict[str, Any]:
    error = item.get("errorMessage")
    return {
        "id": _text(item.get("deploymentId"), 64),
        "status": _status(item.get("status"), DEPLOYMENT_STATUSES),
        "title": _text(item.get("title"), 500),
        "created_at": _text(item.get("createdAt"), 64),
        "finished_at": _text(item.get("finishedAt"), 64),
        "error_message": redact_text(error[:500]) if isinstance(error, str) and error else None,
    }


def deployments(items: Any, limit: int = MAX_DEPLOYMENTS) -> list[dict[str, Any]]:
    ordered = sorted(_list(items), key=lambda d: _sort_key(d.get("createdAt")), reverse=True)
    return [deployment(item) for item in ordered[:limit]]


def last_deployment_summary(item: dict[str, Any] | None) -> dict[str, Any] | None:
    if not item:
        return None
    return {
        "status": _status(item.get("status"), DEPLOYMENT_STATUSES),
        "created_at": _text(item.get("createdAt"), 64),
        "title": _text(item.get("title"), 500),
    }


def latest_by_service(items: Any) -> dict[tuple[str, str], dict[str, Any]]:
    """Map (type, id) -> newest deployment from deployment.allCentralized output."""
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for item in _list(items):
        for service_type, field in (("application", "applicationId"), ("compose", "composeId")):
            service_id = item.get(field)
            if not isinstance(service_id, str) or not service_id:
                continue
            key = (service_type, service_id)
            current = latest.get(key)
            if current is None or _sort_key(item.get("createdAt")) > _sort_key(
                current.get("createdAt")
            ):
                latest[key] = item
    return latest


def _environments(project: dict[str, Any]) -> list[dict[str, Any]]:
    """Dokploy >= 0.25 nests services in environments; older releases do not."""
    if "environments" in project:
        return _list(project.get("environments"))
    return [project]


def services_missing_names(project: dict[str, Any]) -> bool:
    for env in _environments(project):
        for router, id_field, _status_field in SERVICE_TYPES.values():
            key = router if router != "application" else "applications"
            for item in _list(env.get(key)):
                if isinstance(item.get(id_field), str) and not item.get("name"):
                    return True
    return False


def _service_index(project: dict[str, Any] | None) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    if not project:
        return index
    for env in _environments(project):
        for service_type, (router, id_field, _status_field) in SERVICE_TYPES.items():
            key = router if router != "application" else "applications"
            for item in _list(env.get(key)):
                service_id = item.get(id_field)
                if isinstance(service_id, str):
                    index[(service_type, service_id)] = item
    return index


def project_tree(
    projects: Any,
    *,
    details: dict[str, dict[str, Any]] | None = None,
    latest: dict[tuple[str, str], dict[str, Any]] | None = None,
    domains: dict[tuple[str, str], list[str]] | None = None,
) -> list[dict[str, Any]]:
    """Normalize project.all (+ optional project.one per project) to the contract tree."""
    details = details or {}
    latest = latest or {}
    domains = domains or {}
    result: list[dict[str, Any]] = []
    for project in _list(projects):
        project_id = project.get("projectId")
        if not isinstance(project_id, str):
            continue
        extra = _service_index(details.get(project_id))
        services: list[dict[str, Any]] = []
        default_environment: str | None = None
        for env in _environments(project):
            env_name = _text(env.get("name")) if env is not project else None
            env_id = env.get("environmentId") if env is not project else None
            env_id = env_id[:64] if isinstance(env_id, str) and env_id else None
            if env_id and (default_environment is None or env.get("isDefault")):
                default_environment = env_id  # the default one, else the first
            for service_type, (router, id_field, status_field) in SERVICE_TYPES.items():
                key = router if router != "application" else "applications"
                for item in _list(env.get(key)):
                    service_id = item.get(id_field)
                    if not isinstance(service_id, str) or not service_id:
                        continue
                    more = extra.get((service_type, service_id), {})
                    name = item.get("name") or more.get("name") or service_id
                    status = item.get(status_field) or more.get(status_field)
                    services.append(
                        {
                            "id": service_id,
                            "type": service_type,
                            "name": _text(name),
                            "environment": env_name,
                            "environment_id": env_id,
                            "status": _status(status, SERVICE_STATUSES),
                            "domains": list(domains.get((service_type, service_id), [])),
                            "last_deployment": last_deployment_summary(
                                latest.get((service_type, service_id))
                            ),
                        }
                    )
        result.append(
            {
                "id": project_id,
                "name": _text(project.get("name")) or project_id,
                "description": _text(project.get("description"), 1000),
                "default_environment_id": default_environment,
                "services": services,
            }
        )
    return result


def project_outline(project: dict[str, Any]) -> dict[str, Any]:
    """project.one without its secrets: ids, names, appNames and statuses only.

    Same shape as the input (environments -> service lists, or services on the project
    for pre-environment Dokploy), so :func:`project_tree` / :func:`app_name_index` accept it.
    """

    def services(holder: dict[str, Any]) -> dict[str, Any]:
        lists: dict[str, Any] = {}
        for router, id_field, status_field in SERVICE_TYPES.values():
            key = router if router != "application" else "applications"
            if key not in holder:
                continue
            lists[key] = [
                {
                    id_field: _text(item.get(id_field), 64),
                    "name": _text(item.get("name")),
                    "appName": _text(item.get("appName"), 128),
                    status_field: _text(item.get(status_field), 32),
                }
                for item in _list(holder.get(key))
                if isinstance(item.get(id_field), str)
            ]
        return lists

    outline: dict[str, Any] = {
        "projectId": _text(project.get("projectId"), 64),
        "name": _text(project.get("name")),
    }
    if "environments" in project:
        outline["environments"] = [
            {
                "environmentId": _text(env.get("environmentId"), 64),
                "name": _text(env.get("name")),
                "isDefault": bool(env.get("isDefault")),
                **services(env),
            }
            for env in _list(project.get("environments"))
        ]
    else:
        outline.update(services(project))
    return outline


def service_detail(service_type: str, service_id: str, payload: Any) -> dict[str, Any]:
    _router, _id_field, status_field = SERVICE_TYPES[service_type]
    data = payload if isinstance(payload, dict) else {}
    environment = data.get("environment") if isinstance(data.get("environment"), dict) else {}
    project = data.get("project") if isinstance(data.get("project"), dict) else None
    if project is None and isinstance(environment.get("project"), dict):
        project = environment["project"]
    project = project or {}
    server = data.get("server") if isinstance(data.get("server"), dict) else None
    detail: dict[str, Any] = {
        "id": service_id,
        "type": service_type,
        "name": _text(data.get("name")) or service_id,
        "app_name": _text(data.get("appName")),
        "description": _text(data.get("description"), 1000),
        "status": _status(data.get(status_field), SERVICE_STATUSES),
        "created_at": _text(data.get("createdAt"), 64),
        "project": {"id": _text(project.get("projectId"), 64), "name": _text(project.get("name"))},
        "environment": {
            "id": _text(environment.get("environmentId"), 64),
            "name": _text(environment.get("name")),
        },
        "server": _text(server.get("name")) if server else None,
        "domains": domain_strings(data.get("domains")),
        "domain_details": domain_details(data.get("domains")),
        "deployments": deployments(data.get("deployments"))
        if service_type in DEPLOYABLE_TYPES
        else [],
    }
    if service_type == "application":
        detail["source_type"] = _text(data.get("sourceType"), 32)
        detail["build_type"] = _text(data.get("buildType"), 32)
    elif service_type == "compose":
        detail["source_type"] = _text(data.get("sourceType"), 32)
        detail["compose_type"] = _text(data.get("composeType"), 32)
    else:
        detail["docker_image"] = _text(data.get("dockerImage"))
    return detail


def app_name_index(project: Any, index: dict[str, dict[str, Any]]) -> bool:
    """Add ``appName -> service ref`` for one project; True if every service had one.

    Dokploy names a service's swarm service / compose project after its
    ``appName``, which is how a host container is matched back to its service.
    """
    if not isinstance(project, dict) or not isinstance(project.get("projectId"), str):
        return True
    complete = True
    for env in _environments(project):
        environment_id = env.get("environmentId") if env is not project else None
        for service_type, (router, id_field, _status_field) in SERVICE_TYPES.items():
            key = router if router != "application" else "applications"
            for item in _list(env.get(key)):
                service_id = item.get(id_field)
                if not isinstance(service_id, str) or not service_id:
                    continue
                app_name = item.get("appName")
                if not isinstance(app_name, str) or not app_name:
                    complete = False
                    continue
                index[app_name[:128]] = {
                    "type": service_type,
                    "id": service_id[:64],
                    "name": _text(item.get("name")) or service_id[:64],
                    "project_id": project["projectId"][:64],
                    "environment_id": environment_id[:64]
                    if isinstance(environment_id, str)
                    else None,
                }
    return complete
