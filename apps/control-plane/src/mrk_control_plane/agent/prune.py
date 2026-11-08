"""Prune planning: an explicit, reviewable list of items, never Docker's bulk prune APIs.

Docker's ``/containers/prune`` etc. would also delete stopped Dokploy containers, so
the agent computes a plan, hands its sha256 token to the caller, and on execute
re-plans, compares the token and deletes the planned items one by one.

Never in a plan:
- protected (Dokploy) containers and networks, and images that carry protected
  labels or a protected repository path component;
- containers managed by swarm (``com.docker.swarm.task.id``): swarm keeps its own
  task history and Dokploy apps run as swarm services;
- images referenced by any container, running or stopped;
- the default networks (bridge/host/none), swarm system networks (ingress,
  docker_gwbridge), swarm-scoped networks and networks any container is attached to;
- volumes (Gate 17 never removes volumes).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .docker_client import container_labels, container_names
from .protection import ProtectionRules

TARGETS = ("containers", "images", "build_cache", "networks")
IMAGES_MODES = ("dangling", "unused")
_REMOVABLE_STATES = {"exited", "created", "dead"}
_SYSTEM_NETWORKS = {"bridge", "host", "none", "ingress", "docker_gwbridge"}
_NONE_TAGS = {"<none>:<none>", "<none>@<none>"}


class PlanRequestError(ValueError):
    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.field = field


def parse_plan_request(payload: object) -> tuple[list[str], str]:
    if not isinstance(payload, dict):
        raise PlanRequestError("body")
    targets = payload.get("targets")
    if (
        not isinstance(targets, list)
        or not targets
        or not all(isinstance(item, str) and item in TARGETS for item in targets)
        or len(set(targets)) != len(targets)
    ):
        raise PlanRequestError("targets")
    mode = payload.get("images_mode", "dangling")
    if mode not in IMAGES_MODES:
        raise PlanRequestError("images_mode")
    return sorted(targets, key=TARGETS.index), mode


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _image_tags(image: dict[str, Any]) -> list[str]:
    tags = image.get("RepoTags")
    return [tag for tag in tags or [] if isinstance(tag, str) and tag not in _NONE_TAGS]


def _image_protected(image: dict[str, Any], tags: list[str], rules: ProtectionRules) -> bool:
    labels = image.get("Labels")
    if isinstance(labels, dict) and labels:
        prefixes = tuple(prefix.lower() for prefix in rules.label_prefixes)
        if prefixes and any(str(key).lower().startswith(prefixes) for key in labels):
            return True
    for tag in tags:
        repository = tag.rsplit(":", 1)[0] if "/" not in tag.rsplit(":", 1)[-1] else tag
        if any(rules.name_pattern.search(part) for part in repository.split("/")):
            return True
    return False


def build_plan(
    *,
    targets: list[str],
    images_mode: str,
    containers: list[dict[str, Any]],
    images: list[Any],
    networks: list[Any],
    df: dict[str, Any],
    rules: ProtectionRules,
) -> dict[str, Any]:
    used_images: set[str] = set()
    used_networks: set[str] = set()
    for container in containers:
        image_id = container.get("ImageID")
        if isinstance(image_id, str) and image_id:
            used_images.add(image_id)
        settings = container.get("NetworkSettings")
        attached = settings.get("Networks") if isinstance(settings, dict) else None
        if isinstance(attached, dict):
            for name, network in attached.items():
                used_networks.add(str(name))
                if isinstance(network, dict) and network.get("NetworkID"):
                    used_networks.add(str(network["NetworkID"]))

    container_sizes = {
        str(item.get("Id")): _int(item.get("SizeRw"))
        for item in df.get("Containers") or []
        if isinstance(item, dict)
    }

    plan_containers: list[dict[str, Any]] = []
    if "containers" in targets:
        for container in containers:
            names = container_names(container)
            labels = container_labels(container)
            container_id = str(container.get("Id", ""))
            if (
                len(container_id) != 64
                or str(container.get("State", "")) not in _REMOVABLE_STATES
                or rules.is_protected(names, labels)
                or "com.docker.swarm.task.id" in labels
            ):
                continue
            plan_containers.append(
                {
                    "id": container_id,
                    "name": names[0].lstrip("/") if names else "",
                    "size_bytes": container_sizes.get(container_id, 0),
                }
            )

    plan_images: list[dict[str, Any]] = []
    if "images" in targets:
        for image in images:
            if not isinstance(image, dict):
                continue
            image_id = str(image.get("Id", ""))
            if not image_id.startswith("sha256:") or len(image_id) != 71:
                continue
            tags = _image_tags(image)
            if (
                image_id in used_images
                or (images_mode == "dangling" and tags)
                or _image_protected(image, tags, rules)
            ):
                continue
            plan_images.append(
                {"id": image_id, "tags": sorted(tags), "size_bytes": _int(image.get("Size"))}
            )

    plan_networks: list[dict[str, Any]] = []
    if "networks" in targets:
        for network in networks:
            if not isinstance(network, dict):
                continue
            network_id = str(network.get("Id", ""))
            name = str(network.get("Name", ""))
            labels = network.get("Labels") if isinstance(network.get("Labels"), dict) else {}
            if (
                len(network_id) != 64
                or name in _SYSTEM_NETWORKS
                or network.get("Ingress") is True
                or str(network.get("Scope", "local")) == "swarm"
                or network_id in used_networks
                or name in used_networks
                or network.get("Containers")
                or rules.is_protected([name], labels)
            ):
                continue
            plan_networks.append({"id": network_id, "name": name})

    build_cache_bytes = 0
    if "build_cache" in targets:
        build_cache_bytes = sum(
            _int(item.get("Size"))
            for item in df.get("BuildCache") or []
            if isinstance(item, dict) and not item.get("InUse")
        )

    plan_containers.sort(key=lambda item: item["id"])
    plan_images.sort(key=lambda item: item["id"])
    plan_networks.sort(key=lambda item: item["id"])
    plan = {
        "containers": plan_containers,
        "images": plan_images,
        "networks": plan_networks,
        "build_cache_bytes": build_cache_bytes,
        "reclaimable_bytes": sum(item["size_bytes"] for item in plan_containers)
        + sum(item["size_bytes"] for item in plan_images)
        + build_cache_bytes,
    }
    plan["token"] = plan_token(targets, images_mode, plan)
    return plan


def plan_token(targets: list[str], images_mode: str, plan: dict[str, Any]) -> str:
    """sha256 over the canonical JSON of what would be deleted.

    Byte counts are left out on purpose: the build cache size moves with every build
    elsewhere on the host and would invalidate a plan whose items did not change.
    """
    canonical = {
        "targets": targets,
        "images_mode": images_mode,
        "containers": [[item["id"], item["name"]] for item in plan["containers"]],
        "images": [[item["id"], item["tags"]] for item in plan["images"]],
        "networks": [[item["id"], item["name"]] for item in plan["networks"]],
        "build_cache": "build_cache" in targets,
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()
