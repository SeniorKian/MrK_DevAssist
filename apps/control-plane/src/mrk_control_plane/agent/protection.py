"""Detect containers that belong to Dokploy (or other protected stacks).

Protected containers are reported with ``protected: true``. Gate 16 never acts on
any container, but later gates must refuse to touch protected ones.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

# Covers dokploy, dokploy-postgres, dokploy-traefik and swarm task names (dokploy.1.x).
DEFAULT_NAME_REGEX = r"^/?dokploy([-._]|$)"
DEFAULT_LABEL_PREFIXES = ("com.dokploy", "dokploy")
DEFAULT_COMPOSE_PROJECTS = ("dokploy",)


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True, slots=True)
class ProtectionRules:
    name_pattern: re.Pattern[str]
    label_prefixes: tuple[str, ...] = DEFAULT_LABEL_PREFIXES
    compose_projects: tuple[str, ...] = DEFAULT_COMPOSE_PROJECTS

    @classmethod
    def default(cls) -> ProtectionRules:
        return cls(re.compile(DEFAULT_NAME_REGEX, re.IGNORECASE))

    @classmethod
    def from_env(cls) -> ProtectionRules:
        regex = os.getenv("MRK_AGENT_PROTECTED_NAME_REGEX", "").strip() or DEFAULT_NAME_REGEX
        try:
            pattern = re.compile(regex, re.IGNORECASE)
        except re.error as exc:
            raise ValueError("MRK_AGENT_PROTECTED_NAME_REGEX is not a valid regex") from exc
        prefixes = os.getenv("MRK_AGENT_PROTECTED_LABEL_PREFIXES")
        projects = os.getenv("MRK_AGENT_PROTECTED_COMPOSE_PROJECTS")
        return cls(
            pattern,
            _csv(prefixes) if prefixes is not None else DEFAULT_LABEL_PREFIXES,
            _csv(projects) if projects is not None else DEFAULT_COMPOSE_PROJECTS,
        )

    def is_protected(self, names: Sequence[str], labels: Mapping[str, str]) -> bool:
        if any(self.name_pattern.search(name) for name in names):
            return True
        project = str(labels.get("com.docker.compose.project", ""))
        if project and project.lower() in {item.lower() for item in self.compose_projects}:
            return True
        swarm_service = str(labels.get("com.docker.swarm.service.name", ""))
        if swarm_service and self.name_pattern.search(swarm_service):
            return True
        lowered = tuple(prefix.lower() for prefix in self.label_prefixes)
        return bool(lowered) and any(key.lower().startswith(lowered) for key in labels)
