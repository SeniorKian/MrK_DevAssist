"""Feature modules. Add a module by importing it here and listing it in MODULES."""

from __future__ import annotations

from collections.abc import Callable

from ..module_context import ModuleContext

MODULES: list[tuple[str, Callable[[ModuleContext], None]]] = []


def _load() -> None:
    # Imported lazily so a broken optional module cannot break core startup imports.
    import importlib
    import logging

    for name in (
        "notifications",
        "host_agent",
        "monitoring",
        "dokploy",
        "s3",
        "server_backups",
        "updates",
        "firewall",
        "vuln",
        "dbadmin",
        "dns",  # before services: the services card and domain sync read it
        "services",  # after dokploy/s3/host_agent/firewall: it reads their services
        "git_service",  # Git (Gitea), docs/46
        "registry_service",  # Docker image registry (Zot), docs/46
        "install",  # add-service wizard (docs/44): reads agent/firewall/dns
        "install_auto",  # docs/44 phase 6: installs through the Dokploy/Coolify API
        "releases",  # panel/service versions and updates: reads install + services
        "tenancy",  # «my space» (docs/43): after dns/s3, it reuses their services
        "home",  # last: it reads the services the modules above registered
    ):
        try:
            module = importlib.import_module(f"{__name__}.{name}")
        except ModuleNotFoundError as exc:
            if exc.name == f"{__name__}.{name}":
                continue
            raise
        except Exception:
            logging.getLogger(__name__).exception("module %s failed to import", name)
            continue
        MODULES.append((name, module.register))


def register_all(ctx: ModuleContext) -> list[str]:
    if not MODULES:
        _load()
    loaded: list[str] = []
    for name, register in MODULES:
        register(ctx)
        loaded.append(name)
    return loaded
