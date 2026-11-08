"""Agent route for the vulnerability scanner: ``GET /v1/vuln/containers/{ref}/package-files``.

Signed GET like every other agent route. Response::

    {"container_id", "image_id", "image", "state", "running",
     "files": [{"path", "entries": [{"name", "size", "data_b64"}], "note"}],
     "missing": [path...], "errors": [{"path", "error"}], "truncated": bool}

``note`` is ``"symlink"`` (path is a link; not followed), ``"present"`` (presence
only) or null. Nothing inside the container is executed and the request has no
caller-chosen paths: the agent walks ``PACKAGE_DB_PATHS`` itself.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import package_files
from .docker_client import (
    DockerClient,
    DockerNotAllowed,
    DockerRequestFailed,
    DockerUnavailable,
    validate_container_ref,
)

LOGGER = logging.getLogger("mrk_control_plane.agent")
_MAX_SECONDS = 120.0


def add_package_routes(
    app: FastAPI,
    docker: DockerClient,
    docker_ok: Callable[[], bool],
    error: Callable[..., JSONResponse],
) -> None:
    @app.get("/v1/vuln/containers/{ref}/package-files")
    async def package_db_files(ref: str):
        if not docker_ok():
            return error("docker_unavailable", 503)
        try:
            validate_container_ref(ref)
        except DockerNotAllowed:
            return error("invalid_container", 422)
        try:
            inspected = await docker.inspect_container(ref)
        except DockerRequestFailed as exc:
            if exc.status_code == 404:
                return error("not_found", 404)
            return error("docker_error", 502, status=exc.status_code, message=exc.message)
        except DockerUnavailable:
            return error("docker_unavailable", 503)
        container_id = str(inspected.get("Id", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            return error("not_found", 404)
        state = inspected.get("State") if isinstance(inspected.get("State"), dict) else {}
        container_config = inspected.get("Config")
        image = container_config.get("Image") if isinstance(container_config, dict) else None
        files: list[dict[str, Any]] = []
        missing: list[str] = []
        errors: list[dict[str, str]] = []
        total = 0
        truncated_any = False
        try:
            async with asyncio.timeout(_MAX_SECONDS):
                for path in package_files.PACKAGE_DB_PATHS:
                    remaining = package_files.TOTAL_CAP - total
                    if remaining <= 0:
                        truncated_any = True
                        errors.append({"path": path, "error": "total_limit"})
                        continue
                    limit = min(package_files.tar_cap(path), remaining + 64 * 1024)
                    try:
                        result = await docker.archive(container_id, path, limit)
                    except DockerRequestFailed as exc:
                        errors.append({"path": path, "error": f"docker_{exc.status_code}"})
                        continue
                    if result is None:
                        missing.append(path)
                        continue
                    raw, truncated = result
                    if path in package_files.PRESENCE_ONLY:
                        files.append({"path": path, "entries": [], "note": "present"})
                        continue
                    if truncated:
                        truncated_any = True
                        errors.append({"path": path, "error": "too_large"})
                        continue
                    try:
                        entries, note = package_files.decode_archive(raw, path)
                    except package_files.TarTooLarge:
                        truncated_any = True
                        errors.append({"path": path, "error": "too_large"})
                        continue
                    if note == "invalid_archive":
                        errors.append({"path": path, "error": "invalid_archive"})
                        continue
                    total += sum(len(entry.data) for entry in entries)
                    files.append(
                        {"path": path, "entries": [e.public() for e in entries], "note": note}
                    )
        except TimeoutError:
            return error("timeout", 504)
        except DockerUnavailable:
            return error("docker_unavailable", 503)
        LOGGER.info(
            "package files read",
            extra={"container": str(inspected.get("Name", "")).lstrip("/"), "bytes": total,
                   "files": len(files)},
        )
        return {
            "container_id": container_id,
            "image_id": str(inspected.get("Image", ""))[:80],
            "image": str(image or "")[:256],
            "state": str(state.get("Status", ""))[:32],
            "running": state.get("Running") is True,
            "files": files,
            "missing": missing,
            "errors": errors,
            "truncated": truncated_any,
        }
