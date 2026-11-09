"""Internal admin API (loopback ``127.0.0.1:9001``, docs/31 §2).

Every request needs ``X-MRK-Admin-Token`` equal to ``/data/modules/s3/admin.token``.

* ``GET /admin/health``
* ``GET /admin/buckets/{b}/stats`` -> ``{objects, bytes}``
* ``POST /admin/buckets/{b}/ensure`` (reloads the snapshot first)
* ``DELETE /admin/buckets/{b}?force=0|1`` (409 when not empty and force=0; linked
  buckets only lose their index, never files)
* ``GET /admin/links`` -> folders mounted under the link roots
* ``POST /admin/reload``, ``POST /admin/gc``, ``POST /admin/buckets/{b}/rescan``
* ``GET /admin/buckets/{b}/lifecycle`` -> rules, versioning state, last run summary
* ``POST /admin/buckets/{b}/lifecycle/preview`` -> dry-run ("would delete N objects / B bytes")
* ``POST /admin/lifecycle/run`` -> run every bucket's lifecycle rules now
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, unquote

from . import lifecycle
from .linked import LinkedBucket

if TYPE_CHECKING:
    from .engine import Engine


def _mount_points() -> set[str]:
    points: set[str] = set()
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) > 4:
                    points.add(fields[4].replace("\\040", " "))
    except OSError:
        pass
    return points


def discover_links(roots: tuple[Path, ...]) -> list[dict[str, Any]]:
    mounts = _mount_points()
    items: list[dict[str, Any]] = []
    for root in roots:
        try:
            entries = sorted(os.scandir(root), key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in entries:
            if entry.name.startswith(".") or not entry.is_dir(follow_symlinks=False):
                continue
            path = Path(root) / entry.name
            item: dict[str, Any] = {
                "path": path.as_posix(),
                "writable": os.access(path, os.W_OK),
                "mount_point": path.as_posix() in mounts,
            }
            try:
                usage = shutil.disk_usage(path)
                item.update(size_bytes=usage.total, total_bytes=usage.total, free_bytes=usage.free)
            except OSError:
                pass
            items.append(item)
    return items


class AdminApi:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        headers = {
            name.decode("latin-1").lower(): value.decode("latin-1")
            for name, value in scope.get("headers", [])
        }
        token = headers.get("x-mrk-admin-token", "")
        if not token or not hmac.compare_digest(token.encode(), self.engine.admin_token.encode()):
            await self._json(send, 401, {"error": "unauthorized"})
            return
        try:
            status, payload = await self.route(
                scope["method"].upper(),
                scope.get("path", "/"),
                scope.get("query_string", b"").decode(),
            )
        except Exception:
            status, payload = 500, {"error": "internal_error"}
        await self._json(send, status, payload)

    async def _json(self, send: Any, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def route(self, method: str, path: str, query: str) -> tuple[int, dict[str, Any]]:
        engine = self.engine
        params = parse_qs(query)
        parts = [unquote(item) for item in path.strip("/").split("/")]
        if parts[:1] != ["admin"]:
            return 404, {"error": "not_found"}
        rest = parts[1:]
        if rest == ["health"] and method == "GET":
            snapshot = engine.snapshots.current
            return 200, {
                "status": "ok" if snapshot is not None else "unconfigured",
                "enabled": bool(snapshot and snapshot.enabled),
                "config_loaded": snapshot is not None,
                "config_error": engine.snapshots.last_error,
                "buckets": len(snapshot.buckets) if snapshot else 0,
                "generation": snapshot.generation if snapshot else 0,
                "last_gc": engine.last_gc.get("at"),
            }
        if rest == ["links"] and method == "GET":
            return 200, {
                "items": await asyncio.to_thread(discover_links, engine.settings.link_roots)
            }
        if rest == ["reload"] and method == "POST":
            changed = await asyncio.to_thread(engine.snapshots.reload, force=True)
            return 200, {
                "ok": engine.snapshots.last_error is None,
                "changed": changed,
                "error": engine.snapshots.last_error,
            }
        if rest == ["lifecycle", "run"] and method == "POST":
            return 200, {"ok": True, "buckets": await asyncio.to_thread(engine.lifecycle_once)}
        if rest == ["gc"] and method == "POST":
            return 200, {"ok": True, "buckets": await asyncio.to_thread(engine.gc_once)}
        if len(rest) >= 2 and rest[0] == "buckets":
            name = rest[1]
            action = rest[2] if len(rest) > 2 else None
            if action is None and method == "DELETE":
                force = (params.get("force") or ["0"])[0] in {"1", "true"}
                result = await asyncio.to_thread(engine.drop_bucket, name, force=force)
                if result == "not_empty":
                    return 409, {"error": "bucket_not_empty"}
                if result == "unknown":
                    return 404, {"error": "unknown_bucket"}
                return 200, {"ok": True}
            if action == "ensure" and method == "POST":
                await asyncio.to_thread(engine.snapshots.reload, force=True)
                bucket = engine.bucket(name)
                if bucket is None:
                    return 404, {"error": "unknown_bucket"}
                try:
                    await asyncio.to_thread(bucket.ensure)
                except Exception:
                    return 503, {"error": "storage_unavailable"}
                return 200, {"ok": True, "mode": bucket.kind}
            if action == "stats" and method == "GET":
                bucket = engine.bucket(name)
                if bucket is None:
                    return 404, {"error": "unknown_bucket"}
                try:
                    objects, total = await asyncio.to_thread(bucket.usage)
                except Exception:
                    return 503, {"error": "storage_unavailable"}
                return 200, {"objects": objects, "bytes": total}
            if action == "lifecycle" and method == "GET" and len(rest) == 3:
                bucket = engine.bucket(name)
                if bucket is None:
                    return 404, {"error": "unknown_bucket"}
                return 200, {
                    "rules": await asyncio.to_thread(lifecycle.load_rules, bucket) or [],
                    "versioning": bucket.versioning or None,
                    "last_run": await asyncio.to_thread(lifecycle.last_run, bucket),
                    "supported": not bucket.config.read_only,
                }
            if action == "lifecycle" and rest[3:] == ["preview"] and method == "POST":
                bucket = engine.bucket(name)
                if bucket is None:
                    return 404, {"error": "unknown_bucket"}
                try:
                    preview = await asyncio.to_thread(lifecycle.run_bucket, bucket, dry_run=True)
                except Exception:
                    return 503, {"error": "storage_unavailable"}
                return 200, preview
            if action == "rescan" and method == "POST":
                bucket = engine.bucket(name)
                if not isinstance(bucket, LinkedBucket):
                    return 404, {"error": "unknown_linked_bucket"}
                return 200, await asyncio.to_thread(bucket.reconcile)
        return 404, {"error": "not_found"}
