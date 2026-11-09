"""Engine state: config snapshot, bucket backends, background GC/hash/poll tasks."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import shutil
import time
from pathlib import Path

from ..secret_store import SecretStore
from .index import BucketIndex
from .linked import LinkedBucket
from .settings import EngineSettings
from .snapshot import BucketConfig, SnapshotManager, validate_bucket_name
from .storage import BaseBucket, ManagedBucket

LOGGER = logging.getLogger("mrk.s3.engine")


def load_or_create_token(path: Path) -> str:
    """Shared admin token (mode 0600). Either side may create it; O_EXCL avoids races."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(secrets.token_urlsafe(32) + "\n")
    for _ in range(50):
        token = path.read_text(encoding="ascii").strip()
        if token:
            return token
        time.sleep(0.02)  # the other side is still writing
    raise RuntimeError("admin token file is empty")


class Engine:
    def __init__(self, settings: EngineSettings, secret_store: SecretStore | None = None) -> None:
        self.settings = settings
        settings.data_root.mkdir(parents=True, exist_ok=True)
        settings.meta_dir.mkdir(parents=True, exist_ok=True)
        settings.buckets_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots = SnapshotManager(settings, secret_store)
        self.admin_token = load_or_create_token(settings.admin_token_file)
        self.token_key = hmac.new(
            self.admin_token.encode(), b"s3-continuation-token", hashlib.sha256
        ).digest()
        self.trusted_proxies = {
            item.strip()
            for item in os.getenv("MRK_S3_TRUSTED_PROXIES", "").split(",")
            if item.strip()
        }
        self._buckets: dict[str, tuple[BucketConfig, BaseBucket]] = {}
        self._indexes: dict[str, BucketIndex] = {}
        self.key_last_used: dict[str, float] = {}
        self.last_gc: dict[str, object] = {}
        self.last_lifecycle: dict[str, object] = {}
        self._stop = asyncio.Event()
        self.snapshots.reload(force=True)
        from .admin import AdminApi
        from .protocol import S3Api

        self.api = S3Api(self)
        self.admin = AdminApi(self)

    # ------------------------------------------------------------------ buckets
    def index_for(self, name: str) -> BucketIndex:
        index = self._indexes.get(name)
        if index is None:
            synchronous = "FULL" if self.settings.fsync_policy == "strict" else "NORMAL"
            index = BucketIndex(self.settings.meta_dir / f"{name}.sqlite", synchronous=synchronous)
            self._indexes[name] = index
        return index

    def bucket(self, name: str) -> BaseBucket | None:
        snapshot = self.snapshots.current
        if snapshot is None:
            return None
        config = snapshot.buckets.get(name)
        if config is None:
            return None
        cached = self._buckets.get(name)
        if cached is not None and cached[0] == config:
            return cached[1]
        index = self.index_for(name)
        bucket: BaseBucket = (
            LinkedBucket(self.settings, config, index)
            if config.linked
            else ManagedBucket(self.settings, config, index)
        )
        if cached is not None and cached[0].mode == config.mode:
            bucket.key_locks = cached[1].key_locks
        if isinstance(bucket, ManagedBucket):
            bucket.ensure()
        self._buckets[name] = (config, bucket)
        return bucket

    def buckets(self) -> list[BaseBucket]:
        snapshot = self.snapshots.current
        if snapshot is None:
            return []
        result = []
        for name in snapshot.buckets:
            bucket = self.bucket(name)
            if bucket is not None:
                result.append(bucket)
        return result

    def drop_bucket(self, name: str, *, force: bool) -> str:
        """Remove engine-side state. Returns ``deleted``/``not_empty``/``unknown``.

        Linked buckets: only the sidecar index goes; files are never touched.
        """
        if not validate_bucket_name(name):
            return "unknown"
        snapshot = self.snapshots.current
        config = snapshot.buckets.get(name) if snapshot else None
        storage = self.settings.buckets_dir / name
        linked = config.linked if config else not storage.exists()
        index_path = self.settings.meta_dir / f"{name}.sqlite"
        if not linked:
            if not storage.exists() and not index_path.exists():
                return "unknown"
            index = self.index_for(name)
            if not force and (index.has_objects() or index.has_uploads()):
                return "not_empty"
        elif not index_path.exists() and config is None:
            return "unknown"
        self._buckets.pop(name, None)
        index = self._indexes.pop(name, None)
        if index is not None:
            index.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(f"{index_path}{suffix}")
            except FileNotFoundError:
                pass
        if not linked and storage.exists():
            shutil.rmtree(storage, ignore_errors=True)
        LOGGER.info(
            "dropped bucket state", extra={"bucket": name, "linked": linked, "force": force}
        )
        return "deleted"

    def note_key_used(self, access_key_id: str) -> None:
        self.key_last_used[access_key_id] = time.time()

    # ------------------------------------------------------------------ background
    def gc_once(self) -> dict[str, object]:
        now = time.time_ns()
        report: dict[str, object] = {}
        for bucket in self.buckets():
            try:
                result: dict[str, int] = dict(bucket.gc(now))
                if isinstance(bucket, LinkedBucket):
                    result.update(bucket.reconcile())
                elif isinstance(bucket, ManagedBucket):
                    result["orphans"] = bucket.orphan_sweep()
                report[bucket.name] = result
            except Exception:
                LOGGER.exception("S3 GC failed", extra={"bucket": bucket.name})
        self.last_gc = {"at": time.time(), "buckets": report}
        return report

    def lifecycle_once(self, now_ns: int | None = None) -> dict[str, object]:
        """Run every bucket's lifecycle rules once (summary per bucket, not per object)."""
        from .lifecycle import load_rules, run_bucket

        report: dict[str, object] = {}
        for bucket in self.buckets():
            try:
                if not load_rules(bucket):
                    continue
                report[bucket.name] = run_bucket(bucket, now_ns, dry_run=False)
            except Exception:
                LOGGER.exception("S3 lifecycle failed", extra={"bucket": bucket.name})
        self.last_lifecycle = {"at": time.time(), "buckets": report}
        return report

    @staticmethod
    def seconds_until_hour(hour: int, now: float | None = None) -> float:
        now = time.time() if now is None else now
        today = now - now % 86400 + hour * 3600
        target = today if today > now else today + 86400
        return max(1.0, target - now)

    async def _lifecycle_loop(self) -> None:
        hour = self.settings.lifecycle_hour_utc
        if hour < 0:
            return
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), self.seconds_until_hour(hour))
                return
            except TimeoutError:
                pass
            try:
                await asyncio.to_thread(self.lifecycle_once)
            except Exception:
                LOGGER.exception("S3 lifecycle loop failed")

    async def _poll_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.to_thread(self.snapshots.reload)
            except Exception:
                LOGGER.exception("S3 config poll failed")
            try:
                await asyncio.wait_for(self._stop.wait(), self.settings.config_poll_seconds)
            except TimeoutError:
                pass

    async def _gc_loop(self) -> None:
        # Startup recovery pass shortly after boot, then on the configured interval.
        delay = 5.0
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), delay)
                return
            except TimeoutError:
                pass
            try:
                await asyncio.to_thread(self.gc_once)
            except Exception:
                LOGGER.exception("S3 GC loop failed")
            delay = float(self.settings.gc_interval_seconds)

    async def _hash_loop(self) -> None:
        while not self._stop.is_set():
            worked = False
            for bucket in self.buckets():
                if not isinstance(bucket, LinkedBucket) or not bucket.hash_queue:
                    continue
                key = next(iter(bucket.hash_queue))
                bucket.hash_queue.pop(key, None)
                try:
                    await bucket.hash_one(key, self.settings.hash_rate_bytes)
                    worked = True
                except Exception:
                    LOGGER.debug("lazy MD5 failed", extra={"bucket": bucket.name})
            if not worked:
                try:
                    await asyncio.wait_for(self._stop.wait(), 2.0)
                except TimeoutError:
                    pass

    async def run_background(self) -> None:
        await asyncio.gather(
            self._poll_loop(), self._gc_loop(), self._hash_loop(), self._lifecycle_loop()
        )

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        for index in self._indexes.values():
            index.close()
        self._indexes.clear()
        self._buckets.clear()
