"""Server backup destinations: validation, artifact sinks, reads, deletes and tests.

Kinds (docs/31 §4):

* ``local``  – a directory inside the data dir (default
  ``<data>/modules/server-backups/local``); appliance-owned trees are refused.
* ``s3``     – any S3-compatible service, reached through ``outbound.py`` (proxy
  profile + destination policy); secret access key in the SecretStore.
* ``mrk_s3`` – our own S3 engine on loopback (``MRK_S3_ENGINE_URL``, default
  ``http://127.0.0.1:9000``, path-style). The key is either typed in the form or
  an existing access key of an identity (its secret is read from the SecretStore).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import secrets
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import httpx

from .. import outbound
from ..netresolve import NetworkSettingsStore
from ..secret_store import SecretStore
from . import server_backups_s3 as s3

KINDS = ("local", "s3", "mrk_s3")
LOCAL_DEFAULT = "modules/server-backups/local"
# Appliance-owned trees under the data dir that must never receive artifacts.
LOCAL_FORBIDDEN = ("control-plane", "npm", "pypi", "logs", "backups", "modules/s3", "agent",
                   "pgdata", "pglite")
DEFAULT_REGION = "us-east-1"
DEFAULT_MRK_S3_URL = "http://127.0.0.1:9000"
ARTIFACT_CONTENT_TYPE = "application/vnd.mrk.backup"
REQUEST_TIMEOUT_SECONDS = 60.0
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_REGION = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_ACCESS_KEY = re.compile(r"^[A-Za-z0-9+/=._-]{3,128}$")
_PREFIX = re.compile(r"^[A-Za-z0-9!_.*'()/-]{0,256}$")
_IPV4ISH = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

# Tests inject a MockTransport (and a resolver for the outbound policy).
S3_TRANSPORT: httpx.AsyncBaseTransport | None = None
S3_RESOLVER: outbound.Resolver | None = None
S3_SUPPORTED_PROXY_TYPES = outbound.ALL_PROXY_TYPES


class DestinationError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _part_size() -> int:
    try:
        value = int(os.getenv("MRK_SERVER_BACKUP_PART_BYTES", str(s3.DEFAULT_PART_BYTES)))
    except ValueError:
        value = s3.DEFAULT_PART_BYTES
    return min(max(value, s3.MIN_PART_BYTES), 512 * 1024 * 1024)


PART_SIZE: int | None = None  # tests override; None -> environment/default


def part_size() -> int:
    return PART_SIZE if PART_SIZE is not None else _part_size()


def mrk_s3_endpoint() -> str:
    # Same resolution as the file manager: env, then a separate engine (docs/44), then loopback.
    from .s3_client import engine_url

    return engine_url()


def mrk_s3_region(data_dir: Path) -> str:
    try:
        payload = json.loads((data_dir / "modules" / "s3" / "config.json").read_text("utf-8"))
        region = payload.get("region") if isinstance(payload, dict) else None
        if isinstance(region, str) and _REGION.fullmatch(region):
            return region
    except (OSError, ValueError):
        pass
    return DEFAULT_REGION


# --- validation ------------------------------------------------------------------


def _str(config: dict[str, Any], key: str, default: str | None = None) -> str | None:
    value = config.get(key, default)
    if value is None:
        return None
    if not isinstance(value, str):
        raise DestinationError("invalid_destination", f"{key} must be a string")
    return value.strip()


def _validate_local(data_dir: Path, config: dict[str, Any]) -> dict[str, Any]:
    raw = _str(config, "path") or str(data_dir / LOCAL_DEFAULT)
    if "\x00" in raw or len(raw) > 1024:
        raise DestinationError("invalid_path", "path is invalid")
    candidate = Path(raw)
    if not candidate.is_absolute() and not raw.startswith("/"):
        raise DestinationError("invalid_path", "path must be absolute")
    if ".." in PurePosixPath(raw.replace("\\", "/")).parts:
        raise DestinationError("invalid_path", "path must not contain '..'")
    root = data_dir.resolve()
    resolved = Path(os.path.realpath(candidate))
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        raise DestinationError(
            "path_outside_data", "local destinations must be inside the data directory"
        ) from None
    rel = relative.as_posix()
    if rel in {"", "."} or rel == "modules" or any(
        rel == item or rel.startswith(item + "/") for item in LOCAL_FORBIDDEN
    ):
        raise DestinationError("path_forbidden", "this directory belongs to the appliance")
    return {"path": str(resolved)}


def validate_endpoint(value: str) -> str:
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise DestinationError("invalid_endpoint", "endpoint is invalid") from None
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise DestinationError("invalid_endpoint", "endpoint must be an http(s) URL")
    if parts.username or parts.password or "@" in parts.netloc:
        raise DestinationError("invalid_endpoint", "endpoint must not contain credentials")
    if parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise DestinationError("invalid_endpoint", "endpoint must not contain a path or query")
    if any(char.isspace() for char in value):
        raise DestinationError("invalid_endpoint", "endpoint is invalid")
    host = parts.hostname.lower()
    netloc = host if ":" not in host else f"[{host}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    return f"{parts.scheme}://{netloc}"


def _prefix(config: dict[str, Any]) -> str:
    prefix = _str(config, "prefix", "") or ""
    prefix = prefix.strip("/")
    if not _PREFIX.fullmatch(prefix) or "//" in prefix or ".." in prefix.split("/"):
        raise DestinationError("invalid_prefix", "prefix contains unsupported characters")
    return f"{prefix}/" if prefix else ""


def _bucket(config: dict[str, Any]) -> str:
    bucket = _str(config, "bucket") or ""
    if not _BUCKET.fullmatch(bucket) or ".." in bucket or _IPV4ISH.fullmatch(bucket):
        raise DestinationError("invalid_bucket", "bucket name is invalid")
    return bucket


def _access_key(config: dict[str, Any]) -> str:
    value = _str(config, "access_key_id") or ""
    if not _ACCESS_KEY.fullmatch(value):
        raise DestinationError("invalid_access_key", "access_key_id is invalid")
    return value


def _secret_value(secret: dict[str, Any] | None) -> str | None:
    if not secret:
        return None
    value = secret.get("secret_access_key")
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(
        ord(char) < 32 for char in value
    ):
        raise DestinationError("invalid_secret", "secret_access_key is invalid")
    return value


@dataclass(slots=True)
class Validated:
    config: dict[str, Any]
    secret: str | None  # new secret to store (None = keep / not needed)
    clear_secret: bool = False


def validate(
    kind: str,
    config: object,
    secret: object,
    *,
    data_dir: Path,
    network: NetworkSettingsStore,
    previous: dict[str, Any] | None = None,
    has_secret: bool = False,
    known_mrk_key: bool = False,
) -> Validated:
    """Validate a destination body. ``previous`` is the stored config on PATCH."""
    if kind not in KINDS:
        raise DestinationError("invalid_kind", "kind must be local, s3 or mrk_s3")
    if not isinstance(config, dict):
        raise DestinationError("invalid_destination", "config must be an object")
    if secret is not None and not isinstance(secret, dict):
        raise DestinationError("invalid_destination", "secret must be an object")
    merged = {**(previous or {}), **config}
    if kind == "local":
        return Validated(_validate_local(data_dir, merged), None, clear_secret=True)
    new_secret = _secret_value(secret)  # type: ignore[arg-type]
    clean: dict[str, Any] = {
        "bucket": _bucket(merged),
        "prefix": _prefix(merged),
        "access_key_id": _access_key(merged),
    }
    if kind == "s3":
        endpoint = validate_endpoint(_str(merged, "endpoint") or "")
        region = _str(merged, "region", DEFAULT_REGION) or DEFAULT_REGION
        if not _REGION.fullmatch(region):
            raise DestinationError("invalid_region", "region is invalid")
        path_style = merged.get("path_style", True)
        if not isinstance(path_style, bool):
            raise DestinationError("invalid_destination", "path_style must be a boolean")
        try:
            proxy_id = outbound.check_reference(
                network, merged.get("proxy_id"), S3_SUPPORTED_PROXY_TYPES, "proxy_type_unsupported"
            )
        except outbound.OutboundError as exc:
            raise DestinationError(exc.code, str(exc)) from None
        clean.update(endpoint=endpoint, region=region, path_style=path_style, proxy_id=proxy_id)
        if previous is not None:
            moved = (
                previous.get("endpoint") != endpoint
                or previous.get("access_key_id") != clean["access_key_id"]
            )
            if moved and new_secret is None:
                # A stored secret is never sent to a different endpoint or key id.
                raise DestinationError(
                    "secret_required", "Enter the secret access key again for the new endpoint"
                )
        if new_secret is None and not has_secret:
            raise DestinationError("secret_required", "secret_access_key is required")
        return Validated(clean, new_secret)
    region = _str(merged, "region", None)
    if region is not None and not _REGION.fullmatch(region):
        raise DestinationError("invalid_region", "region is invalid")
    if region:
        clean["region"] = region
    if previous is not None and previous.get("access_key_id") != clean["access_key_id"]:
        has_secret = False
    if new_secret is None and not has_secret and not known_mrk_key:
        raise DestinationError(
            "secret_required",
            "Enter the secret access key or choose an existing access key of an identity",
        )
    return Validated(clean, new_secret, clear_secret=new_secret is None and known_mrk_key)


def public_config(kind: str, config: dict[str, Any]) -> dict[str, Any]:
    result = dict(config)
    if kind == "mrk_s3":
        result.setdefault("endpoint", mrk_s3_endpoint())
        result["path_style"] = True
    return result


# --- handles ------------------------------------------------------------------------


class LocalSink:
    def __init__(self, target: Path) -> None:
        self.target = target
        self.temporary = target.with_name(f".{target.name}.{secrets.token_hex(4)}.partial")
        self.handle: Any = None
        self.size = 0

    async def open(self) -> None:
        def _open() -> Any:
            self.target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            return self.temporary.open("xb")

        self.handle = await asyncio.to_thread(_open)

    async def write(self, data: bytes) -> None:
        if data:
            await asyncio.to_thread(self.handle.write, data)
            self.size += len(data)

    async def finish(self) -> None:
        def _finish() -> None:
            self.handle.flush()
            os.fsync(self.handle.fileno())
            self.handle.close()
            with contextlib.suppress(OSError):
                self.temporary.chmod(0o600)
            os.replace(self.temporary, self.target)

        await asyncio.to_thread(_finish)

    async def abort(self) -> None:
        def _abort() -> None:
            if self.handle is not None:
                with contextlib.suppress(OSError):
                    self.handle.close()
            with contextlib.suppress(OSError):
                self.temporary.unlink()

        await asyncio.to_thread(_abort)


class S3Sink:
    def __init__(self, upload: s3.MultipartUpload) -> None:
        self.upload = upload

    async def open(self) -> None:
        return None

    async def write(self, data: bytes) -> None:
        if data:
            await self.upload.write(data)

    async def finish(self) -> None:
        await self.upload.finish()

    async def abort(self) -> None:
        await self.upload.abort()


@dataclass(slots=True)
class DestinationSpec:
    id: str
    kind: str
    config: dict[str, Any]
    secret_ref: str | None
    mrk_key_secret_ref: str | None = None  # SecretStore ref of a chosen identity key


class DestinationHandle:
    """Open connection to one destination (use as ``async with``)."""

    def __init__(
        self,
        spec: DestinationSpec,
        *,
        data_dir: Path,
        network: NetworkSettingsStore,
        secret_store: SecretStore,
    ) -> None:
        self.spec = spec
        self.data_dir = data_dir
        self.network = network
        self.secret_store = secret_store
        self.client: s3.S3Client | None = None
        self._stack = contextlib.AsyncExitStack()

    def _s3_secret(self) -> str:
        reference = self.spec.secret_ref or self.spec.mrk_key_secret_ref
        if not reference:
            raise DestinationError("secret_unavailable", "the destination secret is missing", 409)
        try:
            value = self.secret_store.get(reference).get("secret_access_key")
        except (KeyError, ValueError):
            value = None
        if not value:
            raise DestinationError("secret_unavailable", "the destination secret is missing", 409)
        return value

    async def __aenter__(self) -> DestinationHandle:
        if self.spec.kind == "local":
            return self
        config = self.spec.config
        secret_key = await asyncio.to_thread(self._s3_secret)
        if self.spec.kind == "s3":
            try:
                client = await self._stack.enter_async_context(
                    outbound.outbound_client(
                        self.network,
                        self.secret_store,
                        config.get("proxy_id"),
                        timeout=REQUEST_TIMEOUT_SECONDS,
                        transport=S3_TRANSPORT,
                        resolver=S3_RESOLVER,
                    )
                )
            except outbound.OutboundError as exc:
                raise DestinationError(exc.code, str(exc), 502) from None
            target = s3.S3Target(
                endpoint=config["endpoint"],
                bucket=config["bucket"],
                region=config.get("region") or DEFAULT_REGION,
                access_key_id=config["access_key_id"],
                secret_access_key=secret_key,
                path_style=bool(config.get("path_style", True)),
            )
            self.client = s3.S3Client(target, client.send)
            return self
        http = await self._stack.enter_async_context(
            httpx.AsyncClient(
                transport=S3_TRANSPORT,
                timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS, connect=5.0),
                follow_redirects=False,
                trust_env=False,
            )
        )

        async def send(method: str, url: str, *, headers: dict[str, str],
                       content: bytes | None = None, stream: bool = False) -> httpx.Response:
            request = http.build_request(method, url, headers=headers, content=content)
            return await http.send(request, stream=stream)

        target = s3.S3Target(
            endpoint=mrk_s3_endpoint(),
            bucket=config["bucket"],
            region=config.get("region") or mrk_s3_region(self.data_dir),
            access_key_id=config["access_key_id"],
            secret_access_key=secret_key,
            path_style=True,
        )
        self.client = s3.S3Client(target, send)
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self._stack.aclose()

    # -- operations ------------------------------------------------------------
    def _local_path(self, key: str) -> Path:
        root = Path(self.spec.config["path"])
        path = root.joinpath(*PurePosixPath(key).parts)
        if ".." in PurePosixPath(key).parts or not str(path).startswith(str(root)):
            raise DestinationError("invalid_object_key", "object key is invalid")
        return path

    def object_key(self, relative: str) -> str:
        if self.spec.kind == "local":
            return relative
        return f"{self.spec.config.get('prefix', '')}{relative}"

    async def open_sink(self, key: str) -> LocalSink | S3Sink:
        if self.spec.kind == "local":
            sink: LocalSink | S3Sink = LocalSink(self._local_path(key))
        else:
            assert self.client is not None  # noqa: S101
            sink = S3Sink(
                s3.MultipartUpload(self.client, key, part_size(), ARTIFACT_CONTENT_TYPE)
            )
        await sink.open()
        return sink

    async def delete(self, key: str) -> None:
        if self.spec.kind == "local":
            path = self._local_path(key)
            await asyncio.to_thread(path.unlink, True)
            return
        assert self.client is not None  # noqa: S101
        await self.client.delete_object(key)

    async def read(self, key: str) -> AsyncIterator[bytes]:
        if self.spec.kind == "local":
            path = self._local_path(key)
            try:
                handle = await asyncio.to_thread(path.open, "rb")
            except FileNotFoundError:
                raise DestinationError(
                    "artifact_missing", "the artifact no longer exists", 404
                ) from None
            try:
                while chunk := await asyncio.to_thread(handle.read, 1024 * 1024):
                    yield chunk
            finally:
                await asyncio.to_thread(handle.close)
            return
        assert self.client is not None  # noqa: S101
        try:
            response = await self.client.get_object(key)
        except s3.S3Error as exc:
            if exc.code == "s3_object_not_found":
                raise DestinationError(
                    "artifact_missing", "the artifact no longer exists", 404
                ) from None
            raise
        try:
            async for chunk in response.aiter_bytes():
                yield chunk
        finally:
            await response.aclose()

    async def test(self) -> dict[str, Any]:
        started = time.perf_counter()
        error: str | None = None
        try:
            if self.spec.kind == "local":
                await asyncio.to_thread(self._test_local)
            else:
                assert self.client is not None  # noqa: S101
                await self.client.list_objects(self.spec.config.get("prefix", ""), 1)
        except DestinationError as exc:
            error = exc.code
        except s3.S3Error as exc:
            error = exc.code
        except Exception as exc:  # never echo: messages may contain URLs
            error = outbound.error_code(exc)
        result: dict[str, Any] = {
            "ok": error is None,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        }
        if error:
            result["error_code"] = error
        return result

    def _test_local(self) -> None:
        root = Path(self.spec.config["path"])
        try:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            probe = root / f".mrk-write-test-{secrets.token_hex(4)}"
            probe.write_bytes(b"ok")
            probe.unlink()
        except OSError:
            raise DestinationError("path_not_writable", "the directory is not writable") from None


def error_code(exc: BaseException) -> str:
    if isinstance(exc, DestinationError | s3.S3Error):
        return exc.code
    return outbound.error_code(exc)
