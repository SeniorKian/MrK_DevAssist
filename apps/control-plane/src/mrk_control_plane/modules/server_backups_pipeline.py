"""One backup run: agent stream -> (gzip) -> MRKBKP2 encryption -> destination.

Nothing is spooled to disk; memory holds at most one agent frame batch, one
encryption record (4 MiB) and one multipart part. The run fails unless the
agent's final ``E`` frame reports success, so a cut stream never becomes a
"successful" truncated backup.
"""

from __future__ import annotations

import asyncio
import json
import struct
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import httpx

from .host_agent import AgentError, HostAgentService
from .server_backups_crypto import StreamEncryptor
from .server_backups_dest import DestinationHandle

BATCH_BYTES = 1024 * 1024
MAX_FRAME_BYTES = 4 * 1024 * 1024
DUMP_READ_TIMEOUT_SECONDS = 1800.0
# Compressing an already-compressed pg_dump custom archive wastes CPU.
COMPRESSION = {"volume": "gzip", "postgres": "none", "mysql": "gzip", "mariadb": "gzip",
               "mongo": "gzip", "redis": "gzip"}


_HEADER_SOURCE_FIELDS = frozenset({"kind", "volume", "container", "database"})


class PipelineError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


class FrameParser:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.status: dict[str, Any] | None = None

    def feed(self, chunk: bytes) -> list[bytes]:
        if self.status is not None and chunk:
            raise PipelineError("agent_protocol_error", "data after the end frame")
        self.buffer.extend(chunk)
        out: list[bytes] = []
        while len(self.buffer) >= 5:
            kind = bytes(self.buffer[:1])
            length = struct.unpack(">I", self.buffer[1:5])[0]
            if length > MAX_FRAME_BYTES or kind not in (b"D", b"E"):
                raise PipelineError("agent_protocol_error", "invalid frame")
            if len(self.buffer) < 5 + length:
                break
            payload = bytes(self.buffer[5 : 5 + length])
            del self.buffer[: 5 + length]
            if kind == b"D":
                out.append(payload)
                continue
            try:
                status = json.loads(payload)
            except ValueError as exc:
                raise PipelineError("agent_protocol_error", "invalid end frame") from exc
            if not isinstance(status, dict):
                raise PipelineError("agent_protocol_error", "invalid end frame")
            self.status = status
            if self.buffer:
                raise PipelineError("agent_protocol_error", "data after the end frame")
        return out


async def open_agent_stream(
    agent: HostAgentService, source: dict[str, Any]
) -> tuple[httpx.AsyncClient, httpx.Response]:
    kind = source["kind"]
    if kind == "volume":
        return await agent.open_stream(f"/v1/backup/volumes/{source['volume']}/archive")
    url, key = agent._target()  # noqa: SLF001 - same package, signed POST stream
    client = agent._client(  # noqa: SLF001
        url, httpx.Timeout(connect=3.0, read=DUMP_READ_TIMEOUT_SECONDS, write=10.0, pool=5.0)
    )
    try:
        body: dict[str, Any] = {"engine": kind}
        if source.get("database"):
            body["database"] = source["database"]
        request = agent._signed_request(  # noqa: SLF001
            client, key, "POST", f"/v1/backup/db/{source['container']}/dump", body
        )
        try:
            response = await client.send(request, stream=True)
        except httpx.TimeoutException as exc:
            raise AgentError("agent_timeout", 504, "The agent timed out") from exc
        except httpx.HTTPError as exc:
            raise AgentError("agent_unreachable", 502, "The agent is unreachable") from exc
        if response.status_code != 200:
            try:
                raw = await response.aread()
            finally:
                await response.aclose()
            code = None
            try:
                payload = json.loads(raw)
                code = payload.get("error") if isinstance(payload, dict) else None
            except ValueError:
                pass
            if response.status_code in (403, 404, 409, 422) and isinstance(code, str):
                raise PipelineError(code[:80])
            agent._raise_for_status(response.status_code, raw[:65536])  # noqa: SLF001
            raise AgentError("agent_unreachable", 502, "unexpected agent status")
    except BaseException:
        await client.aclose()
        raise
    return client, response


@dataclass(slots=True)
class RunResult:
    object_key: str
    bytes: int
    source_bytes: int
    sha256: str
    details: dict[str, Any] = field(default_factory=dict)


async def _agent_chunks(response: httpx.Response, parser: FrameParser) -> AsyncIterator[bytes]:
    async for chunk in response.aiter_bytes():
        for payload in parser.feed(chunk):
            yield payload


async def run_backup(
    *,
    agent: HostAgentService,
    destination: DestinationHandle,
    source: dict[str, Any],
    object_key: str,
    passphrase: str,
    key_ref: str,
    job_id: str,
    backup_id: str,
    payload_name: str,
) -> RunResult:
    encryptor = await asyncio.to_thread(
        StreamEncryptor,
        passphrase,
        backup_id=backup_id,
        source={k: v for k, v in source.items() if k in _HEADER_SOURCE_FIELDS},
        payload_name=payload_name,
        compression=COMPRESSION[source["kind"]],
        job_id=job_id,
        key_ref=key_ref,
    )
    sink = await destination.open_sink(object_key)
    try:
        client, response = await open_agent_stream(agent, source)
        parser = FrameParser()
        try:
            batch = bytearray()
            try:
                async for payload in _agent_chunks(response, parser):
                    batch.extend(payload)
                    if len(batch) >= BATCH_BYTES:
                        data = bytes(batch)
                        batch.clear()
                        await sink.write(await asyncio.to_thread(encryptor.update, data))
            except httpx.HTTPError as exc:
                raise PipelineError("agent_stream_interrupted") from exc
            if batch:
                await sink.write(await asyncio.to_thread(encryptor.update, bytes(batch)))
        finally:
            await response.aclose()
            await client.aclose()
        status = parser.status
        if status is None or parser.buffer:
            raise PipelineError("agent_stream_incomplete")
        if status.get("ok") is not True:
            error = status.get("error")
            raise PipelineError(error[:80] if isinstance(error, str) else "source_failed")
        await sink.write(await asyncio.to_thread(encryptor.finish))
        await sink.finish()
    except BaseException:
        await sink.abort()
        raise
    details: dict[str, Any] = {"compression": COMPRESSION[source["kind"]]}
    stats = status.get("stats")
    if isinstance(stats, dict):
        details["stats"] = {k: v for k, v in stats.items() if isinstance(v, int)}
    return RunResult(
        object_key=object_key,
        bytes=encryptor.artifact_bytes,
        source_bytes=encryptor.source_bytes,
        sha256=encryptor.artifact_digest.hexdigest(),
        details=details,
    )
