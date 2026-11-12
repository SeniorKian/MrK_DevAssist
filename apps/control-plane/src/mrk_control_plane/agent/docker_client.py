"""Docker Engine API client with a strict allowlist enforced in our code.

Only the (method, path, query) combinations listed in ``_ALLOWLIST`` can ever
leave this module. Gate 16 allowed read-only GETs; Gate 17 adds exactly:

- ``GET /containers/{id}/logs`` (stdout+stderr required, bounded query values)
- ``POST /containers/{id}/start|stop|restart`` (``t`` 0..300 for stop/restart)
- ``POST /images/create`` (``fromImage`` + ``tag`` only, validated references)
- ``POST /build/prune`` (no parameters)
- ``DELETE /containers/{64-hex id}`` (``v=0``; never ``force``)
- ``DELETE /images/sha256:{64-hex}`` (``noprune=0``; never ``force``)
- ``DELETE /networks/{64-hex id}``

Gate 18 (server backups) adds exec, but only for the fixed dump templates of
``agent/backup.py``:

- ``POST /containers/{64-hex id}/exec`` with a body built here whose ``Cmd``/``Env``
  must pass ``backup.exec_spec_allowed`` (never ``User``, ``Privileged``, TTY or stdin)
- ``POST /exec/{64-hex id}/start`` (body ``{"Detach": false, "Tty": false}``)
- ``GET /exec/{64-hex id}/json``

Gate 19 (vulnerability scanning) adds one read-only call:

- ``GET /containers/{64-hex id}/archive`` with ``path`` exactly one of the fixed
  package-database paths in ``package_files.PACKAGE_DB_PATHS`` (no other query)

No create, volume deletion, prune-all endpoints or anything else; every other
request raises ``DockerNotAllowed`` before a byte is sent to the socket.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from .backup import exec_spec_allowed
from .package_files import PACKAGE_DB_PATHS

DEFAULT_SOCKET = "/var/run/docker.sock"
_ID_OR_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
_FULL_ID = r"[0-9a-f]{64}"
_API_VERSION = re.compile(r"^1\.[0-9]{1,3}$")

# Docker reference grammar (distribution/reference), without IPv6 literals.
_DOMAIN_COMPONENT = r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"
_DOMAIN = rf"{_DOMAIN_COMPONENT}(?:\.{_DOMAIN_COMPONENT})*(?::[0-9]{{1,5}})?"
_PATH_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
_REPOSITORY = rf"(?:{_DOMAIN}/)?{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"  # [\w][\w.-]{0,127}, ASCII only
_DIGEST = r"sha256:[0-9a-f]{64}"
REPOSITORY_PATTERN = re.compile(rf"^{_REPOSITORY}$")
TAG_OR_DIGEST_PATTERN = re.compile(rf"^(?:{_TAG}|{_DIGEST})$")
_MAX_REPOSITORY_LENGTH = 255

_ONE = re.compile(r"^1$")
_ZERO = re.compile(r"^0$")
_ZERO_OR_ONE = re.compile(r"^(0|1)$")
_UNIX_TS = re.compile(r"^[0-9]{1,12}$")
_TAIL = re.compile(r"^(?:[0-9]|[1-9][0-9]{1,2}|[1-4][0-9]{3}|5000)$")
_STOP_TIMEOUT = re.compile(r"^(?:[0-9]|[1-9][0-9]|[12][0-9]{2}|300)$")
_PACKAGE_DB_PATH = re.compile("^(?:" + "|".join(re.escape(p) for p in PACKAGE_DB_PATHS) + ")$")


@dataclass(frozen=True, slots=True)
class _Rule:
    method: str
    path: re.Pattern[str]
    params: dict[str, re.Pattern[str]] = field(default_factory=dict)
    required: frozenset[str] = frozenset()
    body: Callable[[object], bool] | None = None


def _exec_create_body(body: object) -> bool:
    return (
        isinstance(body, dict)
        and set(body) == {"AttachStdin", "AttachStdout", "AttachStderr", "Tty", "Cmd", "Env"}
        and body["AttachStdin"] is False
        and body["AttachStdout"] is True
        and body["AttachStderr"] is True
        and body["Tty"] is False
        and exec_spec_allowed(body["Cmd"], body["Env"])
    )


def _exec_start_body(body: object) -> bool:
    return body == {"Detach": False, "Tty": False}


_ALLOWLIST: tuple[_Rule, ...] = (
    _Rule("GET", re.compile(r"^/version$")),
    _Rule("GET", re.compile(r"^/info$")),
    _Rule("GET", re.compile(r"^/containers/json$"), {"all": re.compile(r"^(1|true)$")}),
    _Rule("GET", re.compile(rf"^/containers/{_ID_OR_NAME}/json$")),
    _Rule("GET", re.compile(r"^/images/json$")),
    _Rule("GET", re.compile(r"^/volumes$")),
    _Rule("GET", re.compile(r"^/networks$")),
    _Rule("GET", re.compile(r"^/system/df$")),
    # Gate 17 -----------------------------------------------------------------
    _Rule(
        "GET",
        re.compile(rf"^/containers/{_ID_OR_NAME}/logs$"),
        {
            "stdout": _ONE,
            "stderr": _ONE,
            "timestamps": _ZERO_OR_ONE,
            "follow": _ZERO_OR_ONE,
            "tail": _TAIL,
            "since": _UNIX_TS,
            "until": _UNIX_TS,
        },
        frozenset({"stdout", "stderr", "tail"}),
    ),
    _Rule("POST", re.compile(rf"^/containers/{_ID_OR_NAME}/start$")),
    _Rule("POST", re.compile(rf"^/containers/{_ID_OR_NAME}/(stop|restart)$"), {"t": _STOP_TIMEOUT}),
    _Rule(
        "POST",
        re.compile(r"^/images/create$"),
        {"fromImage": REPOSITORY_PATTERN, "tag": TAG_OR_DIGEST_PATTERN},
        frozenset({"fromImage", "tag"}),
    ),
    _Rule("POST", re.compile(r"^/build/prune$")),
    _Rule("DELETE", re.compile(rf"^/containers/{_FULL_ID}$"), {"v": _ZERO}),
    _Rule("DELETE", re.compile(rf"^/images/sha256:{_FULL_ID}$"), {"noprune": _ZERO}),
    _Rule("DELETE", re.compile(rf"^/networks/{_FULL_ID}$")),
    # Gate 18: fixed-template database dumps -----------------------------------
    _Rule("POST", re.compile(rf"^/containers/{_FULL_ID}/exec$"), body=_exec_create_body),
    _Rule("POST", re.compile(rf"^/exec/{_FULL_ID}/start$"), body=_exec_start_body),
    _Rule("GET", re.compile(rf"^/exec/{_FULL_ID}/json$")),
    # Gate 19: fixed package-database paths, read-only ------------------------
    _Rule(
        "GET",
        re.compile(rf"^/containers/{_FULL_ID}/archive$"),
        {"path": _PACKAGE_DB_PATH},
        frozenset({"path"}),
    ),
)
LABEL_SUBSET_KEYS = (
    "com.docker.compose.project",
    "com.docker.compose.service",
    # Dokploy runs a Compose with composeType "stack" as `docker stack deploy <appName>`;
    # the namespace label is the only label carrying that appName verbatim.
    "com.docker.stack.namespace",
    "com.docker.swarm.service.name",
    "org.opencontainers.image.title",
    "org.opencontainers.image.version",
)
_MAX_LABEL_VALUE = 256
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_MAX_ERROR_MESSAGE = 300


class DockerNotAllowed(Exception):
    """The requested Docker API call is outside the allowlist."""


class DockerUnavailable(Exception):
    """The Docker socket is missing, unreachable or returned an error."""


class DockerRequestFailed(DockerUnavailable):
    """Docker answered with an error status; ``message`` is Docker's (truncated) text."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"docker returned HTTP {status_code}")
        self.status_code = status_code
        self.message = message[:_MAX_ERROR_MESSAGE]


def check_allowed(
    method: str, path: str, params: dict[str, str] | None = None, body: object = None
) -> None:
    """Raise DockerNotAllowed unless (method, path, params, body) is on the allowlist."""
    verb = method.upper()
    if verb not in {"GET", "POST", "DELETE"}:
        raise DockerNotAllowed("method is not allowed")
    if (
        not path.startswith("/")
        or any(char in path for char in "?#%\\")
        or "//" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        raise DockerNotAllowed("path is not allowed")
    supplied = params or {}
    for rule in _ALLOWLIST:
        if rule.method != verb or not rule.path.fullmatch(path):
            continue
        for key, value in supplied.items():
            validator = rule.params.get(key)
            if validator is None or not validator.fullmatch(str(value)):
                raise DockerNotAllowed("query parameter is not allowed")
        if not rule.required.issubset(supplied):
            raise DockerNotAllowed("required query parameter is missing")
        if rule.body is None:
            if body is not None:
                raise DockerNotAllowed("request body is not allowed")
        elif not rule.body(body):
            raise DockerNotAllowed("request body is not allowed")
        return
    raise DockerNotAllowed("path is not allowed")


def validate_container_ref(value: str) -> str:
    if not re.fullmatch(_ID_OR_NAME, value) or ".." in value:
        raise DockerNotAllowed("invalid container id or name")
    return value


def parse_image_reference(value: object) -> tuple[str, str]:
    """Validate ``[registry[:port]/]path[:tag][@sha256:<hex>]`` -> (repository, tag_or_digest).

    A missing tag means ``latest``: ``fromImage`` without ``tag`` would pull every tag.
    """
    if not isinstance(value, str) or not value or len(value) > 512 or value != value.strip():
        raise ValueError("invalid image reference")
    name, digest = value, None
    if "@" in value:
        name, _, digest = value.partition("@")
        if not re.fullmatch(_DIGEST, digest):
            raise ValueError("invalid image digest")
    tag = None
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        name, _, tag = name.rpartition(":")
        if not re.fullmatch(_TAG, tag):
            raise ValueError("invalid image tag")
    if len(name) > _MAX_REPOSITORY_LENGTH or not REPOSITORY_PATTERN.fullmatch(name):
        raise ValueError("invalid image repository")
    first, separator, _rest = name.partition("/")
    if (
        separator
        and first != "localhost"
        and "." not in first
        and ":" not in first
        and first != first.lower()
    ):
        # Only a registry host may contain upper case; path components never do.
        raise ValueError("invalid image repository")
    return name, digest or tag or "latest"


def _error_message(body: bytes) -> str:
    try:
        payload = json.loads(body)
    except ValueError:
        return body.decode("utf-8", errors="replace").strip()[:_MAX_ERROR_MESSAGE]
    if isinstance(payload, dict) and isinstance(payload.get("message"), str):
        return payload["message"][:_MAX_ERROR_MESSAGE]
    return ""


class DockerClient:
    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds
        self._client = httpx.AsyncClient(
            transport=transport or httpx.AsyncHTTPTransport(uds=socket_path, retries=0),
            base_url="http://docker",
            timeout=httpx.Timeout(timeout_seconds, connect=2.0),
            follow_redirects=False,
            trust_env=False,
        )
        self.api_version: str | None = None
        self.engine_version: str | None = None

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _url(self, path: str) -> str:
        if path == "/version":
            return path
        if self.api_version is None:
            await self.version()
        return f"/v{self.api_version}{path}"

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        *,
        ok_statuses: tuple[int, ...] = (200,),
        timeout: float | None = None,
        body: object = None,
    ) -> Any:
        """Send one allowlisted request; return parsed JSON (or None for an empty body)."""
        check_allowed(method, path, params, body)
        url = await self._url(path)
        request_timeout = (
            httpx.Timeout(timeout, connect=2.0) if timeout is not None else httpx.USE_CLIENT_DEFAULT
        )
        try:
            async with self._client.stream(
                method, url, params=params, timeout=request_timeout,
                **({} if body is None else {"json": body}),
            ) as response:
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_RESPONSE_BYTES:
                        raise DockerUnavailable("docker response is too large")
                status = response.status_code
        except httpx.HTTPError as exc:
            # A broken connection may mean the daemon restarted; renegotiate next time.
            self.api_version = None
            raise DockerUnavailable(type(exc).__name__) from exc
        if status not in ok_statuses:
            raise DockerRequestFailed(status, _error_message(bytes(body)))
        if not body.strip():
            return None
        try:
            return json.loads(bytes(body))
        except ValueError as exc:
            raise DockerUnavailable("docker returned invalid JSON") from exc

    async def _get(self, path: str, params: dict[str, str] | None = None) -> Any:
        return await self._request("GET", path, params)

    async def open_stream(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        body: object = None,
    ) -> httpx.Response:
        """Open an allowlisted streaming request (no read timeout; callers cap the time).

        The caller must ``await response.aclose()``. Error statuses raise
        DockerRequestFailed after the (small) error body is read and the stream closed.
        """
        check_allowed(method, path, params, body)
        url = await self._url(path)
        request = self._client.build_request(
            method,
            url,
            params=params,
            timeout=httpx.Timeout(None, connect=2.0),
            **({} if body is None else {"json": body}),
        )
        try:
            response = await self._client.send(request, stream=True)
        except httpx.HTTPError as exc:
            self.api_version = None
            raise DockerUnavailable(type(exc).__name__) from exc
        if response.status_code != 200:
            try:
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 65536:
                        break
            except httpx.HTTPError:
                body = bytearray()
            finally:
                await response.aclose()
            raise DockerRequestFailed(response.status_code, _error_message(bytes(body)))
        return response

    async def version(self) -> dict[str, Any]:
        payload = await self._get("/version")
        if not isinstance(payload, dict):
            raise DockerUnavailable("unexpected /version payload")
        api_version = str(payload.get("ApiVersion", ""))
        if not _API_VERSION.fullmatch(api_version):
            raise DockerUnavailable("docker did not report a usable API version")
        self.api_version = api_version
        self.engine_version = str(payload.get("Version", ""))[:64] or None
        return payload

    async def info(self) -> dict[str, Any]:
        payload = await self._get("/info")
        return payload if isinstance(payload, dict) else {}

    async def containers(self) -> list[dict[str, Any]]:
        payload = await self._get("/containers/json", {"all": "1"})
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict)]

    async def inspect_container(self, ref: str) -> dict[str, Any]:
        payload = await self._get(f"/containers/{validate_container_ref(ref)}/json")
        return payload if isinstance(payload, dict) else {}

    async def images(self) -> list[Any]:
        payload = await self._get("/images/json")
        return payload if isinstance(payload, list) else []

    async def volumes(self) -> list[Any]:
        payload = await self._get("/volumes")
        items = payload.get("Volumes") if isinstance(payload, dict) else None
        return items if isinstance(items, list) else []

    async def networks(self) -> list[Any]:
        payload = await self._get("/networks")
        return payload if isinstance(payload, list) else []

    async def system_df(self) -> dict[str, Any]:
        payload = await self._get("/system/df")
        return payload if isinstance(payload, dict) else {}

    # ----- Gate 17 writes ---------------------------------------------------

    async def container_action(self, container_id: str, action: str, timeout_seconds: int) -> None:
        if action not in {"start", "stop", "restart"}:
            raise DockerNotAllowed("unknown container action")
        params = None if action == "start" else {"t": str(timeout_seconds)}
        # 304 = already started/stopped; still a success for the caller.
        await self._request(
            "POST",
            f"/containers/{validate_container_ref(container_id)}/{action}",
            params,
            ok_statuses=(204, 304),
            timeout=float(timeout_seconds) + 30.0,
        )

    async def remove_container(self, container_id: str) -> None:
        await self._request(
            "DELETE", f"/containers/{container_id}", {"v": "0"}, ok_statuses=(204,), timeout=60.0
        )

    async def remove_image(self, image_id: str) -> Any:
        return await self._request(
            "DELETE", f"/images/{image_id}", {"noprune": "0"}, ok_statuses=(200,), timeout=60.0
        )

    async def remove_network(self, network_id: str) -> None:
        await self._request(
            "DELETE", f"/networks/{network_id}", None, ok_statuses=(204, 200), timeout=30.0
        )

    async def build_prune(self) -> dict[str, Any]:
        payload = await self._request("POST", "/build/prune", None, timeout=300.0)
        return payload if isinstance(payload, dict) else {}

    # ----- Gate 18 backups ----------------------------------------------------

    async def exec_create(self, container_id: str, argv: list[str], env: list[str]) -> str:
        """Create a non-interactive exec for one of the fixed dump templates."""
        body = {
            "AttachStdin": False,
            "AttachStdout": True,
            "AttachStderr": True,
            "Tty": False,
            "Cmd": list(argv),
            "Env": list(env),
        }
        payload = await self._request(
            "POST", f"/containers/{container_id}/exec", None, ok_statuses=(201,), body=body
        )
        exec_id = payload.get("Id") if isinstance(payload, dict) else None
        if not isinstance(exec_id, str) or not re.fullmatch(_FULL_ID, exec_id):
            raise DockerUnavailable("docker returned an invalid exec id")
        return exec_id

    async def exec_start_stream(self, exec_id: str) -> httpx.Response:
        return await self.open_stream(
            "POST", f"/exec/{exec_id}/start", None, {"Detach": False, "Tty": False}
        )

    async def exec_inspect(self, exec_id: str) -> dict[str, Any]:
        payload = await self._get(f"/exec/{exec_id}/json")
        return payload if isinstance(payload, dict) else {}


    # ----- Gate 19 package databases --------------------------------------------

    async def archive(
        self, container_id: str, path: str, max_bytes: int
    ) -> tuple[bytes, bool] | None:
        """Tar of one fixed path; None if it does not exist. (data, truncated)."""
        try:
            response = await self.open_stream(
                "GET", f"/containers/{container_id}/archive", {"path": path}
            )
        except DockerRequestFailed as exc:
            if exc.status_code == 404:
                return None
            raise
        data = bytearray()
        truncated = False
        try:
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > max_bytes:
                    truncated = True
                    break
        except httpx.HTTPError as exc:
            raise DockerUnavailable(type(exc).__name__) from exc
        finally:
            await response.aclose()
        return bytes(data[:max_bytes]), truncated


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def labels_subset(labels: dict[str, Any], protected_prefixes: tuple[str, ...]) -> dict[str, str]:
    """Labels can carry secrets (e.g. proxy basic-auth); expose only a safe subset."""
    lowered = tuple(prefix.lower() for prefix in protected_prefixes)
    subset: dict[str, str] = {}
    for key, value in labels.items():
        if key in LABEL_SUBSET_KEYS or (lowered and key.lower().startswith(lowered)):
            subset[str(key)[:128]] = str(value)[:_MAX_LABEL_VALUE]
    return subset


def container_names(raw: dict[str, Any]) -> list[str]:
    return [name for name in raw.get("Names") or [] if isinstance(name, str)]


def container_labels(raw: dict[str, Any]) -> dict[str, Any]:
    labels = raw.get("Labels")
    return labels if isinstance(labels, dict) else {}


def summarize_container(
    raw: dict[str, Any], protected: bool, prefixes: tuple[str, ...]
) -> dict[str, Any]:
    names = container_names(raw)
    ports = [
        {
            "ip": port.get("IP"),
            "private": port.get("PrivatePort"),
            "public": port.get("PublicPort"),
            "type": port.get("Type"),
        }
        for port in raw.get("Ports") or []
        if isinstance(port, dict)
    ]
    return {
        "id": str(raw.get("Id", ""))[:64],
        "name": names[0].lstrip("/") if names else "",
        "image": str(raw.get("Image", ""))[:256],
        "image_id": str(raw.get("ImageID", ""))[:80] or None,
        "state": str(raw.get("State", ""))[:32],
        "status": str(raw.get("Status", ""))[:128],
        "created": _int(raw.get("Created")),
        "ports": ports,
        "labels_subset": labels_subset(container_labels(raw), prefixes),
        "networks": container_networks(raw),
        "protected": protected,
    }


def container_networks(raw: dict[str, Any]) -> list[str]:
    """Names of the networks a container is attached to (names only, no addresses)."""
    settings = raw.get("NetworkSettings")
    networks = settings.get("Networks") if isinstance(settings, dict) else None
    if not isinstance(networks, dict):
        return []
    return sorted(str(name)[:128] for name in networks)[:32]


def _strings(value: object, limit: int = 64) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item)[:512] for item in value if isinstance(item, str)][:limit]


def summarize_image(raw: dict[str, Any]) -> dict[str, Any]:
    tags = [tag for tag in _strings(raw.get("RepoTags")) if tag != "<none>:<none>"]
    digests = [d for d in _strings(raw.get("RepoDigests")) if not d.startswith("<none>@")]
    return {"id": str(raw.get("Id", ""))[:80], "repo_tags": tags, "repo_digests": digests}


def _sum(items: object, key: str) -> int:
    if not isinstance(items, list):
        return 0
    return sum(_int(item.get(key)) for item in items if isinstance(item, dict))


def summarize_df(raw: dict[str, Any]) -> dict[str, int]:
    volumes_size = 0
    for item in raw.get("Volumes") or []:
        usage = item.get("UsageData") if isinstance(item, dict) else None
        if isinstance(usage, dict):
            volumes_size += max(_int(usage.get("Size")), 0)
    return {
        "layers_size": _int(raw.get("LayersSize")),
        "images_size": _sum(raw.get("Images"), "Size"),
        "containers_size": _sum(raw.get("Containers"), "SizeRw"),
        "volumes_size": volumes_size,
        "build_cache_size": _sum(raw.get("BuildCache"), "Size"),
    }
