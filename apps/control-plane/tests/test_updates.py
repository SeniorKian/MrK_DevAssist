"""Gate 18 S10: image update tracking (docs/31 §5)."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.auth import ROLE_PERMISSIONS
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import updates
from mrk_control_plane.modules.host_agent import AgentError
from mrk_control_plane.modules.updates_refs import (
    MANIFEST_ACCEPT,
    InvalidReference,
    is_ignored,
    local_digests,
    parse_challenge,
    parse_rate_limit,
    parse_reference,
)
from mrk_control_plane.modules.updates_registry import RegistryChecker
from mrk_control_plane.modules.updates_settings import (
    DEFAULT_SETTINGS,
    SettingsError,
    endpoints_for,
    validate_settings,
)
from mrk_control_plane.netresolve import NetworkSettingsStore
from mrk_control_plane.secret_store import SecretStore

from .helpers import login_owner

PASSWORD = "a-long-role-password-123"  # noqa: S105 - test-only fixture
D_OLD = "sha256:" + "a" * 64
D_NEW = "sha256:" + "b" * 64
D_PIN = "sha256:" + "c" * 64
HUB_CHALLENGE = (
    'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",'
    'scope="repository:library/nginx:pull"'
)


# ----- reference parsing --------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "registry", "repository", "tag", "digest"),
    [
        ("nginx", "docker.io", "library/nginx", "latest", None),
        ("nginx:1.27-alpine", "docker.io", "library/nginx", "1.27-alpine", None),
        ("library/nginx", "docker.io", "library/nginx", "latest", None),
        ("docker.io/nginx", "docker.io", "library/nginx", "latest", None),
        ("index.docker.io/library/redis:7", "docker.io", "library/redis", "7", None),
        ("registry-1.docker.io/bitnami/redis", "docker.io", "bitnami/redis", "latest", None),
        ("traefik/whoami:v1.10", "docker.io", "traefik/whoami", "v1.10", None),
        ("ghcr.io/owner/app:2.0", "ghcr.io", "owner/app", "2.0", None),
        ("quay.io/a/b/c", "quay.io", "a/b/c", "latest", None),
        ("localhost/app", "localhost", "app", "latest", None),
        ("localhost:5000/team/app:dev", "localhost:5000", "team/app", "dev", None),
        ("registry.lan:5000/app", "registry.lan:5000", "app", "latest", None),
        ("GHCR.IO/owner/app", "ghcr.io", "owner/app", "latest", None),
        (f"nginx@{D_PIN}", "docker.io", "library/nginx", "latest", D_PIN),
        (f"ghcr.io/o/a:1.0@{D_PIN}", "ghcr.io", "o/a", "1.0", D_PIN),
    ],
)
def test_parse_reference_table(raw, registry, repository, tag, digest) -> None:
    ref = parse_reference(raw)
    assert (ref.registry, ref.repository, ref.tag, ref.digest) == (
        registry,
        repository,
        tag,
        digest,
    )
    assert ref.pinned is (digest is not None)


@pytest.mark.parametrize(
    "raw",
    ["", "  ", "sha256:" + "d" * 64, "d" * 64, "Nginx", "nginx:", "nginx@sha256:short",
     "a b", "ghcr.io/", "nginx:bad/tag", "-bad/name", "x" * 600],
)
def test_parse_reference_rejects(raw) -> None:
    with pytest.raises(InvalidReference):
        parse_reference(raw)


def test_familiar_and_ignore_forms() -> None:
    hub = parse_reference("nginx:1.27")
    assert hub.familiar == "nginx" and hub.canonical == "docker.io/library/nginx:1.27"
    assert parse_reference("ghcr.io/o/a").familiar == "ghcr.io/o/a"
    assert is_ignored(hub, ["nginx:*"])
    assert is_ignored(hub, ["docker.io/library/*"])
    assert is_ignored(hub, ["library/nginx"])
    assert not is_ignored(hub, ["redis*", "ghcr.io/*"])
    assert is_ignored(parse_reference("ghcr.io/o/a:1"), ["ghcr.io/*"])
    assert not is_ignored(parse_reference("ghcr.io/o/a:1"), ["GHCR.IO/*"])  # case-sensitive


def test_local_digests_match_registry_and_repository() -> None:
    ref = parse_reference("nginx:latest")
    repo_digests = [
        f"nginx@{D_OLD}",
        f"docker.io/library/nginx@{D_OLD}",  # same digest, other spelling: once
        f"docker.arvancloud.ir/library/nginx@{D_NEW}",  # other registry
        f"bitnami/nginx@{D_PIN}",  # other repository
        "garbage",
        f"nginx@sha256:{'z' * 64}",
    ]
    assert local_digests(ref, repo_digests) == [D_OLD]
    mirror_ref = parse_reference("docker.arvancloud.ir/library/nginx")
    assert local_digests(mirror_ref, repo_digests) == [D_NEW]


def test_challenge_and_rate_limit_parsing() -> None:
    scheme, params = parse_challenge(HUB_CHALLENGE)
    assert scheme == "bearer"
    assert params == {
        "realm": "https://auth.docker.io/token",
        "service": "registry.docker.io",
        "scope": "repository:library/nginx:pull",
    }
    _, quoted = parse_challenge('Bearer realm="https://a/t",scope="repository:x:pull,push"')
    assert quoted["scope"] == "repository:x:pull,push"
    assert parse_challenge('Basic realm="Registry"') == ("basic", {"realm": "Registry"})
    assert parse_challenge(None) is None
    assert parse_rate_limit(
        {
            "RateLimit-Limit": "100;w=21600",
            "ratelimit-remaining": "76;w=21600",
            "docker-ratelimit-source": "203.0.113.9",
        }
    ) == {"limit": 100, "remaining": 76, "window_seconds": 21600, "source": "203.0.113.9"}
    assert parse_rate_limit({"content-type": "x"}) is None


# ----- settings -----------------------------------------------------------------------


def test_settings_defaults_merge_and_validation() -> None:
    value = validate_settings({})
    assert value["enabled"] is True and value["interval_hours"] == 12
    assert value["ignore"] == [] and value["include_stopped"] is False
    merged = validate_settings(
        {
            "mirrors": {
                "index.docker.io": "docker.arvancloud.ir",
                "ghcr.io": ["https://registry.example.com/ghcr.io/", "http://10.0.0.5:5000"],
            },
            "ignore": ["nginx:*", "nginx:*"],
            "insecure_registries": ["registry.lan:5000"],
            "registry_proxies": {"ghcr.io": "default"},
        }
    )
    assert merged["mirrors"] == {
        "docker.io": ["docker.arvancloud.ir"],
        "ghcr.io": ["registry.example.com/ghcr.io", "http://10.0.0.5:5000"],
    }
    assert merged["ignore"] == ["nginx:*"]
    again = validate_settings({"interval_hours": 6}, base=merged)
    assert again["mirrors"] == merged["mirrors"] and again["interval_hours"] == 6
    for bad in (
        {"interval_hours": 0},
        {"interval_hours": True},
        {"enabled": "yes"},
        {"ignore": "nginx"},
        {"ignore": [""]},
        {"mirrors": {"docker.io": ["ftp://x"]}},
        {"mirrors": {"docker.io": ["https://user:pw@m.example"]}},
        {"mirrors": {"bad host": ["m.example"]}},
        {"mirrors": {"docker.io": ["https://m.example/v2"]}},
        {"proxy_id": "not valid!"},
        {"insecure_registries": ["docker.io"]},
        {"unknown": 1},
    ):
        with pytest.raises(SettingsError):
            validate_settings(bad)
    with pytest.raises(SettingsError):
        validate_settings([])


def test_mirror_endpoint_mapping() -> None:
    settings = validate_settings(
        {
            "mirrors": {
                "docker.io": ["docker.arvancloud.ir", "https://hub.example.com/dockerhub"],
                "ghcr.io": ["http://registry.lan:5000/ghcr.io"],
            }
        }
    )
    hub = endpoints_for("docker.io", settings)
    assert [endpoint.label for endpoint in hub] == [
        "docker.arvancloud.ir",
        "hub.example.com/dockerhub",
        "registry-1.docker.io",
    ]
    assert hub[0].manifest_url("library/nginx", "latest") == (
        "https://docker.arvancloud.ir/v2/library/nginx/manifests/latest"
    )
    assert hub[1].manifest_url("library/nginx", "1") == (
        "https://hub.example.com/v2/dockerhub/library/nginx/manifests/1"
    )
    ghcr = endpoints_for("ghcr.io", settings)
    assert ghcr[0].manifest_url("o/a", "v1") == "http://registry.lan:5000/v2/ghcr.io/o/a/manifests/v1"
    no_fallback = validate_settings({"mirror_fallback": False}, base=settings)
    assert [e.label for e in endpoints_for("docker.io", no_fallback)][-1] == (
        "hub.example.com/dockerhub"
    )
    assert [e.label for e in endpoints_for("quay.io", no_fallback)] == ["quay.io"]
    insecure = validate_settings({"insecure_registries": ["registry.lan:5000"]})
    assert endpoints_for("registry.lan:5000", insecure)[0].scheme == "http"


# ----- registry checker (httpx MockTransport) -------------------------------------------


class Registry:
    """A fake set of registries keyed by Host header."""

    def __init__(self) -> None:
        self.manifests: dict[tuple[str, str, str], str] = {}  # (host, repo, tag) -> digest
        self.anonymous: set[str] = set()  # hosts that do not require a token
        self.requests: list[httpx.Request] = []
        self.token_requests: list[httpx.Request] = []
        self.status: dict[str, int] = {}  # host -> forced status
        self.rate_headers = {"ratelimit-limit": "100;w=21600", "ratelimit-remaining": "99;w=21600"}
        self.no_digest_header: set[str] = set()

    def handler(self, request: httpx.Request) -> httpx.Response:
        host = request.headers.get("host") or request.url.host
        if host == "auth.docker.io":
            self.token_requests.append(request)
            return httpx.Response(200, json={"token": "tok-1", "expires_in": 300})
        self.requests.append(request)
        if host in self.status:
            return httpx.Response(self.status[host])
        path = request.url.path
        assert path.startswith("/v2/") and "/manifests/" in path
        repo, tag = path[4:].split("/manifests/")
        if host not in self.anonymous and request.headers.get("authorization") != "Bearer tok-1":
            return httpx.Response(401, headers={"www-authenticate": HUB_CHALLENGE.replace(
                "library/nginx", repo)})
        digest = self.manifests.get((host, repo, tag))
        if digest is None:
            return httpx.Response(404)
        headers = {"content-type": "application/vnd.oci.image.index.v1+json"}
        if host not in self.no_digest_header:
            headers["docker-content-digest"] = digest
        if host == "registry-1.docker.io":
            headers.update(self.rate_headers)
        body = b'{"schemaVersion":2}' if request.method == "GET" else b""
        return httpx.Response(200, headers=headers, content=body)


class PlainSender:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    async def send(self, method, url, *, headers=None, content=None, stream=False):
        request = self.client.build_request(method, url, headers=headers, content=content)
        return await self.client.send(request, stream=stream)


def run_checker(registry: Registry, settings: dict[str, Any], refs: list[str], **kwargs):
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(registry.handler)) as client:
            sender = PlainSender(client)
            seen_refs: list[str | None] = []

            async def client_for(proxy_ref):
                seen_refs.append(proxy_ref)
                if kwargs.get("fail_proxy"):
                    from mrk_control_plane.outbound import ProxyUnavailable

                    raise ProxyUnavailable()
                return sender

            checker = RegistryChecker(settings, client_for)
            results = [await checker.check(parse_reference(ref)) for ref in refs]
            return checker, results, seen_refs

    return asyncio.run(scenario())


def test_token_flow_head_accept_and_token_cache() -> None:
    registry = Registry()
    registry.manifests[("registry-1.docker.io", "library/nginx", "latest")] = D_NEW
    registry.manifests[("registry-1.docker.io", "library/nginx", "alpine")] = D_OLD
    checker, results, _ = run_checker(
        registry, validate_settings({}), ["nginx", "nginx:alpine"]
    )
    assert [result.digest for result in results] == [D_NEW, D_OLD]
    assert results[0].media_type == "application/vnd.oci.image.index.v1+json"
    assert results[0].endpoint == "registry-1.docker.io"
    assert all(request.method == "HEAD" for request in registry.requests)
    assert registry.requests[0].headers["accept"] == MANIFEST_ACCEPT
    for media_type in ("oci.image.index", "manifest.list.v2", "oci.image.manifest",
                       "distribution.manifest.v2"):
        assert media_type in MANIFEST_ACCEPT
    (token_request,) = registry.token_requests  # the second tag reuses the token
    assert token_request.url.params["service"] == "registry.docker.io"
    assert token_request.url.params["scope"] == "repository:library/nginx:pull"
    assert "authorization" not in token_request.headers
    # 401 -> token -> retry, then the cached token goes on the first try.
    assert [r.headers.get("authorization") for r in registry.requests] == [
        None, "Bearer tok-1", "Bearer tok-1"]
    assert checker.rate_limits["registry-1.docker.io"]["remaining"] == 99
    assert checker.rate_limits["registry-1.docker.io"]["window_seconds"] == 21600


def test_registry_error_codes() -> None:
    registry = Registry()
    registry.anonymous = {"ghcr.io", "quay.io", "registry.gitlab.com", "docker.example.org"}
    registry.status = {"quay.io": 429, "registry.gitlab.com": 503}
    _, results, _ = run_checker(
        registry,
        validate_settings({}),
        ["ghcr.io/o/missing", "quay.io/a/b", "registry.gitlab.com/x/y"],
    )
    assert [(r.error_code, r.error_detail) for r in results] == [
        ("not_found", "manifest_unknown"),
        ("rate_limited", "http_429"),
        ("unreachable", "http_503"),
    ]

    def basic(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, headers={"www-authenticate": 'Basic realm="x"'})

    async def basic_scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(basic)) as client:
            async def client_for(_ref):
                return PlainSender(client)

            return await RegistryChecker(validate_settings({}), client_for).check(
                parse_reference("private.example.com/team/app")
            )

    assert asyncio.run(basic_scenario()).error_code == "auth_required"

    def failing(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    async def failing_scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(failing)) as client:
            async def client_for(_ref):
                return PlainSender(client)

            return await RegistryChecker(validate_settings({}), client_for).check(
                parse_reference("ghcr.io/o/a")
            )

    result = asyncio.run(failing_scenario())
    assert (result.error_code, result.error_detail) == ("unreachable", "connect_failed")

    _, (proxied,), refs = run_checker(
        registry, validate_settings({"proxy_id": "default"}), ["ghcr.io/o/a"], fail_proxy=True
    )
    assert proxied.error_code == "proxy_unavailable" and refs == ["default"]


def test_token_denied_is_auth_required() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "auth.docker.io":
            return httpx.Response(401)
        return httpx.Response(401, headers={"www-authenticate": HUB_CHALLENGE})

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            async def client_for(_ref):
                return PlainSender(client)

            return await RegistryChecker(validate_settings({}), client_for).check(
                parse_reference("nginx")
            )

    result = asyncio.run(scenario())
    assert (result.error_code, result.error_detail) == ("auth_required", "token_http_401")


def test_mirror_first_then_origin_fallback_and_proxy_choice() -> None:
    registry = Registry()
    registry.anonymous = {"docker.arvancloud.ir"}
    registry.manifests[("docker.arvancloud.ir", "library/nginx", "latest")] = D_NEW
    registry.manifests[("registry-1.docker.io", "library/redis", "7")] = D_OLD
    settings = validate_settings(
        {
            "mirrors": {"docker.io": ["docker.arvancloud.ir"]},
            "proxy_id": "default",
            "registry_proxies": {"docker.arvancloud.ir": None},
        }
    )
    _, (nginx, redis), proxies = run_checker(registry, settings, ["nginx", "redis:7"])
    assert nginx.digest == D_NEW and nginx.endpoint == "docker.arvancloud.ir"
    # redis is not on the mirror (404) -> origin answers.
    assert redis.digest == D_OLD and redis.endpoint == "registry-1.docker.io"
    # Mirror goes direct (override), the origin through the default proxy.
    assert proxies == [None, None, "default"]
    hosts = [request.headers["host"] for request in registry.requests]
    assert hosts[0] == "docker.arvancloud.ir"

    registry.requests.clear()
    strict = validate_settings({"mirror_fallback": False}, base=settings)
    _, (only_mirror,), _ = run_checker(registry, strict, ["redis:7"])
    assert only_mirror.error_code == "not_found"
    assert {request.headers["host"] for request in registry.requests} == {"docker.arvancloud.ir"}


def test_get_fallback_hashes_body_but_never_on_docker_hub() -> None:
    registry = Registry()
    registry.anonymous = {"registry.example.com", "registry-1.docker.io"}
    registry.no_digest_header = {"registry.example.com", "registry-1.docker.io"}
    registry.manifests[("registry.example.com", "app", "latest")] = "unused"
    registry.manifests[("registry-1.docker.io", "library/nginx", "latest")] = "unused"
    _, (other, hub), _ = run_checker(
        registry, validate_settings({}), ["registry.example.com/app", "nginx"]
    )
    import hashlib

    assert other.digest == "sha256:" + hashlib.sha256(b'{"schemaVersion":2}').hexdigest()
    assert hub.error_code == "digest_unavailable"
    assert [r.method for r in registry.requests if r.headers["host"] == "registry-1.docker.io"] == [
        "HEAD"
    ]


# ----- service: comparison, pinned, ignore, stopped, events ---------------------------------


class FakeAgent:
    def __init__(self, containers, images=None, *, images_supported=True) -> None:
        self.containers = containers
        self.images = images or []
        self.images_supported = images_supported
        self.configured = True

    def resolve(self):
        return ("panel", "http://agent:8080", b"k") if self.configured else (None, None, None)

    async def call(self, path: str):
        if path == "/v1/docker/containers":
            return {"items": self.containers}
        if path == "/v1/docker/images":
            if not self.images_supported:
                raise AgentError("agent_not_found", 404, "missing")
            return {"items": self.images}
        raise AssertionError(path)


class Recorder:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def publish(self, event) -> None:
        self.events.append(event)


def container(name, image, image_id=None, state="running", protected=False):
    payload = {"name": name, "image": image, "state": state, "protected": protected}
    if image_id:
        payload["image_id"] = image_id
    return payload


def image(image_id, tags, digests):
    return {"id": image_id, "repo_tags": tags, "repo_digests": digests}


@pytest.fixture
def mock_registry(monkeypatch):
    registry = Registry()
    monkeypatch.setattr(updates, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(registry.handler))
    monkeypatch.setattr(updates, "RESOLVER", lambda host, port, config: ["93.184.216.34"])
    return registry


def make_service(tmp_path: Path, agent: FakeAgent) -> tuple[updates.UpdatesService, Recorder]:
    events = Recorder()
    ctx = SimpleNamespace(
        data_dir=tmp_path,
        network_settings=NetworkSettingsStore(tmp_path),
        secret_store=SecretStore(tmp_path),
        events=events,
    )
    return updates.UpdatesService(ctx, agent=agent), events  # type: ignore[arg-type]


def by_image(view: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["reference"]: item for item in view["items"]}


def test_service_compares_digests_through_outbound(tmp_path: Path, mock_registry) -> None:
    mock_registry.anonymous = {"ghcr.io"}
    mock_registry.manifests.update(
        {
            ("registry-1.docker.io", "library/nginx", "latest"): D_NEW,
            ("registry-1.docker.io", "library/redis", "7"): D_OLD,
            ("ghcr.io", "o/app", "1"): D_NEW,
        }
    )
    agent = FakeAgent(
        [
            container("web", "nginx:latest", "sha256:img1"),
            container("web2", "nginx", "sha256:img1", protected=True),
            container("cache", "redis:7", "sha256:img2"),
            container("app", "ghcr.io/o/app:1"),  # no image_id -> matched by RepoTags
            container("pinned", f"postgres:16@{D_PIN}"),
            container("old", "busybox", state="exited"),
            container("weird", "sha256:" + "e" * 64),
        ],
        [
            image("sha256:img1", ["nginx:latest"], [f"nginx@{D_OLD}"]),
            image("sha256:img2", ["redis:7"], [f"redis@{D_OLD}"]),
            image("sha256:img3", ["ghcr.io/o/app:1"], [f"ghcr.io/o/app@{D_NEW}"]),
        ],
    )
    service, events = make_service(tmp_path, agent)
    assert asyncio.run(service.run_check()) == {"ok": True, "images": 5}
    view = service.images_view()
    items = by_image(view)
    assert "docker.io/library/busybox:latest" not in items  # stopped, include_stopped false
    nginx = items["docker.io/library/nginx:latest"]
    assert nginx["update_available"] is True and nginx["status"] == "update_available"
    assert (nginx["current_digest"], nginx["latest_digest"]) == (D_OLD, D_NEW)
    assert (nginx["image"], nginx["tag"], nginx["registry"]) == ("nginx", "latest", "docker.io")
    assert nginx["containers"] == [
        {"name": "web", "protected": False, "state": "running"},
        {"name": "web2", "protected": True, "state": "running"},
    ]
    assert nginx["checked_at"] and nginx["error_code"] is None
    redis = items["docker.io/library/redis:7"]
    assert redis["update_available"] is False and redis["status"] == "up_to_date"
    assert items["ghcr.io/o/app:1"]["status"] == "up_to_date"
    pinned = items[f"docker.io/library/postgres:16@{D_PIN}"]
    assert pinned["status"] == "pinned" and pinned["update_available"] is False
    assert pinned["current_digest"] == D_PIN and pinned["latest_digest"] is None
    weird = items["sha256:" + "e" * 64]
    assert weird["error_code"] == "invalid_reference" and weird["update_available"] is None
    # The pinned image never reached a registry.
    assert not any("postgres" in r.url.path for r in mock_registry.requests)
    # Requests were pinned to the vetted address but kept the real Host header.
    assert {r.url.host for r in mock_registry.requests} == {"93.184.216.34"}
    assert view["rate_limits"]["registry-1.docker.io"]["remaining"] == 99
    assert view["summary"] == {"total": 5, "update_available": 1, "errors": 0}
    assert view["last_run_at"] and view["running"] is False

    (event,) = events.events
    assert event.type == "update.available" and event.severity == "info"
    assert event.dedupe_key == f"update.available:docker.io/library/nginx:latest@{D_NEW}"
    assert event.details["containers"] == ["web", "web2"]

    # Same digest again: no new event (persisted dedupe, also across restarts).
    asyncio.run(service.run_check())
    assert len(events.events) == 1
    restarted, restarted_events = make_service(tmp_path, agent)
    asyncio.run(restarted.run_check())
    assert restarted_events.events == []
    # A newer digest for the same tag notifies again.
    mock_registry.manifests[("registry-1.docker.io", "library/nginx", "latest")] = D_PIN
    asyncio.run(restarted.run_check())
    (second,) = restarted_events.events
    assert second.details["latest_digest"] == D_PIN
    stored = json.loads((tmp_path / "control-plane" / "updates.json").read_text("utf-8"))
    assert stored["notified"] == {"docker.io/library/nginx:latest": D_PIN}


def test_service_ignore_stopped_unknown_and_errors(tmp_path: Path, mock_registry) -> None:
    mock_registry.manifests[("registry-1.docker.io", "library/nginx", "latest")] = D_NEW
    mock_registry.manifests[("registry-1.docker.io", "library/busybox", "latest")] = D_NEW
    agent = FakeAgent(
        [
            container("web", "nginx", "sha256:img1"),
            container("old", "busybox", state="exited"),
            container("skip", "ghcr.io/o/skipme:1"),
            container("gone", "quay.io/a/missing"),
        ],
        images_supported=False,
    )
    mock_registry.anonymous = {"quay.io"}
    service, events = make_service(tmp_path, agent)
    service.save_settings({"include_stopped": True, "ignore": ["ghcr.io/o/skip*"]})
    asyncio.run(service.run_check())
    items = by_image(service.images_view())
    nginx = items["docker.io/library/nginx:latest"]
    # Agent without the images endpoint: remote digest known, local unknown.
    assert nginx["latest_digest"] == D_NEW and nginx["current_digest"] is None
    assert nginx["update_available"] is None and nginx["status"] == "unknown"
    assert nginx["error_detail"] == "agent_no_images"
    busybox = items["docker.io/library/busybox:latest"]
    assert busybox["containers"][0]["state"] == "exited"
    ignored = items["ghcr.io/o/skipme:1"]
    assert ignored["status"] == "ignored" and ignored["checked_at"] is None
    assert not any("skipme" in r.url.path for r in mock_registry.requests)
    missing = items["quay.io/a/missing:latest"]
    assert missing["status"] == "error" and missing["error_code"] == "not_found"
    assert events.events == []

    agent.configured = True
    failing = FakeAgent([])

    async def broken(_path):
        raise AgentError("agent_unreachable", 502, "down")

    failing.call = broken  # type: ignore[method-assign]
    service.agent = failing
    assert asyncio.run(service.run_check()) == {"ok": False, "error_code": "agent_unreachable"}
    view = service.images_view()
    assert view["last_error"] == "agent_unreachable" and len(view["items"]) == 4  # kept
    assert view["next_run_at"] <= view["last_attempt_at"] + updates.RETRY_SECONDS


def test_service_proxy_unavailable_per_image(tmp_path: Path, mock_registry) -> None:
    agent = FakeAgent([container("web", "nginx")], [])
    service, _ = make_service(tmp_path, agent)
    service.state["settings"] = validate_settings({"proxy_id": "abc123"})
    asyncio.run(service.run_check())
    (item,) = service.images_view()["items"]
    assert item["error_code"] == "proxy_unavailable" and item["status"] == "error"
    assert mock_registry.requests == []


def test_outbound_entries_and_set_proxy(tmp_path: Path) -> None:
    service, _ = make_service(tmp_path, FakeAgent([]))
    service.save_settings({"mirrors": {"docker.io": ["docker.arvancloud.ir"]}})
    service.state["items"] = [{"registry": "ghcr.io"}]
    entries = {entry["id"]: entry for entry in service.outbound_entries()}
    assert set(entries) == {"default", "docker.io", "ghcr.io", "docker.arvancloud.ir"}
    assert entries["docker.arvancloud.ir"]["group"] == "mirror"
    service.set_proxy("default", "default")
    service.set_proxy("docker.arvancloud.ir", None)
    settings = service.settings
    assert settings["proxy_id"] == "default"
    assert settings["registry_proxies"] == {"docker.arvancloud.ir": None}
    with pytest.raises(KeyError):
        service.set_proxy("unknown.example", None)


def test_next_run_schedule(tmp_path: Path) -> None:
    service, _ = make_service(tmp_path, FakeAgent([]))
    assert service.next_run_at() == 0.0  # never ran -> due immediately
    service.state["last_run_at"] = 1000.0
    assert service.next_run_at() == 1000.0 + 12 * 3600
    service.save_settings({"enabled": False})
    assert service.next_run_at() is None


# ----- API ----------------------------------------------------------------------------------


def role_client(owner: TestClient, headers: dict[str, str], role: str):
    created = owner.post(
        "/api/v1/users",
        headers=headers,
        json={"username": f"{role}1", "password": PASSWORD, "role": role},
    )
    assert created.status_code == 201, created.text
    client = TestClient(owner.app)
    login = client.post("/api/v1/auth/login", json={"username": f"{role}1", "password": PASSWORD})
    assert login.status_code == 200
    return client, {"X-CSRF-Token": str(login.json()["csrf_token"])}


def allowed(role: str, permission: str) -> bool:
    granted = ROLE_PERMISSIONS[role]
    return "*" in granted or permission in granted


def test_updates_api_rbac_check_and_settings(tmp_path: Path, monkeypatch, mock_registry) -> None:
    monkeypatch.delenv("MRK_AGENT_URL", raising=False)
    monkeypatch.delenv("MRK_AGENT_KEY_FILE", raising=False)
    mock_registry.manifests[("registry-1.docker.io", "library/nginx", "latest")] = D_NEW
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as owner:
        headers = {"X-CSRF-Token": str(login_owner(owner)["csrf_token"])}
        service = updates.ACTIVE_SERVICE
        assert service is not None
        agent = FakeAgent(
            [container("web", "nginx", "sha256:img1")],
            [image("sha256:img1", ["nginx:latest"], [f"nginx@{D_OLD}"])],
        )
        agent.configured = False
        service.agent = agent

        roles = {"owner": (owner, headers)}
        for role in ("admin", "operator", "developer", "viewer"):
            roles[role] = role_client(owner, headers, role)
        for role, (client, role_headers) in roles.items():
            can_read = allowed(role, "updates:read")
            can_write = allowed(role, "updates:write")
            for path in ("/api/v1/updates/images", "/api/v1/updates/settings"):
                assert client.get(path).status_code == (200 if can_read else 403), (role, path)
            put = client.put(
                "/api/v1/updates/settings", headers=role_headers, json={"interval_hours": 24}
            )
            assert put.status_code == (200 if can_write else 403), role
            check = client.post("/api/v1/updates/check", headers=role_headers)
            assert check.status_code == (409 if can_write else 403), role
        assert roles["owner"][0].get("/api/v1/updates/images").status_code == 200
        assert roles["viewer"][0].put(
            "/api/v1/updates/settings", headers=roles["viewer"][1], json={}
        ).status_code == 403
        anonymous = TestClient(app)
        assert anonymous.get("/api/v1/updates/images").status_code == 401
        assert owner.put("/api/v1/updates/settings", json={}).status_code == 403  # no CSRF
        assert owner.post("/api/v1/updates/check").status_code == 403  # no CSRF

        settings = owner.get("/api/v1/updates/settings").json()
        assert settings["interval_hours"] == 24 and settings["include_stopped"] is False
        bad = owner.put(
            "/api/v1/updates/settings", headers=headers, json={"interval_hours": 0}
        )
        assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_settings"
        missing_proxy = owner.put(
            "/api/v1/updates/settings", headers=headers, json={"proxy_id": "abc123"}
        )
        assert missing_proxy.json()["error"]["code"] == "proxy_not_found"
        assert owner.put(
            "/api/v1/updates/settings", headers=headers, content=b"{nope"
        ).status_code == 422
        mirrors = owner.put(
            "/api/v1/updates/settings",
            headers=headers,
            json={"mirrors": {"docker.io": "docker.arvancloud.ir"}, "ignore": ["redis*"]},
        )
        assert mirrors.json()["mirrors"] == {"docker.io": ["docker.arvancloud.ir"]}

        # Manual check -> 202, runs in the background on the app loop.
        mock_registry.anonymous = {"docker.arvancloud.ir"}
        mock_registry.manifests[("docker.arvancloud.ir", "library/nginx", "latest")] = D_NEW
        agent.configured = True
        started = owner.post("/api/v1/updates/check", headers=headers)
        assert started.status_code == 202 and started.json()["running"] is True
        deadline = time.time() + 10
        view = owner.get("/api/v1/updates/images").json()
        while (view["running"] or not view["items"]) and time.time() < deadline:
            time.sleep(0.05)
            view = owner.get("/api/v1/updates/images").json()
        (item,) = view["items"]
        assert item["update_available"] is True and item["endpoint"] == "docker.arvancloud.ir"
        assert set(item) >= {"image", "tag", "registry", "current_digest", "latest_digest",
                             "update_available", "checked_at", "error_code", "containers"}
        assert view["last_run_at"]

        # The registry checks show up in the central "service -> proxy" table.
        services = owner.get("/api/v1/settings/outbound-services").json()["items"]
        registry_ids = {entry["id"] for entry in services if entry["kind"] == "registry"}
        assert {"default", "docker.io", "docker.arvancloud.ir"} <= registry_ids
        no_default = owner.put(
            "/api/v1/settings/outbound-services/registry/default",
            headers=headers,
            json={"proxy_id": "default"},
        )
        assert no_default.status_code in (409, 422)
        direct = owner.put(
            "/api/v1/settings/outbound-services/registry/docker.arvancloud.ir",
            headers=headers,
            json={"proxy_id": None},
        )
        assert direct.status_code == 200, direct.text
        assert owner.get("/api/v1/updates/settings").json()["registry_proxies"] == {
            "docker.arvancloud.ir": None
        }
        viewer, viewer_headers = roles["viewer"]
        assert viewer.put(
            "/api/v1/settings/outbound-services/registry/default",
            headers=viewer_headers,
            json={"proxy_id": None},
        ).status_code == 403


def test_default_settings_constant_is_valid() -> None:
    assert validate_settings({}) == DEFAULT_SETTINGS
