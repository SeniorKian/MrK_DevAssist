from __future__ import annotations

import ipaddress
import json
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ALLOWED_ENVIRONMENTS = {"development", "test", "production"}
ALLOWED_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

# ---- startup overrides (settings registry, docs/27 §1.6) ---------------------
#
# Precedence for a startup (environment) setting: an explicit environment
# variable wins, then data_dir/control-plane/settings-overrides.json (written by
# the "All settings" screen), then the code default. Values baked into the
# appliance image (Dockerfile ENV) count as defaults, not as operator choices.

OVERRIDES_FILE = "settings-overrides.json"
# Names that locate the overrides file itself; they can only come from the environment.
BOOTSTRAP_ENV_NAMES = frozenset({"MRK_ENV", "MRK_DATA_DIR"})
# Dockerfile ENV defaults (deploy/images/Dockerfile). An environment value equal
# to one of these is treated as "default", so a panel override still applies.
IMAGE_ENV_DEFAULTS: dict[str, str] = {
    "MRK_ADMIN_UI_DIR": "/opt/mrk/admin-ui",
    "MRK_NPM_ENABLED": "true",
    "MRK_NPM_HEALTH_PORT": "4873",
    "MRK_PYPI_ENABLED": "true",
    "MRK_PYPI_HEALTH_PORT": "3141",
    "MRK_PYPI_SERVER_DIR": "/data/pypi/server",
    "MRK_PYPI_BOOTSTRAP_STATE_FILE": "/data/pypi/auth/upstream-configured",
    "MRK_PYPI_UPSTREAM_URL": "http://127.0.0.1:3142/simple/",
    "MRK_PYPI_PRIMARY_UPSTREAM": "https://pypi.org/simple/",
    "MRK_PYPI_FALLBACK_UPSTREAM": "https://package-mirror.liara.ir/repository/pypi/simple/",
    "MRK_PYPI_ROUTER_PORT": "3142",
    "MRK_PYPI_ROUTER_HEALTH_HOST": "127.0.0.1",
    "MRK_PYPI_ROUTER_READ_TIMEOUT": "90",
    "MRK_PYPI_REQUEST_TIMEOUT": "900",
    "MRK_AUTH_COOKIE_SECURE": "true",
    "MRK_SESSION_TTL_SECONDS": "43200",
    "MRK_HOST": "0.0.0.0",  # noqa: S104 - container listener default
    "MRK_PORT": "8080",
}
# Names this process injected into os.environ from the overrides file at start.
INJECTED_ENV_NAMES: set[str] = set()
_OVERRIDES_CACHE: dict[str, tuple[tuple[int, int], dict[str, str]]] = {}
_OVERRIDES_LOCK = threading.Lock()


def default_data_dir() -> Path:
    """The data directory as derived from the environment only (MRK_DATA_DIR/MRK_ENV)."""
    configured = os.getenv("MRK_DATA_DIR", "").strip()
    if configured:
        return Path(configured).resolve()
    environment = os.getenv("MRK_ENV", "development").strip().lower()
    return Path("/data") if environment == "production" else (Path.cwd() / ".data").resolve()


def overrides_path(data_dir: Path | None = None) -> Path:
    return (data_dir or default_data_dir()) / "control-plane" / OVERRIDES_FILE


def load_overrides(path: Path | None = None) -> dict[str, str]:
    """Read the overrides file ({"values": {name: text}}); missing or broken -> {}."""
    target = path or overrides_path()
    try:
        info = target.stat()
    except OSError:
        return {}
    stamp = (info.st_mtime_ns, info.st_size)
    key = str(target)
    with _OVERRIDES_LOCK:
        cached = _OVERRIDES_CACHE.get(key)
        if cached is not None and cached[0] == stamp:
            return dict(cached[1])
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    raw = payload.get("values") if isinstance(payload, dict) else None
    values = {
        str(name): str(value)
        for name, value in (raw.items() if isinstance(raw, dict) else ())
        if isinstance(name, str)
        and name.startswith("MRK_")
        and name not in BOOTSTRAP_ENV_NAMES
        and isinstance(value, str | int | float | bool)
    }
    with _OVERRIDES_LOCK:
        _OVERRIDES_CACHE[key] = (stamp, values)
    return dict(values)


def explicit_env(name: str) -> str | None:
    """The operator's own environment value, or None (unset, injected or image default)."""
    value = os.environ.get(name)
    if value is None or name in INJECTED_ENV_NAMES:
        return None
    if name in IMAGE_ENV_DEFAULTS and value == IMAGE_ENV_DEFAULTS[name]:
        return None
    return value


def resolve_env(
    name: str, default: str | None = None, *, overrides: dict[str, str] | None = None
) -> tuple[str | None, str]:
    """(value, source) where source is env | override | image | default."""
    value = explicit_env(name)
    if value is not None:
        return value, "env"
    values = load_overrides() if overrides is None else overrides
    if name in values and name not in BOOTSTRAP_ENV_NAMES:
        return values[name], "override"
    if name in IMAGE_ENV_DEFAULTS and os.environ.get(name) == IMAGE_ENV_DEFAULTS[name]:
        return IMAGE_ENV_DEFAULTS[name], "image"
    return default, "default"


def setting_env(name: str, default: str | None = None) -> str | None:
    """Drop-in for os.getenv honoring the overrides file (env > override > default)."""
    return resolve_env(name, default)[0]


def apply_startup_overrides(data_dir: Path | None = None) -> set[str]:
    """Copy override values into os.environ for names the operator did not set.

    Called once at process start so readers that still use os.getenv directly
    (modules, auth, child processes) honor the panel's startup overrides.
    """
    applied: set[str] = set()
    for name, value in load_overrides(overrides_path(data_dir)).items():
        if explicit_env(name) is None:
            os.environ[name] = value
            INJECTED_ENV_NAMES.add(name)
            applied.add(name)
    return applied


EnvLookup = Callable[[str, str | None], str | None]
_LOOKUP: list[EnvLookup] = []


def _getenv(name: str, default: str = "") -> str:
    lookup = _LOOKUP[-1] if _LOOKUP else setting_env
    value = lookup(name, default)
    return default if value is None else value


def database_url_with_password(url: str | None, password_file: str | None) -> str | None:
    """Put the password from ``MRK_DATABASE_PASSWORD_FILE`` into the URL.

    The compose stack generates the PostgreSQL password once into a file shared
    by the database and the panel; it never appears in an environment variable.
    A URL that already has a password is left alone.
    """
    if not url or not password_file:
        return url
    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    if parsed.password:
        return url
    try:
        password = Path(password_file).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError("MRK_DATABASE_PASSWORD_FILE cannot be read") from exc
    if not password:
        raise ValueError("MRK_DATABASE_PASSWORD_FILE is empty")
    return parsed.set(password=password).render_as_string(hide_password=False)


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _boolean(name: str, default: bool) -> bool:
    value = _getenv(name, str(default)).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(_getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _port(name: str, default: int) -> int:
    try:
        value = int(_getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not 1 <= value <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str
    data_dir: Path
    database_url: str | None
    log_level: str
    cors_origins: tuple[str, ...]
    trusted_hosts: tuple[str, ...]
    admin_ui_dir: Path | None = None
    npm_enabled: bool = False
    npm_health_host: str = "127.0.0.1"
    npm_health_port: int = 4873
    pypi_enabled: bool = False
    pypi_health_host: str = "127.0.0.1"
    pypi_health_port: int = 3141
    pypi_bootstrap_state_file: Path | None = None
    pypi_router_health_host: str = "127.0.0.1"
    pypi_router_health_port: int = 3142
    auth_cookie_secure: bool = True
    # Idle window (sliding); "keep me signed in" uses the longer remember window;
    # nobody stays signed in past the maximum age.
    session_ttl_seconds: int = 43200
    session_remember_ttl_seconds: int = 7 * 86400
    session_max_age_seconds: int = 30 * 86400
    build_commit: str = "unknown"
    build_date: str = "unknown"
    host: str = "0.0.0.0"  # noqa: S104 - required inside the container network namespace
    port: int = 8080
    login_rate_limit_attempts: int = 5
    login_rate_limit_window_seconds: int = 300
    session_prune_age_seconds: int = 7 * 86400
    npm_block_poll_seconds: int = 30

    @classmethod
    def from_env(cls, lookup: EnvLookup | None = None) -> Settings:
        """Build settings from env > overrides file > defaults (or a custom lookup)."""
        if lookup is not None:
            _LOOKUP.append(lookup)
            try:
                return cls.from_env()
            finally:
                _LOOKUP.pop()
        environment = _getenv("MRK_ENV", "development").strip().lower()
        log_level = _getenv("MRK_LOG_LEVEL", "INFO").strip().upper()
        cors_origins = _csv(_getenv("MRK_CORS_ORIGINS", "http://localhost:8080"))
        trusted_hosts = _csv(_getenv("MRK_TRUSTED_HOSTS", "localhost,127.0.0.1"))
        npm_health_host = _getenv("MRK_NPM_HEALTH_HOST", "127.0.0.1").strip()
        pypi_health_host = _getenv("MRK_PYPI_HEALTH_HOST", "127.0.0.1").strip()
        pypi_router_health_host = _getenv(
            "MRK_PYPI_ROUTER_HEALTH_HOST", "127.0.0.1"
        ).strip()
        configured_data_dir = _getenv("MRK_DATA_DIR", "").strip()

        if environment not in ALLOWED_ENVIRONMENTS:
            raise ValueError("MRK_ENV must be development, test, or production")
        if log_level not in ALLOWED_LOG_LEVELS:
            raise ValueError("MRK_LOG_LEVEL is invalid")
        if not trusted_hosts:
            raise ValueError("MRK_TRUSTED_HOSTS must contain at least one host")
        if environment == "production" and "*" in trusted_hosts:
            raise ValueError("wildcard trusted hosts are forbidden in production")
        if environment == "production" and "*" in cors_origins:
            raise ValueError("wildcard CORS origins are forbidden in production")
        try:
            session_ttl_seconds = int(_getenv("MRK_SESSION_TTL_SECONDS", "43200"))
        except ValueError as exc:
            raise ValueError("MRK_SESSION_TTL_SECONDS must be an integer") from exc
        if not 900 <= session_ttl_seconds <= 2592000:
            raise ValueError("MRK_SESSION_TTL_SECONDS must be between 900 and 2592000")
        try:
            npm_health_address = ipaddress.ip_address(npm_health_host)
        except ValueError as exc:
            raise ValueError("MRK_NPM_HEALTH_HOST must be a loopback IP address") from exc
        if not npm_health_address.is_loopback:
            raise ValueError("MRK_NPM_HEALTH_HOST must be a loopback IP address")
        try:
            pypi_health_address = ipaddress.ip_address(pypi_health_host)
        except ValueError as exc:
            raise ValueError("MRK_PYPI_HEALTH_HOST must be a loopback IP address") from exc
        if not pypi_health_address.is_loopback:
            raise ValueError("MRK_PYPI_HEALTH_HOST must be a loopback IP address")
        try:
            pypi_router_health_address = ipaddress.ip_address(pypi_router_health_host)
        except ValueError as exc:
            raise ValueError(
                "MRK_PYPI_ROUTER_HEALTH_HOST must be a loopback IP address"
            ) from exc
        if not pypi_router_health_address.is_loopback:
            raise ValueError("MRK_PYPI_ROUTER_HEALTH_HOST must be a loopback IP address")

        return cls(
            environment=environment,
            data_dir=(
                Path(configured_data_dir).resolve()
                if configured_data_dir
                else (
                    Path("/data")
                    if environment == "production"
                    else (Path.cwd() / ".data").resolve()
                )
            ),
            database_url=database_url_with_password(
                _getenv("MRK_DATABASE_URL", "").strip() or None,
                _getenv("MRK_DATABASE_PASSWORD_FILE", "").strip() or None,
            ),
            log_level=log_level,
            cors_origins=cors_origins,
            trusted_hosts=trusted_hosts,
            admin_ui_dir=(
                Path(value).resolve()
                if (value := _getenv("MRK_ADMIN_UI_DIR", "").strip())
                else None
            ),
            npm_enabled=_boolean("MRK_NPM_ENABLED", False),
            npm_health_host=npm_health_host,
            npm_health_port=_port("MRK_NPM_HEALTH_PORT", 4873),
            pypi_enabled=_boolean("MRK_PYPI_ENABLED", False),
            pypi_health_host=pypi_health_host,
            pypi_health_port=_port("MRK_PYPI_HEALTH_PORT", 3141),
            pypi_bootstrap_state_file=(
                Path(value).resolve()
                if (value := _getenv("MRK_PYPI_BOOTSTRAP_STATE_FILE", "").strip())
                else None
            ),
            pypi_router_health_host=pypi_router_health_host,
            pypi_router_health_port=_port("MRK_PYPI_ROUTER_PORT", 3142),
            auth_cookie_secure=_boolean("MRK_AUTH_COOKIE_SECURE", environment == "production"),
            session_ttl_seconds=session_ttl_seconds,
            session_remember_ttl_seconds=_bounded_int(
                "MRK_SESSION_REMEMBER_TTL_SECONDS", 7 * 86400, 900, 365 * 86400
            ),
            session_max_age_seconds=_bounded_int(
                "MRK_SESSION_MAX_AGE_SECONDS", 30 * 86400, 3600, 365 * 86400
            ),
            build_commit=_getenv("MRK_BUILD_COMMIT", "unknown").strip() or "unknown",
            build_date=_getenv("MRK_BUILD_DATE", "unknown").strip() or "unknown",
            host=_getenv(
                "MRK_HOST", "0.0.0.0"  # noqa: S104 - container listener, not host exposure
            ),
            port=_port("MRK_PORT", 8080),
            login_rate_limit_attempts=_bounded_int("MRK_LOGIN_RATE_LIMIT_ATTEMPTS", 5, 1, 100),
            login_rate_limit_window_seconds=_bounded_int(
                "MRK_LOGIN_RATE_LIMIT_WINDOW_SECONDS", 300, 10, 86400
            ),
            session_prune_age_seconds=_bounded_int(
                "MRK_SESSION_PRUNE_AGE_SECONDS", 7 * 86400, 3600, 365 * 86400
            ),
            npm_block_poll_seconds=_bounded_int("MRK_NPM_BLOCK_POLL_SECONDS", 30, 5, 3600),
        )

    @classmethod
    def for_test(cls, data_dir: Path) -> Settings:
        return cls(
            environment="test",
            data_dir=data_dir,
            database_url=None,
            log_level="WARNING",
            cors_origins=("http://testserver",),
            trusted_hosts=("testserver", "localhost", "127.0.0.1"),
            auth_cookie_secure=False,
        )
