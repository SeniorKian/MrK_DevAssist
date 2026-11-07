from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

ALLOWED_ENVIRONMENTS = {"development", "test", "production"}
ALLOWED_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _boolean(name: str, default: bool) -> bool:
    value = os.getenv(name, str(default)).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _port(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
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
    session_ttl_seconds: int = 28800
    build_commit: str = "unknown"
    build_date: str = "unknown"
    host: str = "0.0.0.0"  # noqa: S104 - required inside the container network namespace
    port: int = 8080

    @classmethod
    def from_env(cls) -> Settings:
        environment = os.getenv("MRK_ENV", "development").strip().lower()
        log_level = os.getenv("MRK_LOG_LEVEL", "INFO").strip().upper()
        cors_origins = _csv(os.getenv("MRK_CORS_ORIGINS", "http://localhost:8080"))
        trusted_hosts = _csv(os.getenv("MRK_TRUSTED_HOSTS", "localhost,127.0.0.1"))
        npm_health_host = os.getenv("MRK_NPM_HEALTH_HOST", "127.0.0.1").strip()
        pypi_health_host = os.getenv("MRK_PYPI_HEALTH_HOST", "127.0.0.1").strip()
        pypi_router_health_host = os.getenv(
            "MRK_PYPI_ROUTER_HEALTH_HOST", "127.0.0.1"
        ).strip()

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
            session_ttl_seconds = int(os.getenv("MRK_SESSION_TTL_SECONDS", "28800"))
        except ValueError as exc:
            raise ValueError("MRK_SESSION_TTL_SECONDS must be an integer") from exc
        if not 900 <= session_ttl_seconds <= 604800:
            raise ValueError("MRK_SESSION_TTL_SECONDS must be between 900 and 604800")
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
            data_dir=Path(os.getenv("MRK_DATA_DIR", "/data")).resolve(),
            database_url=os.getenv("MRK_DATABASE_URL", "").strip() or None,
            log_level=log_level,
            cors_origins=cors_origins,
            trusted_hosts=trusted_hosts,
            admin_ui_dir=(
                Path(value).resolve()
                if (value := os.getenv("MRK_ADMIN_UI_DIR", "").strip())
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
                if (value := os.getenv("MRK_PYPI_BOOTSTRAP_STATE_FILE", "").strip())
                else None
            ),
            pypi_router_health_host=pypi_router_health_host,
            pypi_router_health_port=_port("MRK_PYPI_ROUTER_PORT", 3142),
            auth_cookie_secure=_boolean("MRK_AUTH_COOKIE_SECURE", environment == "production"),
            session_ttl_seconds=session_ttl_seconds,
            build_commit=os.getenv("MRK_BUILD_COMMIT", "unknown").strip() or "unknown",
            build_date=os.getenv("MRK_BUILD_DATE", "unknown").strip() or "unknown",
            host=os.getenv(
                "MRK_HOST", "0.0.0.0"  # noqa: S104 - container listener, not host exposure
            ),
            port=_port("MRK_PORT", 8080),
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
