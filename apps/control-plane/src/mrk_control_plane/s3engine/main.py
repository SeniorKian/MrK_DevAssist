"""``mrk-s3-engine`` entry point: S3 API + admin API in one process (docs/31 §2)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
from collections.abc import Iterator

import uvicorn

from ..config import apply_startup_overrides
from ..logging_config import configure_logging
from .engine import Engine
from .settings import EngineSettings

LOGGER = logging.getLogger("mrk.s3")


class _Server(uvicorn.Server):
    """Signals are handled once for both servers (uvicorn would keep only the last)."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def build_servers(engine: Engine) -> tuple[uvicorn.Server, uvicorn.Server]:
    settings = engine.settings
    common = {
        "log_config": None,
        "access_log": False,
        "server_header": False,
        "lifespan": "off",
        "timeout_keep_alive": 75,
    }
    api = _Server(
        uvicorn.Config(engine.api, host=settings.listen[0], port=settings.listen[1], **common)
    )
    admin = _Server(
        uvicorn.Config(
            engine.admin, host=settings.admin_listen[0], port=settings.admin_listen[1], **common
        )
    )
    return api, admin


async def serve(settings: EngineSettings) -> None:
    engine = Engine(settings)
    api, admin = build_servers(engine)

    def stop(*_args: object) -> None:
        api.should_exit = True
        admin.should_exit = True
        engine.stop()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop))
    LOGGER.info(
        "starting S3 engine",
        extra={
            "listen": f"{settings.listen[0]}:{settings.listen[1]}",
            "admin": f"{settings.admin_listen[0]}:{settings.admin_listen[1]}",
        },
    )
    background = asyncio.ensure_future(engine.run_background())
    try:
        await asyncio.gather(api.serve(), admin.serve())
    finally:
        engine.stop()
        background.cancel()
        with contextlib.suppress(BaseException):
            await background
        engine.close()


def run() -> None:
    apply_startup_overrides()  # panel overrides; explicit env still wins
    configure_logging(os.getenv("MRK_LOG_LEVEL", "INFO").strip().upper() or "INFO")
    asyncio.run(serve(EngineSettings.from_env()))


if __name__ == "__main__":  # pragma: no cover
    run()
