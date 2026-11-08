"""Native S3-compatible object storage engine (Gate 18, docs/30 + docs/31 §2).

Process ``mrk-s3-engine`` (supervisord program ``s3-engine``):

* S3 REST API on ``MRK_S3_LISTEN`` (default ``0.0.0.0:9000``),
* internal admin API on ``MRK_S3_ADMIN_LISTEN`` (default ``127.0.0.1:9001``,
  header ``X-MRK-Admin-Token`` = contents of ``/data/modules/s3/admin.token``).

The engine never talks to PGlite. The control plane writes the configuration
snapshot ``/data/modules/s3/config.json`` atomically; the engine polls its mtime.
Access-key secrets are read from the shared ``SecretStore(/data)``; each
``secret_ref`` must decrypt to ``{"secret_access_key": "<secret>"}``.
"""

from __future__ import annotations

__all__ = ["Engine", "EngineSettings"]


def __getattr__(name: str):  # pragma: no cover - lazy import keeps `import s3engine` cheap
    if name == "Engine":
        from .engine import Engine

        return Engine
    if name == "EngineSettings":
        from .settings import EngineSettings

        return EngineSettings
    raise AttributeError(name)
