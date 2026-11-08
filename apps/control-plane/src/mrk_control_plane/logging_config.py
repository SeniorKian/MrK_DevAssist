from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

from .middleware import correlation_id_context

_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)[^\s,;]+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/=]{8,}"),
    re.compile(r"(?i)(mrk_)[A-Za-z0-9_-]{16,}"),
    re.compile(r'(?i)(password|passwd|secret|token)([\"\s]*[:=][\"\s]*)[^\s,;}\"]+'),
    re.compile(r"(https?://)[^/@\s:]+:[^/@\s]+@"),
)
# Attributes every LogRecord has; anything else came from ``extra=``.
_STANDARD_ATTRIBUTES = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys()
) | {"message", "asctime", "correlation_id", "taskName"}


def redact_text(value: str) -> str:
    redacted = value
    for pattern in _SENSITIVE_PATTERNS:
        if pattern.pattern.startswith("(https?"):
            redacted = pattern.sub(r"\1[REDACTED]@", redacted)
        else:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted


def _safe_extra(value: object) -> object:
    if isinstance(value, bool | int | float) or value is None:
        return value
    return redact_text(str(value))


class CorrelationIdFilter(logging.Filter):
    """Attach the request id from the middleware context to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not getattr(record, "correlation_id", None):
            record.correlation_id = correlation_id_context.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        correlation_id = getattr(record, "correlation_id", None)
        if correlation_id:
            event["correlation_id"] = correlation_id
        for key, value in vars(record).items():
            # ``extra=`` fields (upstream name, error code, counts) used to be dropped.
            if key not in _STANDARD_ATTRIBUTES and key not in event:
                event[key] = _safe_extra(value)
        if record.exc_info:
            event["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(event, ensure_ascii=False)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(CorrelationIdFilter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
