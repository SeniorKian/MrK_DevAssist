from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(mrk_)[A-Za-z0-9_-]{16,}"),
    re.compile(r'(?i)(password|passwd|secret|token)([\"\s]*[:=][\"\s]*)[^\s,;}\"]+'),
    re.compile(r"(https?://)[^/@\s:]+:[^/@\s]+@"),
)


def redact_text(value: str) -> str:
    redacted = value
    for pattern in _SENSITIVE_PATTERNS:
        if pattern.pattern.startswith("(https?"):
            redacted = pattern.sub(r"\1[REDACTED]@", redacted)
        else:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted


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
        if record.exc_info:
            event["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(event, ensure_ascii=False)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
