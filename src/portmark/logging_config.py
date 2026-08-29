from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone


SENSITIVE_LOG_PATTERNS = (
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,'\"}]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[^\s,'\"}]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b[A-Z0-9_]*(?:TOKEN|SECRET|PRIVATE_KEY|PASSWORD|SIGNATURE)[A-Z0-9_]*\s*=\s*)[^\s,'\"}]+"), r"\1[REDACTED]"),
    (
        re.compile(r"(?i)((?:\"|')?(?:authorization|bearer_token|a2a_token|token|secret|private_key|raw_private_key|password|signature)(?:\"|')?\s*[:=]\s*([\"']))([^\"']+)([\"'])"),
        r"\1[REDACTED]\4",
    ),
)


def redact_log_value(value: str) -> str:
    redacted = value
    for pattern, replacement in SENSITIVE_LOG_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_log_value(record.getMessage()),
        }
        if record.exc_info:
            payload["exception"] = redact_log_value(self.formatException(record.exc_info))
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonLogFormatter() if json_logs else logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
