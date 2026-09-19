from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone


SENSITIVE_LOG_PATTERNS = (
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,'\"}]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[^\s,'\"}]+"), r"\1[REDACTED]"),
    (
        re.compile(
            r"(?i)(\b[A-Z0-9_\-]*(?:TOKEN|SECRET|PRIVATE_KEY|PASSWORD|SIGNATURE|API[_\-]?KEY|ACCESS[_\-]?KEY|CREDENTIALS?)[A-Z0-9_\-]*\s*=\s*)[^\s,'\"}]+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)((?:\"|')?(?:proxy-authorization|authorization|bearer_token|a2a_token|token|secret|private_key|raw_private_key|password|signature|x-api-key|api[_\-]?key|access[_\-]?key|set-cookie|cookie)(?:\"|')?\s*[:=]\s*([\"']))([^\"']+)([\"'])"
        ),
        r"\1[REDACTED]\4",
    ),
    # Section 11 #2 (auditor round 2): credential-bearing HTTP headers written as `Name: value`.
    # A non-Bearer Authorization (Basic, Digest, a raw key) and a Cookie can hold spaces, commas,
    # and quotes, so their value is redacted to the end of the line; a Bearer value was already
    # reduced to `Bearer [REDACTED]` above and keeps its scheme. Key headers carry one token.
    (re.compile(r"(?im)(\b(?:proxy-)?authorization\s*:\s*)(?!\s*bearer\s+\[REDACTED\])(?=\S)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?im)(\b(?:set-)?cookie\s*:\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:x-)?(?:api|access|auth)[_\-]?(?:key|token)\s*:\s*)[^\s,;'\"}]+"), r"\1[REDACTED]"),
    # Section 11 #2: credentials embedded in a URI's user-info (postgres://user:pass@db,
    # redis://:pass@cache, https://token@host). The whole user-info is dropped, not just the
    # password span, because a bare token often sits in the user position. Greedy up to the
    # last '@' before the path, so an unencoded '@' inside a password is still covered.
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/?#@'\"]*(?:@[^\s/?#@'\"]*)*@"), r"\1[REDACTED]@"),
    # Section 11 #2: credentials in a query string (?token=..., &api_key=..., &password=...).
    (
        re.compile(
            r"(?i)([?&;][a-z0-9_.\-]*(?:token|api[_\-]?key|apikey|access[_\-]?key|password|passwd|pwd|secret|signature|sig|auth)[a-z0-9_.\-]*=)[^&\s#'\"]+"
        ),
        r"\1[REDACTED]",
    ),
)


SERVER_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi")


def redact_log_value(value: str) -> str:
    redacted = value
    for pattern, replacement in SENSITIVE_LOG_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


class RedactingFormatter(logging.Formatter):
    """Plain-text formatter that redacts the fully rendered line.

    Section 11 #2: redaction must cover everything a handler writes -- the message, its
    %-args, the exception text and traceback, and stack_info. A logging.Filter only sees the
    record before formatting and cannot reach the traceback text, so the redaction runs on the
    formatter's final output instead.
    """

    def format(self, record: logging.LogRecord) -> str:
        return redact_log_value(super().format(record))


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
        elif record.exc_text:
            payload["exception"] = redact_log_value(record.exc_text)
        if record.stack_info:
            payload["stack"] = redact_log_value(self.formatStack(record.stack_info))
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonLogFormatter() if json_logs else RedactingFormatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Section 11 #2: uvicorn installs its own handlers (with propagate=False) before it imports
    # the app, so its tracebacks ("Exception in ASGI application") would bypass redaction. Route
    # every server logger through the one redacting root handler instead.
    for name in SERVER_LOGGERS:
        server_logger = logging.getLogger(name)
        server_logger.handlers.clear()
        server_logger.propagate = True
