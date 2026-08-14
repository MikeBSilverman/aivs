"""Structured JSON logging.

Written against the standard library rather than pulling in a logging framework.
The formatter is thirty lines, every dependency in this service is a dependency
a member firm's third-party-risk review will ask about, and log formatting is
not where we need someone else's abstraction.

Logs are the operational view; the audit log is the evidentiary one. Nothing
here is a substitute for ``aivs_server.audit.log`` -- application logs are
rotated and discarded, audit rows are not.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import sys
from contextvars import ContextVar
from typing import Any, Final

__all__ = ["JsonFormatter", "configure_logging", "current_request_id", "set_request_id"]

#: Correlates every log line emitted while handling one request. Set by
#: RequestContextMiddleware; read by the formatter without threading it through
#: every call site.
_request_id: ContextVar[str] = ContextVar("aivs_request_id", default="")

#: LogRecord attributes that are structural rather than caller-supplied. Any
#: other attribute on a record came from an `extra=` and is worth emitting.
_STANDARD_RECORD_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)

#: Recursion bound for :func:`_scrub`. A cyclic or pathologically nested
#: structure must not be able to turn a log call into a stack overflow.
_MAX_SCRUB_DEPTH: Final[int] = 4

#: Never emitted, at any nesting level, even if a caller passes one in `extra`.
#: Application logs reach stdout, container log drivers, and often a SIEM; a
#: secret that lands there has been disclosed to every one of them.
_SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "set-cookie",
        "proxy_auth",
        "hmac_secret",
        "private_key",
        "totp",
        "totp_secret",
        "session_token",
        "api_key",
        "database_url",
    }
)


def set_request_id(request_id: str) -> None:
    """Bind ``request_id`` to the current context."""
    _request_id.set(request_id)


def current_request_id() -> str:
    """Return the request id bound to the current context, or an empty string."""
    return _request_id.get()


def _scrub(value: Any, depth: int = 0) -> Any:
    """Recursively redact sensitive keys and bound the structure's size."""
    if depth > _MAX_SCRUB_DEPTH:
        return "[truncated]"
    if isinstance(value, dict):
        return {
            key: ("[redacted]" if str(key).lower() in _SENSITIVE_KEYS else _scrub(item, depth + 1))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scrub(item, depth + 1) for item in value[:50]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": dt.datetime.fromtimestamp(record.created, tz=dt.UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        request_id = current_request_id()
        if request_id:
            payload["request_id"] = request_id

        for key, value in record.__dict__.items():
            if key in _STANDARD_RECORD_FIELDS or key.startswith("_"):
                continue
            payload[key] = _scrub(value)

        if record.exc_info:
            # The traceback is operationally essential and stays server-side;
            # it is never included in an HTTP response outside development.
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(_scrub(payload), separators=(",", ":"), default=str)


def configure_logging(level: str = "INFO") -> None:
    """Install the JSON formatter on the root logger.

    Replaces existing handlers rather than adding to them, so uvicorn's default
    handlers do not produce a duplicate plain-text copy of every line.
    """
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    for noisy in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(noisy)
        logger.handlers.clear()
        logger.propagate = True

    # SQLAlchemy at INFO echoes every statement, and our statements carry
    # submission titles and member identifiers.
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
