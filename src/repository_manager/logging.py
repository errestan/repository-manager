"""Structured logging (specification.md 13.3, 10.7).

Every line carries a request ID so a single request can be followed across the
web layer and the job queue.  A redaction processor runs on every event: secrets
must not reach the log even when a future caller passes one in by mistake, so
the filter lives here rather than at each call site.
"""

from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from typing import Any, Literal

import structlog

# Set per request by the web layer, and inherited by any task the request spawns.
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

# Substrings; a key is redacted if any appears in it, case-insensitively.
# Deliberately broad -- a false positive costs a log line, a false negative
# leaks a credential.
SENSITIVE_KEY_PARTS = (
    "password",
    "passphrase",
    "secret",
    "token",
    "cookie",
    "authorization",
    "auth_header",
    "api_key",
    "apikey",
    "private_key",
    "session_id",
    "csrf",
)

REDACTED = "[redacted]"


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def redact_secrets(
    _logger: Any, _method: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    """Replace the value of any sensitive-looking key, at any nesting depth."""

    def scrub(value: Any, depth: int = 0) -> Any:
        if depth > 6:  # pragma: no cover - defensive against cyclic structures
            return value
        if isinstance(value, dict):
            return {
                key: (REDACTED if _is_sensitive(str(key)) else scrub(item, depth + 1))
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return type(value)(scrub(item, depth + 1) for item in value)
        return value

    return {
        key: (REDACTED if _is_sensitive(key) else scrub(value)) for key, value in event_dict.items()
    }


def add_request_id(
    _logger: Any, _method: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    """Attach the current request ID, when there is one."""
    request_id = request_id_var.get()
    if request_id is not None:
        event_dict["request_id"] = request_id
    return event_dict


def configure_logging(log_format: Literal["json", "console"] = "json", level: str = "INFO") -> None:
    """Configure structlog and route the standard library through it."""
    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if log_format == "json"
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    shared: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        add_request_id,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        redact_secrets,
    ]

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    # Uvicorn and SQLAlchemy log through the standard library; send those to the
    # same stream so a deployment has exactly one log format to parse.
    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=level.upper(), force=True)
    for noisy in ("uvicorn.error", "uvicorn.access"):
        logging.getLogger(noisy).handlers.clear()
        logging.getLogger(noisy).propagate = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
