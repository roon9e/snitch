"""Logging setup.

Secrets are scrubbed from the *fully formatted* record rather than from the
message in a filter. That ordering matters: ``record.exc_info`` is only rendered
into text when the formatter runs, which is after every filter has already been
given the record. Scrubbing in a filter would therefore leave the token intact
inside any traceback, which is exactly where it tends to surface.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from snitch.config import LogFormat, Settings

_RESERVED = frozenset(
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
        "taskName",
        "thread",
        "threadName",
    }
)

PLACEHOLDER = "***redacted***"


def scrub(text: str, secrets: Iterable[str]) -> str:
    """Replace every non-empty secret in ``text`` with a placeholder."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, PLACEHOLDER)
    return text


class RedactingFormatter(logging.Formatter):
    """Base formatter that scrubs secrets from everything it renders.

    Scrubbing the final string covers the message, the ``%``-interpolated
    arguments, any ``extra=`` fields and the traceback, with no ordering
    subtleties.
    """

    def __init__(
        self,
        secrets: Iterable[str] = (),
        *,
        fmt: str | None = None,
        datefmt: str | None = None,
    ) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)
        self._secrets = [secret for secret in secrets if secret]

    def format(self, record: logging.LogRecord) -> str:
        return scrub(super().format(record), self._secrets)


class JsonFormatter(RedactingFormatter):
    """One JSON object per line, with any ``extra=`` fields merged in."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = datetime.fromtimestamp(record.created, tz=timezone.utc)
        payload: dict[str, Any] = {
            "ts": stamp.isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = scrub(str(value), self._secrets)
        if record.exc_info:
            payload["exception"] = scrub(self.formatException(record.exc_info), self._secrets)
        return json.dumps(payload, default=str, ensure_ascii=False)


class TextFormatter(RedactingFormatter):
    """Compact human readable formatter."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__(
            secrets,
            fmt="%(asctime)s %(levelname)-8s %(name)-28s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def formatTime(  # noqa: N802 - stdlib signature
        self, record: logging.LogRecord, datefmt: str | None = None
    ) -> str:
        stamp = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return stamp.strftime(datefmt or "%Y-%m-%d %H:%M:%S")


def configure_logging(settings: Settings) -> None:
    """Install a single redacting handler on the root logger."""
    level = getattr(logging, settings.log_level, logging.INFO)
    # Both the bot token and any proxy password. settings.secrets drops empties,
    # so a proxy-less deployment does not scrub the empty string.
    secrets = settings.secrets
    formatter: logging.Formatter = (
        JsonFormatter(secrets) if settings.log_format is LogFormat.JSON else TextFormatter(secrets)
    )

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    # aiogram and aiohttp are chatty at INFO.
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    logging.getLogger("aiogram.event").setLevel(logging.WARNING)
    logging.getLogger("snitch").setLevel(level)
