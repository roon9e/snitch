"""Logging setup.

The redaction is the last line of defence for the bot token, so it is tested
against the awkward cases: a token in an exception traceback, a token produced by
``%``-interpolation, and a token in an ``extra=`` field.
"""

from __future__ import annotations

import json
import logging
import sys

import pytest

from snitch.config import LogFormat
from snitch.logging_conf import (
    PLACEHOLDER,
    JsonFormatter,
    TextFormatter,
    configure_logging,
    scrub,
)
from tests.conftest import make_settings

TOKEN = "123456789:SUPER_SECRET_TOKEN_VALUE"


@pytest.fixture
def record() -> logging.LogRecord:
    return logging.LogRecord(
        name="snitch.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )


@pytest.fixture(autouse=True)
def _restore_root_logger() -> object:
    """Leave the root logger as we found it."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    yield
    root.handlers = saved_handlers
    root.setLevel(saved_level)


# ===========================================================================
# scrub
# ===========================================================================
def test_scrub_replaces_every_occurrence():
    assert scrub(f"a {TOKEN} b {TOKEN}", [TOKEN]) == f"a {PLACEHOLDER} b {PLACEHOLDER}"


def test_scrub_ignores_empty_secrets():
    assert scrub("untouched", ["", ""]) == "untouched"


# ===========================================================================
# text output
# ===========================================================================
def test_token_in_a_plain_message_is_scrubbed(record):
    record.msg = f"using token {TOKEN} to poll"

    assert TOKEN not in TextFormatter([TOKEN]).format(record)
    assert PLACEHOLDER in TextFormatter([TOKEN]).format(record)


def test_token_in_interpolated_args_is_scrubbed(record):
    """%s interpolation is where a token most often leaks from."""
    record.msg = "polling with %s"
    record.args = (TOKEN,)

    assert TOKEN not in TextFormatter([TOKEN]).format(record)


def test_token_in_an_exception_is_scrubbed(record):
    """The regression: exc_info is only rendered during format(), after filters."""
    try:
        raise RuntimeError(f"failed with token {TOKEN}")
    except RuntimeError:
        record.exc_info = sys.exc_info()

    formatted = TextFormatter([TOKEN]).format(record)

    assert TOKEN not in formatted
    assert PLACEHOLDER in formatted
    assert "RuntimeError" in formatted


def test_text_formatter_renders_a_single_line(record):
    assert "\n" not in TextFormatter().format(record)


# ===========================================================================
# json output
# ===========================================================================
def test_json_formatter_emits_one_object_per_line(record):
    record.msg = "structured"
    record.violation_kind = "reply"  # an ``extra=`` field

    payload = json.loads(JsonFormatter().format(record))

    assert payload["level"] == "INFO"
    assert payload["logger"] == "snitch.test"
    assert payload["message"] == "structured"
    assert payload["violation_kind"] == "reply"
    assert "ts" in payload


def test_json_formatter_scrubs_extra_fields(record):
    record.msg = "ok"
    record.note = f"leaked {TOKEN}"

    assert TOKEN not in JsonFormatter([TOKEN]).format(record)


def test_json_formatter_scrubs_the_exception(record):
    try:
        raise ValueError(f"boom {TOKEN}")
    except ValueError:
        record.exc_info = sys.exc_info()

    payload = json.loads(JsonFormatter([TOKEN]).format(record))

    assert TOKEN not in payload["exception"]
    assert "ValueError" in payload["exception"]


# ===========================================================================
# installation
# ===========================================================================
def test_configure_logging_scrubs_the_token_end_to_end(capsys):
    settings = make_settings(log_level="INFO", log_format=LogFormat.TEXT)

    configure_logging(settings)
    logging.getLogger("snitch.probe").info("token=%s", settings.token)

    captured = capsys.readouterr()
    assert settings.token not in captured.out
    assert PLACEHOLDER in captured.out


def test_configure_logging_honours_json_format(capsys):
    settings = make_settings(log_level="INFO", log_format=LogFormat.JSON)

    configure_logging(settings)
    logging.getLogger("snitch.probe").info("hello")

    assert json.loads(capsys.readouterr().out.strip())["message"] == "hello"


def test_configure_logging_replaces_existing_handlers():
    """Reload must not stack handlers and duplicate every log line."""
    configure_logging(make_settings())
    configure_logging(make_settings())

    assert len(logging.getLogger().handlers) == 1


def test_log_level_is_applied():
    configure_logging(make_settings(log_level="WARNING"))

    assert logging.getLogger("snitch").level == logging.WARNING


def test_noisier_libraries_are_quietened():
    configure_logging(make_settings(log_level="DEBUG"))

    assert logging.getLogger("aiohttp.access").level == logging.WARNING
    assert logging.getLogger("aiogram.event").level == logging.WARNING
