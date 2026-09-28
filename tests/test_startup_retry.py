"""Startup retry policy.

A wrong CHAT_ID will still be wrong in thirty seconds, so the process must exit
and let the operator read the logs. A Telegram 502 must not kill the container.
These tests pin that split down.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from aiogram.exceptions import TelegramBadRequest, TelegramServerError

from snitch import __main__ as entrypoint
from snitch.preflight import PreflightError


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record requested delays instead of actually waiting."""
    delays: list[float] = []

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    return delays


@pytest.fixture
def build_calls(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count build attempts and make them fail on demand."""
    attempts = {"count": 0}
    queue: list[BaseException] = []

    async def fake_build(settings: Any) -> Any:  # noqa: ARG001 - must accept the call
        attempts["count"] += 1
        if queue:
            raise queue.pop(0)
        return object()

    monkeypatch.setattr(entrypoint, "build_app", fake_build)
    attempts["queue"] = queue  # type: ignore[assignment]
    return attempts  # type: ignore[return-value]


def queue_of(build_calls: dict, *errors: BaseException) -> None:  # type: ignore[type-arg]
    build_calls["queue"].extend(errors)


# ===========================================================================
# permanent failures are not retried
# ===========================================================================
async def test_permanent_failure_is_not_retried(build_calls, no_sleep):
    queue_of(build_calls, PreflightError("wrong chat id", permanent=True))

    with pytest.raises(PreflightError):
        await entrypoint._build_with_retry(object())  # type: ignore[arg-type]

    assert build_calls["count"] == 1, "a permanent error must not be retried"
    assert no_sleep == []


@pytest.mark.usefixtures("no_sleep")
async def test_bad_chat_id_exits_after_one_attempt(build_calls):
    queue_of(build_calls, PreflightError("cannot read CHAT_ID", permanent=True))

    with pytest.raises(PreflightError):
        await entrypoint._build_with_retry(object())  # type: ignore[arg-type]

    assert build_calls["count"] == 1


# ===========================================================================
# transient failures are retried
# ===========================================================================
async def test_transient_failure_is_retried_then_succeeds(build_calls, no_sleep):
    queue_of(
        build_calls,
        PreflightError("Telegram is having a moment", permanent=False),
        PreflightError("still down", permanent=False),
    )

    result = await entrypoint._build_with_retry(object())  # type: ignore[arg-type]

    assert result is not None
    assert build_calls["count"] == 3
    assert no_sleep == [5, 15]


async def test_retry_gives_up_after_the_configured_attempts(build_calls, no_sleep):
    queue_of(*(build_calls, *([PreflightError("down", permanent=False)] * 10)))

    with pytest.raises(PreflightError, match="down"):
        await entrypoint._build_with_retry(object())  # type: ignore[arg-type]

    assert build_calls["count"] == entrypoint.STARTUP_ATTEMPTS
    # One delay fewer than the attempt count: the last failure is not followed
    # by a pointless sleep.
    assert len(no_sleep) == entrypoint.STARTUP_ATTEMPTS - 1


async def test_retry_backoff_is_bounded(build_calls, no_sleep):
    queue_of(*(build_calls, *([PreflightError("down", permanent=False)] * 10)))

    with pytest.raises(PreflightError):
        await entrypoint._build_with_retry(object())  # type: ignore[arg-type]

    assert max(no_sleep) <= max(entrypoint.STARTUP_BACKOFF_SECONDS)
    assert no_sleep == sorted(no_sleep), "delays must not shrink"


async def test_no_retry_when_the_first_attempt_succeeds(build_calls, no_sleep):
    result = await entrypoint._build_with_retry(object())  # type: ignore[arg-type]

    assert result is not None
    assert build_calls["count"] == 1
    assert no_sleep == []


# ===========================================================================
# classification feeds the policy
# ===========================================================================
def test_telegram_5xx_is_worth_retrying():
    from snitch.preflight import is_transient

    assert is_transient(TelegramServerError(method=None, message="Internal Server Error"))


def test_chat_not_found_is_not_worth_retrying():
    from snitch.preflight import is_transient

    assert not is_transient(TelegramBadRequest(method=None, message="Bad Request: chat not found"))
