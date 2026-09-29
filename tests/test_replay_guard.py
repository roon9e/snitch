"""The replay guard: never act on a message that predates this process.

Telegram replays a backlog through ``getUpdates`` after downtime, so without this
a restarting bot would retroactively delete messages and start mutes for offences
that already happened. A mute in particular is a *now*-lasting action, so
replaying a three day old offence would silence someone for 24 hours starting
today, which is not what "mute for 24 hours after the offence" means.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from aiogram import Dispatcher
from aiogram.dispatcher.event.bases import UNHANDLED
from aiogram.types import Chat, Message, Update, User

from snitch.bot import UpdateMiddleware, _message_of
from snitch.config import Settings
from snitch.liveness import LivenessMonitor
from tests.conftest import CHAT_ID, make_settings

START = datetime(2026, 9, 29, 19, 0, 0, tzinfo=timezone.utc)


def message_at(when: datetime, message_id: int = 1, sender_id: int = 111) -> Message:
    return Message(
        message_id=message_id,
        date=when,
        chat=Chat(id=CHAT_ID, type="supergroup"),
        from_user=User(id=sender_id, is_bot=False, first_name="u"),
        text="hello",
    )


def update_for(message: Message) -> Update:
    return Update(update_id=message.message_id, message=message)


# ===========================================================================
# the decision
# ===========================================================================
def test_message_before_start_is_a_replay():
    guard = UpdateMiddleware(started_at=START)

    assert guard.is_replay(message_at(START - timedelta(seconds=1))) is True


def test_message_at_start_is_not_a_replay():
    guard = UpdateMiddleware(started_at=START)

    assert guard.is_replay(message_at(START)) is False


def test_message_after_start_is_not_a_replay():
    guard = UpdateMiddleware(started_at=START)

    assert guard.is_replay(message_at(START + timedelta(seconds=5))) is False


def test_message_in_the_start_second_is_kept():
    """Telegram dates are whole seconds, so a message sent microseconds after the
    recorded start can appear to be earlier. Truncating avoids dropping a
    genuinely new message."""
    started = datetime(2026, 9, 29, 19, 0, 0, 750000, tzinfo=timezone.utc)
    guard = UpdateMiddleware(started_at=started)

    assert guard.is_replay(message_at(START)) is False


def test_backlog_is_ignored_by_default():
    guard = UpdateMiddleware(started_at=START)

    assert guard.is_replay(message_at(START - timedelta(days=3))) is True


def test_backlog_can_be_opted_into():
    guard = UpdateMiddleware(started_at=START, process_backlog=True)

    assert guard.is_replay(message_at(START - timedelta(days=3))) is False


def test_naive_dates_are_read_as_utc_not_local_time():
    """Telegram dates are UTC. Reading a naive datetime as local time would
    shift the comparison by the server's UTC offset - up to 14 hours - and
    silently drop or admit live traffic."""
    guard = UpdateMiddleware(started_at=START)
    naive = START.replace(tzinfo=None)

    assert guard.is_replay(message_at(naive)) is False
    assert guard.is_replay(message_at(naive - timedelta(seconds=1))) is True


def test_it_works_on_a_message_parsed_from_the_real_wire_format():
    """Guards against the parsed shape differing from a hand-built Message:
    Telegram sends an integer timestamp and aiogram hands back aware UTC."""
    message = Message.model_validate(
        {
            "message_id": 1,
            "date": int(START.timestamp()),
            "chat": {"id": CHAT_ID, "type": "supergroup"},
            "from_user": {"id": 111, "is_bot": False, "first_name": "u"},
            "text": "hello",
        }
    )
    guard = UpdateMiddleware(started_at=START)

    assert guard.is_replay(message) is False
    assert guard.is_replay(message.model_copy(update={"date": START - timedelta(days=2)})) is True
    # One second later it counts as a backlog: the comparison is genuinely
    # against the parsed timestamp, not against something else.
    assert UpdateMiddleware(started_at=START + timedelta(seconds=1)).is_replay(message) is True


# ===========================================================================
# the middleware
# ===========================================================================
async def test_replayed_update_never_reaches_the_handler():
    seen: list[int] = []

    async def handler(event: Any, _data: dict[str, Any]) -> str:
        seen.append(event.update_id)
        return "ok"

    guard = UpdateMiddleware(started_at=START)
    result = await guard(handler, update_for(message_at(START - timedelta(hours=2))), {})

    assert seen == []
    assert result is UNHANDLED, "the update must be reported as unhandled"


async def test_new_update_reaches_the_handler():
    seen: list[int] = []

    async def handler(event: Any, _data: dict[str, Any]) -> str:
        seen.append(event.update_id)
        return "ok"

    guard = UpdateMiddleware(started_at=START)
    result = await guard(handler, update_for(message_at(START + timedelta(seconds=1))), {})

    assert seen == [1]
    assert result == "ok"


async def test_replayed_update_is_not_counted_as_liveness():
    """A swallowed backlog must not make the liveness warning stay quiet - the
    whole point of that warning is to notice when nothing is being processed."""
    liveness = LivenessMonitor()
    guard = UpdateMiddleware(liveness=liveness, started_at=START)

    async def handler(_event: Any, _data: dict[str, Any]) -> str:
        return "ok"

    for index in range(5):
        await guard(
            handler,
            update_for(message_at(START - timedelta(hours=index + 1), message_id=index)),
            {},
        )

    assert liveness.update_count == 0

    await guard(handler, update_for(message_at(START + timedelta(seconds=1), 99)), {})
    assert liveness.update_count == 1


async def test_a_replayed_burst_is_logged_once_not_per_message(caplog):
    """After a long outage the backlog can be large; a line per message would
    bury the reason it is being replayed."""

    async def handler(_event: Any, _data: dict[str, Any]) -> str:
        return "ok"

    guard = UpdateMiddleware(started_at=START)
    with caplog.at_level(logging.INFO):
        for index in range(50):
            await guard(
                handler,
                update_for(message_at(START - timedelta(hours=index + 1), index)),
                {},
            )

    ignored = [r for r in caplog.records if "predates this process" in r.message]
    assert len(ignored) == 5, "only the first few are logged individually"
    assert any("not be logged individually" in r.message for r in caplog.records)


async def test_replay_log_explains_why(caplog):
    async def handler(_event: Any, _data: dict[str, Any]) -> str:
        return "ok"

    guard = UpdateMiddleware(started_at=START)
    with caplog.at_level(logging.INFO):
        await guard(handler, update_for(message_at(START - timedelta(days=1))), {})

    message = next(r for r in caplog.records if "predates this process" in r.message).message
    assert "retroactively" in message
    assert "PROCESS_BACKLOG" not in message, "the safe default needs no instructions"


# ===========================================================================
# extracting the message
# ===========================================================================
def test_message_is_extracted_from_an_update():
    message = message_at(START)

    assert _message_of(update_for(message)) is message


def test_a_bare_message_is_extracted():
    message = message_at(START)

    assert _message_of(message) is message


def test_a_non_message_update_yields_nothing():
    assert _message_of(Update(update_id=1)) is None


# ===========================================================================
# configuration
# ===========================================================================
def test_backlog_is_ignored_by_default_in_config():
    assert make_settings().process_backlog is False


def test_backlog_can_be_enabled_in_config():
    assert make_settings(process_backlog=True).process_backlog is True


def test_request_timeout_default_and_bounds():
    assert make_settings().request_timeout == 30.0
    assert make_settings(request_timeout=5.0).request_timeout == 5.0
    with pytest.raises(ValueError, match="less than or equal"):
        make_settings(request_timeout=1000.0)
    with pytest.raises(ValueError, match="greater than or equal"):
        make_settings(request_timeout=1.0)


def test_summary_reports_the_new_settings():
    summary: dict[str, object] = make_settings().redacted_summary()

    assert summary["process_backlog"] is False
    assert summary["request_timeout"] == 30.0


# ===========================================================================
# it composes with a real dispatcher
# ===========================================================================
async def test_commands_from_before_start_are_also_dropped():
    """A replayed ``/unmute`` must not be executed days later either."""
    dispatcher = Dispatcher()
    seen: list[str] = []

    @dispatcher.message()
    async def catch_all(message: Message) -> None:
        seen.append(message.text or "")

    dispatcher.update.outer_middleware(UpdateMiddleware(started_at=START))

    await dispatcher.feed_update(
        _StubBot(),  # type: ignore[arg-type]
        update_for(message_at(START - timedelta(days=1), 1)),
    )
    await dispatcher.feed_update(
        _StubBot(),  # type: ignore[arg-type]
        update_for(message_at(START + timedelta(seconds=1), 2)),
    )

    assert seen == ["hello"]


class _StubBot:
    id = 1

    async def get_chat_member(self, **kwargs: Any) -> Any:  # pragma: no cover
        raise NotImplementedError

    def __getattr__(self, name: str) -> Any:  # pragma: no cover
        async def noop(*_args: Any, **_kwargs: Any) -> None:
            return None

        return noop


def test_settings_still_validate_end_to_end():
    settings: Settings = make_settings(process_backlog=True, request_timeout=15.0)

    assert settings.process_backlog is True
    assert settings.request_timeout == 15.0
