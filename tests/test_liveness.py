"""Liveness self-diagnosis.

The failure this guards against is invisible from the Bot API: privacy mode
cannot be queried, and a bot that cannot see the group cannot be asked about it.
These tests pin down that the monitor stays quiet when it should and speaks up
when the bot is genuinely deaf.
"""

from __future__ import annotations

import asyncio
import logging
import time

import pytest

from snitch.liveness import LivenessMonitor


def make_monitor(**overrides) -> LivenessMonitor:
    defaults = {"grace_seconds": 600.0, "check_interval": 0.01, "repeat_seconds": 3600.0}
    defaults.update(overrides)
    return LivenessMonitor(**defaults)


# ===========================================================================
# recording
# ===========================================================================
def test_fresh_monitor_has_seen_nothing():
    monitor = make_monitor()

    assert monitor.update_count == 0


def test_record_counts_updates():
    monitor = make_monitor()

    monitor.record()
    monitor.record()

    assert monitor.update_count == 2


def test_seconds_since_last_update_uses_start_before_any_update():
    monitor = make_monitor()
    time.sleep(0.01)

    assert monitor.seconds_since_last_update >= 0.0


# ===========================================================================
# when to warn
# ===========================================================================
def test_no_warning_during_the_grace_period():
    monitor = make_monitor(grace_seconds=600.0)

    assert monitor.should_warn() is False


def test_warns_after_the_grace_period_with_no_updates():
    monitor = make_monitor(grace_seconds=0.0)

    assert monitor.should_warn() is True


def test_never_warns_once_an_update_has_arrived():
    monitor = make_monitor(grace_seconds=0.0)
    monitor.record()

    assert monitor.should_warn() is False


def test_warns_again_only_after_the_repeat_interval():
    monitor = make_monitor(grace_seconds=0.0, repeat_seconds=100.0)
    assert monitor.should_warn() is True

    monitor._last_warning = time.monotonic()
    assert monitor.should_warn() is False

    monitor._last_warning = time.monotonic() - 101
    assert monitor.should_warn() is True


def test_one_update_is_enough_to_stop_the_warning_forever():
    monitor = make_monitor(grace_seconds=0.0)
    monitor.record()

    for _ in range(5):
        assert monitor.should_warn() is False


# ===========================================================================
# the background loop
# ===========================================================================
async def test_loop_logs_the_checklist_when_deaf(caplog):
    monitor = make_monitor(grace_seconds=0.0, check_interval=0.01)

    with caplog.at_level(logging.WARNING):
        task = asyncio.create_task(monitor.run())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    warnings = [r for r in caplog.records if "no messages received" in r.message]
    assert warnings, "the monitor must speak up when it has seen nothing"
    assert "Privacy mode is still ON" in warnings[0].getMessage()
    assert "/setprivacy" in warnings[0].getMessage()


async def test_loop_stays_quiet_when_updates_flow(caplog):
    monitor = make_monitor(grace_seconds=0.0, check_interval=0.01)
    monitor.record()

    with caplog.at_level(logging.WARNING):
        task = asyncio.create_task(monitor.run())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert not [r for r in caplog.records if "no messages received" in r.message]


async def test_checklist_names_the_most_likely_cause_first(caplog):
    """Privacy mode is the answer the overwhelming majority of the time."""
    monitor = make_monitor(grace_seconds=0.0, check_interval=0.01)

    with caplog.at_level(logging.WARNING):
        task = asyncio.create_task(monitor.run())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    message = next(r for r in caplog.records if "no messages received" in r.message).getMessage()
    assert message.index("Privacy mode") < message.index("not a member")


async def test_checklist_offers_a_private_chat_test(caplog):
    """Private chats ignore privacy mode, so /id in a DM is a clean control."""
    monitor = make_monitor(grace_seconds=0.0, check_interval=0.01)

    with caplog.at_level(logging.WARNING):
        task = asyncio.create_task(monitor.run())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    message = next(r for r in caplog.records if "no messages received" in r.message).getMessage()
    assert "PRIVATE" in message or "private" in message


async def test_loop_stops_cleanly_on_cancel():
    monitor = make_monitor(grace_seconds=0.0, check_interval=0.01)

    task = asyncio.create_task(monitor.run())
    await asyncio.sleep(0.03)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert task.cancelled() or task.done()
