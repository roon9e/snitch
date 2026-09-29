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


# ===========================================================================
# the checklist is assembled per deployment, not fixed
# ===========================================================================
def test_the_checklist_names_the_bot_it_is_actually_running_as():
    """Regression: the handle used to be hardcoded, which pointed every other
    operator at this repository's own bot."""
    message = make_monitor(bot_username="their_own_bot").checklist()

    assert "@their_own_bot /id" in message
    assert "snitch_punish_bot" not in message


def test_no_handle_invents_none():
    """Unknown username must not fall back to somebody else's handle."""
    message = make_monitor(bot_username=None).checklist()

    assert "@snitch_punish_bot" not in message
    assert "private" in message.lower(), "the advice survives, only the @name goes"


def test_a_stalled_proxy_is_offered_as_a_cause():
    """A proxy that accepts and then goes quiet is indistinguishable from a deaf
    bot by reading logs, so it belongs in the checklist when one is configured."""
    message = make_monitor(proxy="socks5://user:***@10.0.0.1:1080").checklist()

    assert "proxy is down or stalling" in message
    assert "REQUEST_TIMEOUT" in message


def test_the_proxy_cause_is_absent_when_no_proxy_is_configured():
    """Advice about a proxy nobody configured is noise."""
    message = make_monitor(proxy=None).checklist()

    assert "proxy" not in message.lower()


def test_the_proxy_url_in_the_warning_is_redacted():
    """The checklist is a warning, not a place to leak a password."""
    message = make_monitor(proxy="socks5://user:***@10.0.0.1:1080").checklist()

    assert "***" in message
    assert "hunter2" not in message


def test_confirmed_privacy_mode_drops_off_the_list():
    """Once checked in @BotFather it is a permanent property of the bot, so
    repeating that advice forever buries the causes still live."""
    message = make_monitor(privacy_mode_verified=True).checklist()

    assert "setprivacy" not in message
    assert "not a member" in message
    assert "group is quiet" in message


def test_confirmed_privacy_mode_also_drops_the_pointless_private_chat_test():
    """The DM test exists to isolate privacy mode. With it ruled out, suggesting
    it is a distraction."""
    message = make_monitor(privacy_mode_verified=True).checklist()

    assert "in private" not in message


def test_the_checklist_still_warns_when_privacy_mode_is_ruled_out():
    """Ruling out one cause must not silence the monitor; the bot can still be
    blind for a reason that has nothing to do with privacy mode."""
    monitor = make_monitor(privacy_mode_verified=True, grace_seconds=0.0)

    assert monitor.should_warn() is True


def test_a_verified_bot_with_a_proxy_still_gets_the_proxy_advice():
    """The two exclusions are independent."""
    message = make_monitor(
        privacy_mode_verified=True,
        proxy="socks5://user:***@10.0.0.1:1080",
    ).checklist()

    assert "proxy is down or stalling" in message
    assert "setprivacy" not in message


def test_the_causes_stay_numbered_in_order():
    message = make_monitor(proxy="socks5://10.0.0.1:1080").checklist()

    assert "  1. Privacy mode" in message
    assert "  2. The proxy is down or stalling" in message
    assert "  3. The bot is not a member" in message
    assert "  4. The group is quiet" in message


async def test_loop_stops_cleanly_on_cancel():
    monitor = make_monitor(grace_seconds=0.0, check_interval=0.01)

    task = asyncio.create_task(monitor.run())
    await asyncio.sleep(0.03)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert task.cancelled() or task.done()
