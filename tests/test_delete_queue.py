"""Batched deletion: the queue, the flood wait, and the split fallback.

The behaviours worth pinning are the ones that cost API calls. A regression here
does not crash anything - it just quietly earns a 429 and starts dropping
messages, which is the failure nobody notices until the group is full of
messages that should have gone.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter

from snitch.services.delete_queue import MAX_BATCH, DeleteQueue


class FakeBot:
    """Records every deleteMessages call, and can fail or flood on demand."""

    def __init__(
        self,
        *,
        result: bool = True,
        errors: dict[int, Exception] | None = None,
        sequence: list[Any] | None = None,
    ) -> None:
        self.result = result
        self.errors = errors or {}
        self.sequence = list(sequence or [])
        # (chat_id, message_ids) per call: chat_id is recorded because batching
        # across chats is a real way to send ids to the wrong place.
        self.calls: list[tuple[Any, list[int]]] = []
        self.slept: list[float] = []

    async def delete_messages(self, *, chat_id: Any, message_ids: list[int]) -> bool:
        self.calls.append((chat_id, list(message_ids)))
        if self.sequence:
            action = self.sequence.pop(0)
            if isinstance(action, float):
                # A flood wait of this many seconds, then succeed.
                self.slept.append(action)
                return True
            if isinstance(action, Exception):
                raise action
        for message_id in message_ids:
            error = self.errors.get(message_id)
            if error is not None:
                raise error
        return self.result

    @property
    def chats(self) -> list[Any]:
        return [chat_id for chat_id, _ in self.calls]


def queue_for(bot: FakeBot, **kwargs: Any) -> DeleteQueue:
    defaults: dict[str, Any] = {"flush_seconds": 0.05}
    defaults.update(kwargs)
    return DeleteQueue(bot, **defaults)


async def wait_until_idle(queue: DeleteQueue, timeout: float = 2.0) -> None:
    """Let the worker drain, without asserting on interleaving.

    Batching is timing dependent by nature, so these tests assert on the size
    distribution rather than on an exact call count: the worker may flush a
    partial batch the moment it wakes, and that is correct behaviour.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    for _ in range(400):
        if not queue.pending or loop.time() >= deadline:
            break
        await asyncio.sleep(0.005)
    assert queue.pending == 0, f"{queue.pending} deletions never left the queue"


async def parked_queue(bot: FakeBot, **kwargs: Any) -> DeleteQueue:
    """A queue whose worker will never flush on its own.

    With a deadline far in the future, everything after the first message
    accumulates and only an explicit flush or close() sends it - which is what
    the failure-path tests need in order to know exactly what they are sending.
    """
    queue = queue_for(bot, flush_seconds=3600.0, **kwargs)
    await queue.start()
    return queue


# ===========================================================================
# shape of the traffic
# ===========================================================================


async def test_a_lone_deletion_is_not_queued():
    """It must not wait for a flush: the whole point is that a single violation
    disappears immediately."""
    bot = FakeBot()
    queue = queue_for(bot)

    await queue.enqueue(-100, 7)

    assert bot.calls == [(-100, [7])]
    assert queue.pending == 0


async def test_a_burst_is_sent_in_batches_not_one_call_each():
    """The entire reason this exists: 250 messages must not be 250 calls."""
    bot = FakeBot()
    queue = queue_for(bot, flush_seconds=0.05)
    await queue.start()

    await queue.enqueue(-100, 1)
    for message_id in range(2, 251):
        await queue.enqueue(-100, message_id)

    await wait_until_idle(queue)
    await queue.close()

    assert sorted(mid for _, ids in bot.calls for mid in ids) == list(range(1, 251))
    assert len(bot.calls) < 250 / 2, f"batching did not happen: {len(bot.calls)} calls"
    assert max(len(ids) for _, ids in bot.calls) > 1, "nothing was batched"


async def test_batches_never_exceed_telegram_s_ceiling():
    bot = FakeBot()
    queue = queue_for(bot, batch_size=100, flush_seconds=0.05)
    await queue.start()

    await queue.enqueue(-100, 0)
    for message_id in range(1, 401):
        await queue.enqueue(-100, message_id)

    await wait_until_idle(queue)
    await queue.close()

    assert max(len(ids) for _, ids in bot.calls) <= MAX_BATCH


async def test_the_batch_size_is_configurable_and_validated():
    bot = FakeBot()
    queue = queue_for(bot, batch_size=3, flush_seconds=0.05)
    await queue.start()

    await queue.enqueue(-100, 0)
    for message_id in range(1, 8):
        await queue.enqueue(-100, message_id)

    await wait_until_idle(queue)
    await queue.close()

    assert max(len(ids) for _, ids in bot.calls) <= 3


@pytest.mark.parametrize("size", [0, -1, MAX_BATCH + 1])
def test_an_impossible_batch_size_is_refused_at_construction(size):
    with pytest.raises(ValueError, match="batch_size"):
        DeleteQueue(FakeBot(), batch_size=size)


async def test_the_queue_flushes_on_its_own_without_being_asked():
    """Under a burst nobody is going to call flush(); the worker has to."""
    bot = FakeBot()
    queue = queue_for(bot, flush_seconds=0.01)
    await queue.start()

    await queue.enqueue(-100, 1)
    for message_id in range(2, 12):
        await queue.enqueue(-100, message_id)

    for _ in range(50):
        if not queue.pending:
            break
        await asyncio.sleep(0.01)
    await queue.close()

    assert queue.pending == 0
    assert len(bot.calls) < 11, "queued deletions must be batched, not sent one by one"


async def test_a_full_batch_is_sent_without_waiting_for_the_deadline():
    bot = FakeBot()
    queue = queue_for(bot, batch_size=5, flush_seconds=30.0)
    await queue.start()

    await queue.enqueue(-100, 1)
    for message_id in range(2, 6):
        await queue.enqueue(-100, message_id)

    for _ in range(50):
        if not queue.pending:
            break
        await asyncio.sleep(0.01)
    await queue.close()

    assert queue.pending == 0


async def test_the_worker_does_not_spin_when_idle(caplog):
    """An empty queue must cost nothing; a poll loop here would show up as
    constant CPU in a container that is meant to be idle."""
    bot = FakeBot()
    queue = queue_for(bot)
    await queue.start()

    with caplog.at_level(logging.DEBUG):
        await asyncio.sleep(0.2)
    await queue.close()

    assert bot.calls == []
    assert not [r for r in caplog.records if "delete" in r.message.lower()]


# ===========================================================================
# flood waits
# ===========================================================================
async def test_a_flood_wait_is_obeyed_then_retried(monkeypatch):
    """Retry sooner and the flood wait becomes an outage."""
    bot = FakeBot(sequence=[TelegramRetryAfter(method=None, message="slow down", retry_after=7)])
    queue = queue_for(bot)

    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    await queue.enqueue(-100, 1)

    assert slept == [7.0], "Telegram's number, not ours"
    assert bot.calls == [(-100, [1]), (-100, [1])], "the same batch is retried"


async def test_flood_waits_are_bounded(monkeypatch):
    """A server demanding an hour must not park the shutdown for an hour."""
    bot = FakeBot(sequence=[TelegramRetryAfter(method=None, message="wait", retry_after=3600)])
    queue = queue_for(bot, retry_cap_seconds=5.0)

    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    await queue.enqueue(-100, 1)

    assert slept == [5.0]
    assert queue.stats.flood_waits == 1


async def test_flood_waits_are_eventually_given_up_on(monkeypatch):
    """Retrying forever turns one bad moment into a permanently stuck queue."""
    always = [TelegramRetryAfter(method=None, message="wait", retry_after=1) for _ in range(20)]
    bot = FakeBot(sequence=always)
    queue = queue_for(bot)

    async def fake_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    await queue.enqueue(-100, 1)

    assert queue.stats.flood_waits == 4, "3 retries, then the 4th 429 gives up"
    assert queue.stats.failed == 1, "and reports the message as undeleted"


async def test_a_flood_wait_on_a_batch_retries_the_whole_batch(monkeypatch):
    # The first call (the inline one) succeeds; the batched call is flood limited.
    bot = FakeBot(
        sequence=[
            None,
            TelegramRetryAfter(method=None, message="wait", retry_after=2),
        ]
    )
    queue = await parked_queue(bot)

    async def fake_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    await queue.enqueue(-100, 1)
    for message_id in range(2, 12):
        await queue.enqueue(-100, message_id)
    await queue.flush()

    assert bot.calls[1][1] == list(range(2, 12)), "the batch is what got flood limited"
    assert bot.calls[2][1] == list(range(2, 12)), "and the retry is the whole batch"


# ===========================================================================
# the split fallback
# ===========================================================================
async def test_one_undeletable_message_does_not_cost_the_others():
    """A message older than 48 hours is rejected, and Telegram rejects the whole
    call when the batch contains one. Retrying all 100 individually would be the
    flood wait we are trying to avoid."""
    old = TelegramBadRequest(method=None, message="Bad Request: message can't be deleted")
    bot = FakeBot(errors={5: old})
    queue = await parked_queue(bot)

    await queue.enqueue(-100, 0)
    for message_id in range(1, 21):
        await queue.enqueue(-100, message_id)
    await queue.flush()

    # 21 messages in, one bad, twenty still deleted.
    assert queue.stats.failed == 1
    assert queue.stats.deleted == 20
    assert len(bot.calls) < 21, "splitting must be cheaper than one call per message"


async def test_the_split_actually_isolates_the_culprit():
    """The point of splitting: the failure is attributed to the right message."""
    old = TelegramBadRequest(method=None, message="Bad Request: message can't be deleted")
    bot = FakeBot(errors={7: old})
    queue = queue_for(bot)

    outcomes = await queue._send_batch(
        [_pending(-100, mid) for mid in (5, 7, 9)],
        attempt=0,
    )

    assert outcomes == {5: None, 7: f"Telegram server says - {old.message}", 9: None}


def _pending(chat_id: int, message_id: int) -> Any:
    from snitch.services.delete_queue import _Pending

    return _Pending(chat_id, message_id, 0.0)


async def test_a_whole_call_failure_is_not_split(caplog):
    """No rights cannot be fixed by halving the batch, and each split would be
    another call against a limit we are already near."""
    bot = FakeBot(
        sequence=[TelegramBadRequest(method=None, message="Forbidden: not enough rights")] * 60
    )
    queue = await parked_queue(bot)

    await queue.enqueue(-100, 0)
    for message_id in range(1, 50):
        await queue.enqueue(-100, message_id)

    with caplog.at_level(logging.WARNING):
        await queue.flush()

    assert queue.stats.failed == 50
    assert queue.stats.batched == 49
    assert any("not a per-message problem" in r.message for r in caplog.records)


async def test_an_already_deleted_batch_counts_as_success():
    """A message that vanished between the update and our call is not a failure."""
    bot = FakeBot(
        sequence=[
            TelegramBadRequest(method=None, message="Bad Request: message to delete not found")
        ]
    )
    queue = queue_for(bot)

    await queue.enqueue(-100, 4)

    assert queue.stats.failed == 0
    assert queue.stats.deleted == 1


async def test_a_false_return_is_a_failure(caplog):
    """deleteMessages can answer False without raising."""
    bot = FakeBot(result=False)
    queue = queue_for(bot)

    await queue.enqueue(-100, 4)

    assert queue.stats.failed == 1
    assert any("returned False" in r.message for r in caplog.records)


async def test_an_unattributable_failure_is_not_split():
    """A False with no detail must not turn into 100 blind single-message retries.

    That is the flood wait this whole module exists to avoid, and it would be
    triggered by the least informative failure Telegram can produce.
    """
    bot = FakeBot(result=False)
    queue = await parked_queue(bot)

    await queue.enqueue(-100, 0)
    for message_id in range(1, 101):
        await queue.enqueue(-100, message_id)
    await queue.flush()

    assert queue.stats.failed == 101
    assert len(bot.calls) == 2, "one inline plus one batch, and no blind splitting"


# ===========================================================================
# housekeeping
# ===========================================================================
async def test_close_flushes_what_is_pending():
    """A queued deletion dropped at shutdown is a message left in the group."""
    bot = FakeBot()
    queue = await parked_queue(bot)

    await queue.enqueue(-100, 1)
    for message_id in range(2, 8):
        await queue.enqueue(-100, message_id)
    assert queue.pending > 0

    await queue.close()

    assert queue.pending == 0
    assert sorted(mid for _, ids in bot.calls for mid in ids) == list(range(1, 8))


async def test_close_is_idempotent_and_safe_when_never_started():
    bot = FakeBot()
    queue = queue_for(bot)

    await queue.close()
    await queue.close()

    assert bot.calls == []


async def test_an_enqueue_after_close_still_deletes():
    """Not a restart, but it must not silently swallow a deletion: the inline
    path does not need the worker."""
    bot = FakeBot()
    queue = queue_for(bot)
    await queue.close()

    await queue.enqueue(-100, 1)

    assert bot.calls == [(-100, [1])]


async def test_stats_are_reportable():
    bot = FakeBot()
    queue = await parked_queue(bot)

    await queue.enqueue(-100, 1)
    for message_id in range(2, 12):
        await queue.enqueue(-100, message_id)
    await queue.flush()

    summary = queue.stats.summary()
    assert "11 deleted" in summary
    assert "0 failed" in summary


async def test_chats_are_never_mixed_in_one_call():
    """deleteMessages takes one chat, so two chats in one request would be
    rejected - or worse, delete from the wrong place.

    snitch guards a single chat, so this cannot happen in production today. The
    queue must not be relying on that: a queue that batches by arrival order and
    sends with `batch[0].chat_id` is one config change away from deleting the
    wrong thing.
    """
    bot = FakeBot()
    queue = await parked_queue(bot)

    # Fill the queue first so these all have to travel together.
    await queue.enqueue(-100, 0)
    for message_id in range(1, 30):
        await queue.enqueue(-200 if message_id % 2 else -100, message_id)
    await queue.flush()

    assert sorted(mid for _, ids in bot.calls for mid in ids) == list(range(0, 30))
    assert all(len(ids) <= MAX_BATCH for _, ids in bot.calls)
    # Every call is single-chat, so a call's ids all belong to the same chat.
    for chat_id, ids in bot.calls:
        expected = {-200 if mid % 2 else -100 for mid in ids}
        assert expected == {chat_id}, f"mixed chats in one call: {chat_id} with {ids}"
