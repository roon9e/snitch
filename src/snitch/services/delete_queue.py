"""Batched deletion, so a message flood does not earn a flood wait.

Deleting one message per API call is what earns a 429 in the first place. Telegram
offers ``deleteMessages``, which takes up to 100 ids at a time, so a burst of a
thousand violations costs ten calls instead of a thousand.

The design keeps the punishment sharp where it matters. A single violation is
deleted **inline, immediately** - queueing it would add latency to the one case
where the message being visible for even a moment is the whole problem. Only
when a burst is already in flight does anything queue, and then it is flushed in
batches of 100.

Two failure modes get real handling rather than a blanket retry:

* **Flood wait.** ``TelegramRetryAfter`` carries the server's own number of
  seconds. We wait exactly that, then retry the same batch. Retrying sooner is
  how a flood wait turns into an outage; retrying forever is how a bad proxy
  turns into one.
* **One undeletable message.** A message older than 48 hours cannot be deleted,
  and Telegram rejects the whole call when the batch contains one. Rather than
  give up on the other 99 - or retry all 100 individually - the batch is split
  in half and each half retried, so the cost is logarithmic. A failure that is
  not per-message (no rights, bot removed) is detected and not split, because
  splitting cannot help and each attempt would be another call against a limit
  we are already near.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass

from aiogram import Bot
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest, TelegramRetryAfter

logger = logging.getLogger(__name__)

#: Telegram's documented ceiling for deleteMessages.
MAX_BATCH = 100

#: Markers for failures that apply to the whole call rather than one message.
#: Splitting cannot fix these, and every split would be another API call.
_WHOLE_CALL_FAILURES = (
    "chat admin required",
    "not enough rights",
    "message delete forbidden",
    "bot was kicked",
    "bot is not a member",
    "chat not found",
    "forbidden",
)

#: Markers for "it is already gone", which counts as success.
_ALREADY_GONE = ("message to delete not found", "message_id_invalid", "message not found")


@dataclass(slots=True)
class _Pending:
    chat_id: int | str
    message_id: int
    queued_at: float


def _by_chat(batch: list[_Pending]) -> list[list[_Pending]]:
    """Split a batch into one group per chat, preserving order."""
    groups: dict[int | str, list[_Pending]] = {}
    for item in batch:
        groups.setdefault(item.chat_id, []).append(item)
    return list(groups.values())


@dataclass(slots=True)
class DeleteStats:
    """Counters for /status and for the summary line."""

    batched: int = 0
    deleted: int = 0
    failed: int = 0
    flood_waits: int = 0
    batches: int = 0

    def summary(self) -> str:
        """One line for the log."""
        return (
            f"{self.deleted} deleted in {self.batches} calls, {self.failed} failed, "
            f"{self.flood_waits} flood waits"
        )


class DeleteQueue:
    """Collects deletions and sends them in batches.

    Owned by the Moderator and closed on shutdown, because a queued deletion that
    is never flushed is a message that stays in the group.
    """

    def __init__(
        self,
        bot: Bot,
        *,
        batch_size: int = MAX_BATCH,
        flush_seconds: float = 0.5,
        max_retries: int = 3,
        retry_cap_seconds: float = 60.0,
    ) -> None:
        if batch_size < 1 or batch_size > MAX_BATCH:
            raise ValueError(f"batch_size must be 1..{MAX_BATCH}, got {batch_size}")
        self._bot = bot
        self._batch_size = batch_size
        self._flush_seconds = flush_seconds
        self._max_retries = max_retries
        self._retry_cap = retry_cap_seconds
        self._queue: list[_Pending] = []
        self._wake = asyncio.Event()
        self._worker: asyncio.Task[None] | None = None
        self._closing = False
        #: When the last inline delete opened its coalescing window. See enqueue.
        self._coalesce_until = 0.0
        self.stats = DeleteStats()

    # ------------------------------------------------------------------
    @property
    def pending(self) -> int:
        """How many deletions are queued."""
        return len(self._queue)

    async def enqueue(self, chat_id: int | str, message_id: int) -> dict[int, str | None] | None:
        """Delete one message, batching it if a burst is already in flight.

        Returns the outcome (message id -> error, None meaning deleted) when the
        deletion happened inline, and ``None`` when it was queued. That
        distinction matters: reporting a queued deletion as successful would put
        a lie in the audit log, and reporting it as failed would punish the
        operator's bookkeeping for latency they never see.
        """
        now = time.monotonic()
        if not self._queue and now >= self._coalesce_until:
            # Isolated violation, so delete it now and open a short coalescing
            # window. The window is what makes batching actually happen:
            # without it every message would find an empty queue, take the
            # inline path, and a thousand-message flood would still be a
            # thousand calls. Anything arriving inside the window is batched.
            outcome = await self._send([_Pending(chat_id, message_id, now)])
            self._record(outcome)
            self._coalesce_until = time.monotonic() + self._flush_seconds
            return outcome

        self._queue.append(_Pending(chat_id, message_id, now))
        self.stats.batched += 1
        # Always wake the worker, not just at full batch. It may be parked on
        # `_wake` with no timeout, waiting for either a full batch or the
        # flush deadline - and it cannot know the deadline has passed while it
        # is asleep. Waking only at batch_size would strand a burst of 30
        # messages until shutdown, which is exactly a set of messages left
        # sitting in the group.
        self._wake.set()
        return None

    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Start the flush worker. Idempotent, and safe to call from anywhere."""
        if self._worker is None or self._worker.done():
            self._closing = False
            self._worker = asyncio.create_task(self._run(), name="snitch-delete-queue")

    async def flush(self) -> None:
        """Send everything queued, regardless of age. Used by tests and shutdown."""
        while self._queue:
            await self._flush_once()

    async def _flush_once(self) -> bool:
        """Send one batch, partitioned by chat. Returns whether anything went."""
        batch = self._take(self._batch_size)
        if not batch:
            return False
        # deleteMessages takes a single chat_id. Batching across chats would send
        # one chat's message ids to another chat, which Telegram rejects - and
        # which would be a very confusing thing to debug. snitch guards one chat,
        # so this is normally a no-op, but the queue is not allowed to depend on
        # that being true.
        for group in _by_chat(batch):
            self._record(await self._send(group))
        return True

    async def close(self) -> None:
        """Stop the worker after a final flush. Never leaves deletions pending."""
        self._closing = True
        self._wake.set()
        worker, self._worker = self._worker, None
        if worker is not None:
            worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await worker
        await self.flush()

    # ------------------------------------------------------------------
    async def _run(self) -> None:
        """Flush on deadline, on fullness, or on demand - never spinning."""
        try:
            while not self._closing:
                wait = self._seconds_until_ready()
                if wait is None:
                    # Nothing queued: sleep until something arrives.
                    await self._wake.wait()
                    self._wake.clear()
                    continue
                if wait > 0:
                    try:
                        await asyncio.wait_for(self._wake.wait(), timeout=wait)
                        self._wake.clear()
                        continue
                    except asyncio.TimeoutError:
                        pass
                if self._queue:
                    await self._flush_once()
        except asyncio.CancelledError:
            logger.debug("delete queue worker cancelled")
            raise

    def _seconds_until_ready(self) -> float | None:
        """How long to wait before a flush is due, or None if there is nothing."""
        if not self._queue:
            return None
        if len(self._queue) >= self._batch_size:
            return 0.0
        oldest = self._queue[0].queued_at
        return max(0.0, self._flush_seconds - (time.monotonic() - oldest))

    def _take(self, count: int) -> list[_Pending]:
        """Pop the oldest ``count`` entries. Oldest first: Telegram is happier
        about deletions in order, and it keeps the log readable."""
        batch = self._queue[:count]
        del self._queue[:count]
        return batch

    # ------------------------------------------------------------------
    async def _send(self, batch: list[_Pending]) -> dict[int, str | None]:
        """Delete ``batch``, returning message id -> error, or None on success."""
        if not batch:
            return {}
        self.stats.batches += 1
        return await self._send_batch(batch, attempt=0)

    async def _send_batch(self, batch: list[_Pending], *, attempt: int) -> dict[int, str | None]:
        chat_id = batch[0].chat_id
        ids = [item.message_id for item in batch]
        detail: str

        try:
            if await self._bot.delete_messages(chat_id=chat_id, message_ids=ids):
                return dict.fromkeys(ids, None)
            # A False with no explanation says nothing about *which* message was
            # the problem, so splitting would be 100 blind retries against a rate
            # limit we are already near. Report the batch as failed and stop.
            logger.warning(
                "deleteMessages returned False for %d messages in chat %s; not retrying "
                "individually, because the failure cannot be attributed to one message",
                len(ids),
                chat_id,
            )
            return dict.fromkeys(ids, "deleteMessages returned False")
        except TelegramRetryAfter as exc:
            return await self._after_flood_wait(batch, attempt=attempt, exc=exc)
        except TelegramAPIError as exc:
            detail = str(exc)
            lowered = detail.lower()
            if any(marker in lowered for marker in _ALREADY_GONE):
                logger.debug("messages %s were already gone in chat %s", ids, chat_id)
                return dict.fromkeys(ids, None)
            # Split only for a *per-message* rejection, which the Bot API signals
            # with 400. A 403, or a missing right, applies to the whole call, and
            # halving it cannot help - it can only spend more calls.
            if not isinstance(exc, TelegramBadRequest) or any(
                marker in lowered for marker in _WHOLE_CALL_FAILURES
            ):
                logger.warning(
                    "batch delete failed for %d messages in chat %s and is not a "
                    "per-message problem: %s",
                    len(ids),
                    chat_id,
                    detail,
                )
                return dict.fromkeys(ids, detail)

        # A 400 with no whole-call marker: almost always one undeletable message
        # (older than 48 hours) poisoning the batch. Halve it, so the others
        # still go and the failure is attributed to the right id. The split is
        # always in half, so isolating one bad id in a full batch costs ~7 calls
        # rather than 100.
        if len(ids) <= 1:
            return dict.fromkeys(ids, detail)

        middle = len(batch) // 2
        logger.info(
            "batch delete of %d messages failed (%s); splitting to find the culprit",
            len(ids),
            detail,
        )
        return {
            **(await self._send_batch(batch[:middle], attempt=attempt)),
            **(await self._send_batch(batch[middle:], attempt=attempt)),
        }

    async def _after_flood_wait(
        self,
        batch: list[_Pending],
        *,
        attempt: int,
        exc: TelegramRetryAfter,
    ) -> dict[int, str | None]:
        """Wait out a 429 for exactly as long as Telegram asked, then retry."""
        ids = [item.message_id for item in batch]
        self.stats.flood_waits += 1
        wait = max(float(exc.retry_after), 0.0)

        if attempt >= self._max_retries:
            detail = f"flood wait after {self._max_retries} retries (last: {wait:.0f}s)"
            logger.warning("giving up on %d deletions: %s", len(ids), detail)
            return dict.fromkeys(ids, detail)

        # Honour the server's number, but never block shutdown indefinitely.
        capped = min(wait, self._retry_cap)
        logger.warning(
            "flood wait: Telegram asked for %.0fs before %d deletions; waiting %.0fs "
            "(attempt %d/%d)",
            wait,
            len(ids),
            capped,
            attempt + 1,
            self._max_retries,
        )
        await asyncio.sleep(capped)
        return await self._send_batch(batch, attempt=attempt + 1)

    # ------------------------------------------------------------------
    def _record(self, outcomes: dict[int, str | None]) -> None:
        """Tally and log what actually happened. Silence here means success."""
        if not outcomes:
            return
        succeeded = [mid for mid, error in outcomes.items() if error is None]
        failures = {mid: error for mid, error in outcomes.items() if error is not None}
        self.stats.deleted += len(succeeded)
        self.stats.failed += len(failures)

        if failures:
            for message_id, detail in failures.items():
                logger.warning(
                    "could not delete message %s: %s",
                    message_id,
                    detail,
                    extra={
                        "event": "delete_failed",
                        "message_id": message_id,
                        "detail": detail,
                    },
                )
        if len(succeeded) > 1:
            logger.info("deleted %d messages in one call", len(succeeded))


__all__ = ["MAX_BATCH", "DeleteQueue", "DeleteStats"]
