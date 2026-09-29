"""Punishment orchestration: delete, then optionally mute.

Design rules that this module exists to enforce:

* **Delete first.** Removing the message is the punishment that actually works
  per-message (and therefore respects the topic whitelist), so it happens before
  anything slower.
* **Never raise into the dispatcher.** A single Telegram failure is recorded in
  the returned result and logged; it must not take the update loop down.
* **Never stack mutes.** A message flood must not extend a mute on every message
  or hammer the API, hence the per-user lock plus cooldown, and the refusal to
  re-mute somebody who is already under an active restriction.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from aiogram import Bot
from aiogram.exceptions import TelegramAPIError
from aiogram.types import Message

from snitch.config import Settings
from snitch.detection import Detection
from snitch.directory import DirectoryHolder
from snitch.permissions import (
    MUTE_PERMISSIONS,
    UNMUTE_PERMISSIONS,
    USE_INDEPENDENT_PERMISSIONS,
)
from snitch.services.audit import AuditLog
from snitch.services.delete_queue import DeleteQueue
from snitch.services.notifier import Notifier, describe_user

logger = logging.getLogger(__name__)

#: Statuses that a bot is not allowed to restrict.
_UNRESTRICTABLE = frozenset({"creator", "administrator", "owner"})


class MuteOutcome(str, Enum):
    """Why a mute did or did not happen."""

    DISABLED = "disabled"
    APPLIED = "applied"
    ALREADY_MUTED = "already_muted"
    COOLDOWN = "cooldown"
    NOT_PERMITTED = "not_permitted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ViolationResult:
    """Everything that was attempted for one violation."""

    deleted: bool
    delete_error: str | None
    mute: MuteOutcome
    mute_until: datetime | None = None
    mute_error: str | None = None

    def summary(self) -> str:
        """One line for logs."""
        delete = "deleted" if self.deleted else f"delete failed ({self.delete_error})"
        mute = self.mute.value
        if self.mute is MuteOutcome.APPLIED and self.mute_until is not None:
            until = self.mute_until.isoformat(timespec="seconds")
            mute = f"muted until {until}"
        return f"{delete}; mute={mute}"


class Moderator:
    """Applies the punishment for a detected violation."""

    def __init__(
        self,
        bot: Bot,
        settings: Settings,
        directory: DirectoryHolder,
        audit: AuditLog,
        notifier: Notifier,
    ) -> None:
        self._bot = bot
        self._settings = settings
        self._directory = directory
        self._audit = audit
        self._notifier = notifier
        self._locks: defaultdict[int, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._last_mute_attempt: dict[int, float] = {}
        # Batched deletion. Kept per Moderator so there is one code path for
        # every deletion, in production and under test alike.
        self._deletes = DeleteQueue(
            bot,
            batch_size=settings.delete_batch_size,
            flush_seconds=settings.delete_flush_seconds,
        )

    # ------------------------------------------------------------------
    async def handle(self, message: Message, detection: Detection) -> ViolationResult:
        """Punish ``message``'s author. Never raises."""
        sender = message.from_user
        assert sender is not None, "handle() called for a message without a sender"

        await self._deletes.start()
        async with self._locks[sender.id]:
            deleted, delete_error = await self._delete(message)
            mute, mute_until, mute_error = await self._mute(message, sender.id)

        result = ViolationResult(
            deleted=deleted,
            delete_error=delete_error,
            mute=mute,
            mute_until=mute_until,
            mute_error=mute_error,
        )
        self._audit_message(message, detection, result)
        await self._notifier.notify(
            message,
            detection,
            self._settings.mute_hours if mute is MuteOutcome.APPLIED else None,
        )
        return result

    # ------------------------------------------------------------------
    async def flush_deletes(self) -> None:
        """Send every queued deletion now. Used by tests and by shutdown."""
        await self._deletes.flush()

    async def close_deletes(self) -> None:
        """Stop the delete worker after a final flush.

        Must run on shutdown: a queued deletion that is never flushed is a
        message left sitting in the group, which is the failure this queue
        creates and therefore also the one it has to clean up.
        """
        await self._deletes.close()

    # ------------------------------------------------------------------
    async def _delete(self, message: Message) -> tuple[bool, str | None]:
        """Remove the offending message.

        A lone violation is deleted inline, so its outcome is known exactly and
        reported exactly. Under a burst the message is queued and ``True`` here
        means "Telegram has been asked" - the flush logs what really happened,
        per message, when the answer arrives.
        """
        if not self._settings.delete_message:
            return False, None

        try:
            outcome = await self._deletes.enqueue(message.chat.id, message.message_id)
        except TelegramAPIError as exc:
            failure = _describe_api_error(exc)
            logger.warning("could not delete message %s: %s", message.message_id, failure)
            return False, failure

        if outcome is None:
            return True, None  # queued; the flush will report the result
        error = outcome.get(message.message_id)
        if error is not None:
            return False, error
        return True, None

    async def _mute(
        self,
        message: Message,
        user_id: int,
    ) -> tuple[MuteOutcome, datetime | None, str | None]:
        """Apply the native Telegram restriction, if enabled."""
        if not self._settings.mute_enabled:
            return MuteOutcome.DISABLED, None, None

        cooldown = self._settings.mute_cooldown_seconds
        last = self._last_mute_attempt.get(user_id)
        now = time.monotonic()
        if last is not None and (now - last) < cooldown:
            return MuteOutcome.COOLDOWN, None, None
        self._last_mute_attempt[user_id] = now

        try:
            member = await self._bot.get_chat_member(
                chat_id=message.chat.id,
                user_id=user_id,
            )
        except TelegramAPIError as exc:
            detail = _describe_api_error(exc)
            logger.warning("could not read member %s before muting: %s", user_id, detail)
            return MuteOutcome.FAILED, None, detail

        if member.status in _UNRESTRICTABLE:
            return MuteOutcome.NOT_PERMITTED, None, f"status={member.status}"

        if member.status == "restricted":
            until = getattr(member, "until_date", None)
            if until is None or until > datetime.now(tz=timezone.utc):
                # Refuse to extend an active mute: otherwise a message flood
                # would turn an N hour penalty into an indefinite one.
                return MuteOutcome.ALREADY_MUTED, None, None

        until_date = datetime.now(tz=timezone.utc) + timedelta(hours=self._settings.mute_hours)
        try:
            await self._bot.restrict_chat_member(
                chat_id=message.chat.id,
                user_id=user_id,
                permissions=MUTE_PERMISSIONS,
                use_independent_chat_permissions=USE_INDEPENDENT_PERMISSIONS,
                until_date=until_date,
            )
        except TelegramAPIError as exc:
            detail = _describe_api_error(exc)
            logger.warning("could not mute %s: %s", user_id, detail)
            return MuteOutcome.FAILED, None, detail

        return MuteOutcome.APPLIED, until_date, None

    # ------------------------------------------------------------------
    async def unmute(self, chat_id: int | str, user_id: int | str) -> None:
        """Lift a restriction early. Raises ``TelegramAPIError`` on failure."""
        # user_id is typed int by aiogram, but the Bot API also accepts @username.
        await self._bot.restrict_chat_member(
            chat_id=chat_id,
            user_id=user_id,  # type: ignore[arg-type]
            permissions=UNMUTE_PERMISSIONS,
            use_independent_chat_permissions=USE_INDEPENDENT_PERMISSIONS,
            until_date=0,
        )
        logger.info("lifted restrictions for %s in chat %s", user_id, chat_id)

    async def member_status(self, chat_id: int | str, user_id: int | str) -> str:
        """Human readable status of a member, for the /status command."""
        try:
            member = await self._bot.get_chat_member(
                chat_id=chat_id,
                user_id=user_id,  # type: ignore[arg-type]
            )
        except TelegramAPIError as exc:
            return f"unknown ({_describe_api_error(exc)})"
        if member.status == "restricted":
            until = getattr(member, "until_date", None)
            if until is None:
                return "restricted indefinitely"
            if until > datetime.now(tz=timezone.utc):
                return f"muted until {until.isoformat(timespec='seconds')}"
            return "restriction expired"
        return member.status

    # ------------------------------------------------------------------
    def _audit_message(
        self,
        message: Message,
        detection: Detection,
        result: ViolationResult,
    ) -> None:
        """Append one structured record. Logging always happens; the file is best effort."""
        sender = message.from_user
        assert sender is not None
        logger.warning(
            "violation in chat %s thread %s: %s -> %s [%s]",
            message.chat.id,
            message.message_thread_id,
            self._directory.current.label(sender.id),
            detection.summary(),
            result.summary(),
            extra={
                "event": "violation",
                "chat_id": message.chat.id,
                "thread_id": message.message_thread_id,
                "user_id": sender.id,
                "username": sender.username,
                "message_id": message.message_id,
                "targets": detection.summary(),
                "words": list(detection.words),
                "rule": "word" if detection.by_word else "contact",
                "deleted": result.deleted,
                "mute_outcome": result.mute.value,
            },
        )
        self._audit.record(
            event="violation",
            rule="word" if detection.by_word else "contact",
            chat_id=message.chat.id,
            thread_id=message.message_thread_id,
            user_id=sender.id,
            username=sender.username,
            author=describe_user(message),
            message_id=message.message_id,
            message_excerpt=_excerpt(message),
            targets=[target.describe() for target in detection.targets],
            words=list(detection.words),
            deleted=result.deleted,
            delete_error=result.delete_error,
            mute=result.mute.value,
            mute_until=result.mute_until.isoformat() if result.mute_until else None,
            mute_error=result.mute_error,
        )


def _describe_api_error(exc: TelegramAPIError) -> str:
    """Human readable string for a Telegram error.

    ``TelegramAPIError`` carries the server's text in ``message``; there is no
    separate ``description`` attribute.
    """
    return str(getattr(exc, "message", None) or exc)


def _excerpt(message: Message, limit: int = 120) -> str:
    """A short, log-safe preview of the offending content."""
    source = message.text or message.caption or ""
    source = " ".join(source.split())
    if len(source) > limit:
        return f"{source[:limit]}..."
    return source
