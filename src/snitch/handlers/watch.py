"""The message watcher: the pipeline described in the README, in order.

Every early return here is a cheap, local check. Telegram is only contacted once
a message has already been proven to be a violation, so a busy group costs the
bot nothing.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass

from aiogram import Bot
from aiogram.types import ChatMemberAdministrator, ChatMemberOwner, Message

from snitch.config import Settings
from snitch.detection import Detection, detect, is_whitelisted
from snitch.directory import DirectoryHolder
from snitch.services.moderator import Moderator, ViolationResult

logger = logging.getLogger(__name__)

#: Statuses that must never be moderated.
_PROTECTED = frozenset({"creator", "administrator", "owner"})

#: How many recent messages /check can reason about.
SAMPLE_SIZE = 50

#: Seconds an admin-status lookup is reused before being refreshed.
_ADMIN_CACHE_TTL = 60.0


@dataclass(slots=True)
class Sample:
    """One remembered message, so ``/check`` can explain past decisions."""

    message: Message
    was_violation: bool
    target_summary: str


class RecentSamples:
    """Bounded ring buffer of recent messages."""

    def __init__(self, size: int = SAMPLE_SIZE) -> None:
        self._items: deque[Sample] = deque(maxlen=size)

    def add(self, message: Message, was_violation: bool, detection: Detection) -> None:
        self._items.append(
            Sample(
                message=message,
                was_violation=was_violation,
                target_summary=detection.summary() if was_violation else "",
            )
        )

    def all(self) -> tuple[Sample, ...]:
        """Newest last."""
        return tuple(self._items)

    def __len__(self) -> int:
        return len(self._items)


class Watcher:
    """Decides whether a message violates the rule, and punishes it if so."""

    def __init__(
        self,
        bot: Bot,
        settings: Settings,
        directory: DirectoryHolder,
        moderator: Moderator,
        samples: RecentSamples,
    ) -> None:
        self._bot = bot
        self._settings = settings
        self._directory = directory
        self._moderator = moderator
        self._samples = samples
        # Admins change rarely, but not never: cache with a short TTL so a
        # promotion or demotion is picked up without an API call per message.
        self._admin_cache: dict[int, tuple[bool, float]] = {}

    async def handle(self, message: Message) -> ViolationResult | None:
        """Process one message. Returns a result only when it was a violation."""
        if not self._is_watched(message):
            return None

        if is_whitelisted(message, self._settings):
            logger.debug(
                "message %s ignored: whitelisted topic %s",
                message.message_id,
                message.message_thread_id if message.message_thread_id is not None else "general",
            )
            return None

        detection = detect(message, self._settings, self._directory.current)
        self._samples.add(message, bool(detection), detection)
        if not detection:
            return None

        if self._settings.ignore_admins and await self._is_admin(message):
            logger.warning(
                "message %s would have been a violation but the author is an admin; "
                "bots cannot restrict admins, so skipping",
                message.message_id,
            )
            return None

        logger.info(
            "violation detected: message %s in thread %s addresses %s",
            message.message_id,
            message.message_thread_id,
            detection.summary(),
        )
        return await self._moderator.handle(message, detection)

    # ------------------------------------------------------------------
    def _is_watched(self, message: Message) -> bool:
        """Cheap, purely local gate: is this message even in scope?"""
        if message.chat.id != self._settings.chat_id:
            return False
        # A sender_chat means an anonymous admin or a channel post; there is no
        # user to punish and the rule is about people.
        if message.from_user is None or message.sender_chat is not None:
            return False
        if message.from_user.is_bot:
            return False
        return self._directory.current.matches(user_id=message.from_user.id)

    async def _is_admin(self, message: Message) -> bool:
        """Whether the author currently holds an admin right (cached briefly)."""
        assert message.from_user is not None
        user_id = message.from_user.id
        now = time.monotonic()
        cached = self._admin_cache.get(user_id)
        if cached is not None and (now - cached[1]) < _ADMIN_CACHE_TTL:
            return cached[0]
        try:
            member = await self._bot.get_chat_member(
                chat_id=message.chat.id,
                user_id=user_id,
            )
        except Exception as exc:
            # A failed lookup must never be fatal: the worst case is that a
            # genuine admin is punished once.
            logger.debug("admin lookup failed for %s: %s", user_id, exc)
            return False
        privileged = member.status in _PROTECTED or isinstance(
            member, (ChatMemberOwner, ChatMemberAdministrator)
        )
        self._admin_cache[user_id] = (privileged, now)
        return privileged
