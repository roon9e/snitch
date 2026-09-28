"""Optional operator-facing notifications after a violation.

``NOTICE_MODE`` picks one of four behaviours; ``log`` is the default so the bot
stays quiet in the chat and simply records what happened.
"""

from __future__ import annotations

import logging

from aiogram import Bot
from aiogram.exceptions import TelegramAPIError
from aiogram.types import Message

from snitch.config import NoticeMode, Settings
from snitch.detection import Detection

logger = logging.getLogger(__name__)


class Notifier:
    """Sends the configured notice, swallowing any Telegram failure."""

    def __init__(self, bot: Bot, settings: Settings) -> None:
        self._bot = bot
        self._mode = settings.notice_mode

    async def notify(
        self,
        message: Message,
        detection: Detection,
        muted_for_hours: int | None,
    ) -> None:
        """Report a violation according to ``NOTICE_MODE``."""
        if self._mode is NoticeMode.NONE:
            return

        actor = describe_user(message)
        if self._mode is NoticeMode.LOG:
            logger.warning(
                "violation: %s addressed a restricted user via %s in chat %s (thread %s)",
                actor,
                detection.summary(),
                message.chat.id,
                message.message_thread_id,
            )
            return

        text = build_notice_text(
            actor=actor,
            detection=detection,
            muted_for_hours=muted_for_hours,
            include_actor=self._mode is NoticeMode.CHAT,
        )

        if self._mode is NoticeMode.CHAT:
            await self._post_in_chat(message, text)
        else:
            await self._post_dm(message, actor, text)

    async def _post_in_chat(self, message: Message, text: str) -> None:
        try:
            await self._bot.send_message(
                chat_id=message.chat.id,
                text=text,
                message_thread_id=message.message_thread_id,
                disable_web_page_preview=True,
            )
        except TelegramAPIError as exc:
            logger.warning("could not post violation notice in chat: %s", exc)

    async def _post_dm(self, message: Message, actor: str, text: str) -> None:
        user = message.from_user
        if user is None:  # pragma: no cover - callers filter this out
            return
        try:
            await self._bot.send_message(chat_id=user.id, text=text, disable_web_page_preview=True)
        except TelegramAPIError as exc:
            # Overwhelmingly "bot can't initiate conversation with the user" -
            # the offender has never started the bot in private. Not an error.
            logger.info("could not DM %s about the violation: %s", actor, exc)


def build_notice_text(
    *,
    actor: str,
    detection: Detection,
    muted_for_hours: int | None,
    include_actor: bool,
) -> str:
    """Assemble the human readable notice body."""
    head = f"{actor} " if include_actor else ""
    text = f"{head}had a message removed for addressing a restricted user ({detection.summary()})."
    if muted_for_hours:
        text += f" Muted for {muted_for_hours}h."
    return text


def describe_user(message: Message) -> str:
    """``@alice`` / ``Alice`` label for a message author."""
    user = message.from_user
    if user is None:  # pragma: no cover - callers filter this out
        return "<unknown>"
    if user.username:
        return f"@{user.username}"
    name = " ".join(part for part in (user.first_name, user.last_name) if part).strip()
    return name or str(user.id)
