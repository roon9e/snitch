"""Startup sanity checks.

The overwhelmingly common reason a moderation bot "does nothing" is that the bot
is not an admin, or lacks *Delete messages*, or that privacy mode is still on so
it never receives group messages. Everything checkable is checked here, and a
missing capability that the configured punishment depends on is a hard boot
failure with an actionable message rather than a silent no-op.
"""

from __future__ import annotations

import logging

from aiogram import Bot
from aiogram.exceptions import TelegramAPIError
from aiogram.types import Chat, ChatMemberAdministrator, ChatMemberOwner, User

from snitch.config import Settings
from snitch.directory import Directory

logger = logging.getLogger(__name__)


class PreflightError(RuntimeError):
    """Raised when the bot cannot work with the given configuration."""


async def check_token(bot: Bot) -> User:
    """Validate the bot token. Raises :class:`PreflightError` if it is rejected.

    Split out from :func:`run` so that a bad token is reported before anything
    else is attempted, rather than after a screen of failed lookups.
    """
    try:
        me = await bot.get_me()
    except TelegramAPIError as exc:
        raise PreflightError(
            f"BOT_TOKEN looks invalid: {_describe(exc)}\n"
            "Get a fresh token from @BotFather via /token."
        ) from exc
    logger.info("signed in as @%s (id %s)", me.username, me.id)
    return me


async def run(
    bot: Bot,
    settings: Settings,
    directory: Directory,
    me: User | None = None,
) -> None:
    """Validate the environment. Raises :class:`PreflightError` on fatal issues."""
    await check_token(bot) if me is None else None

    chat = await _check_chat(bot, settings)
    await _check_rights(bot, settings, me.id if me is not None else (await bot.get_me()).id)
    _check_config(settings, directory)
    _check_topic_hint(chat, settings)


async def _check_chat(bot: Bot, settings: Settings) -> Chat:
    try:
        return await bot.get_chat(settings.chat_id)
    except TelegramAPIError as exc:
        raise PreflightError(
            f"cannot read CHAT_ID {settings.chat_id!r}: {_describe(exc)}\n"
            "The bot must be a member of the group. Forward any message from the "
            "group to @userinfobot to get the numeric id (it starts with -100)."
        ) from exc


async def _check_rights(bot: Bot, settings: Settings, bot_id: int) -> None:
    """Verify the admin capabilities the configured punishment relies on."""
    try:
        member = await bot.get_chat_member(chat_id=settings.chat_id, user_id=bot_id)
    except TelegramAPIError as exc:
        raise PreflightError(
            f"cannot read the bot's own member record in {settings.chat_id!r}: {_describe(exc)}"
        ) from exc

    if isinstance(member, ChatMemberOwner):
        logger.info("the bot is the chat owner - all rights available")
        return
    if not isinstance(member, ChatMemberAdministrator):
        raise PreflightError(
            "the bot is not an administrator in the chat.\n"
            "Promote it: Manage chat -> Administrators -> add the bot, and grant "
            "'Delete messages'. Without admin rights it cannot delete anything."
        )

    missing: list[str] = []
    if settings.delete_message and not member.can_delete_messages:
        missing.append("Delete messages")
    if settings.mute_enabled and not member.can_restrict_members:
        missing.append("Ban users")
    if not settings.mute_enabled and not member.can_restrict_members:
        logger.warning(
            "the bot cannot restrict members ('Ban users' is off), so MUTE_ENABLED and "
            "/unmute will not work. This is fine while MUTE_ENABLED=false."
        )

    if missing:
        raise PreflightError(
            "the bot is missing admin rights required by the current configuration: "
            + ", ".join(missing)
            + ".\nPromote the bot again and enable: "
            + ", ".join(f"'{right}'" for right in missing)
            + "."
        )
    logger.info(
        "bot admin rights verified (delete=%s, restrict=%s)",
        member.can_delete_messages,
        member.can_restrict_members,
    )


def _check_config(settings: Settings, directory: Directory) -> None:
    """Warn about configurations that are valid but will not do anything useful."""
    if not settings.restricted_users:
        raise PreflightError("RESTRICTED_USERS is empty - there is no rule to enforce.")
    if not directory:
        raise PreflightError(
            "no entry in RESTRICTED_USERS could be resolved in the chat, so nothing "
            "can ever be detected. Check that those users are still members of the group."
        )
    if not settings.detection_enabled:
        raise PreflightError(
            "every detector is disabled (DETECT_REPLIES, DETECT_MENTIONS and "
            "DETECT_BARE_USERNAMES are all false) - no message could ever be a violation."
        )
    if not settings.delete_message and not settings.mute_enabled:
        raise PreflightError(
            "both DELETE_MESSAGE and MUTE_ENABLED are false, so a violation would be "
            "logged and nothing else would happen."
        )
    if settings.detect_bare_usernames and not directory.usernames:
        logger.warning(
            "DETECT_BARE_USERNAMES is on but no restricted user has a public username, "
            "so bare-text detection cannot work. Use numeric user ids, or accept that "
            "only replies and mentions will be caught."
        )


def _check_topic_hint(chat: Chat, settings: Settings) -> None:
    """Warn when topic whitelisting is configured but the chat has no topics."""
    if not settings.whitelist_topic_ids:
        return
    if not getattr(chat, "is_forum", False):
        logger.warning(
            "WHITELIST_TOPIC_IDS is set but %s is not a forum supergroup, so no message "
            "will ever carry a message_thread_id and the whitelist will never apply. "
            "Enable 'Topics' in the chat settings.",
            settings.chat_id,
        )
    else:
        logger.info(
            "topic whitelist active: %s (general=%s)",
            sorted(settings.whitelist_thread_ids) or "none",
            settings.whitelist_general,
        )


def _describe(exc: TelegramAPIError) -> str:
    """Human readable string for a Telegram error."""
    return str(getattr(exc, "message", None) or exc)
