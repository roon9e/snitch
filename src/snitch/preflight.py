"""Startup sanity checks.

The overwhelmingly common reason a moderation bot "does nothing" is that the bot
is not an admin, lacks *Delete messages*, has privacy mode still on so it never
receives group messages, or is pointed at a chat it is not a member of. Everything
checkable is checked here, in dependency order, and each failure carries an
actionable message.

Failures are also classified as permanent or transient. A wrong chat id will
still be wrong in thirty seconds, so the process should exit and let the operator
look at the logs; a Telegram 502 should be retried instead of crash-looping the
container forever.
"""

from __future__ import annotations

import asyncio
import logging

import aiohttp
from aiogram import Bot
from aiogram.exceptions import TelegramAPIError, TelegramRetryAfter, TelegramServerError
from aiogram.types import Chat, ChatMemberAdministrator, ChatMemberOwner, User

from snitch.config import Settings
from snitch.directory import Directory

logger = logging.getLogger(__name__)

#: Errors that are worth retrying rather than giving up on.
_TRANSIENT_ERRORS: tuple[type[BaseException], ...] = (
    TelegramServerError,
    TelegramRetryAfter,
    aiohttp.ClientError,
    asyncio.TimeoutError,
    OSError,
)


class PreflightError(RuntimeError):
    """Raised when the bot cannot work with the given configuration.

    ``permanent`` distinguishes "the operator must change something" from "try
    again shortly"; only the latter should be retried.
    """

    def __init__(self, message: str, *, permanent: bool = True) -> None:
        super().__init__(message)
        self.permanent = permanent


def is_transient(exc: BaseException) -> bool:
    """Whether a failure is worth retrying."""
    if isinstance(exc, PreflightError):
        return not exc.permanent
    return isinstance(exc, _TRANSIENT_ERRORS)


def check_local(settings: Settings) -> None:
    """Validate everything that can be decided without touching the network.

    Run before the token check so an obviously wrong CHAT_ID is reported
    immediately, rather than after a round trip to Telegram.
    """
    _check_chat_id_shape(settings)


async def check_token(bot: Bot) -> User:
    """Validate the bot token.

    Split out from :func:`run` so that a bad token is reported before anything
    else is attempted, rather than after a screen of failed lookups.
    """
    try:
        me = await bot.get_me()
    except TelegramAPIError as exc:
        raise PreflightError(
            f"BOT_TOKEN looks invalid: {_describe(exc)}\n"
            "Get a fresh token from @BotFather via /token.",
            permanent=not is_transient(exc),
        ) from exc
    logger.info("signed in as @%s (id %s)", me.username, me.id)
    return me


async def check_chat(bot: Bot, settings: Settings) -> Chat:
    """Verify the bot can actually see the chat it is configured to guard."""
    try:
        chat = await bot.get_chat(settings.chat_id)
    except TelegramAPIError as exc:
        raise PreflightError(
            f"cannot read CHAT_ID {settings.chat_id!r}: {_describe(exc)}\n"
            "\n"
            "Telegram answers 'chat not found' for both of these, so check them in order:\n"
            "  1. Is the bot actually a member of the group? Add it, then promote it\n"
            "     to admin with 'Delete messages'.\n"
            "  2. Is CHAT_ID the CURRENT id? A group that becomes a supergroup is\n"
            "     assigned a brand new id, so any id copied earlier is now stale.\n"
            "\n"
            "To read the current id from inside the group, send /id to the bot - it\n"
            "replies with CHAT_ID and the current topic id. Or forward a group message\n"
            "to @userinfobot.",
            permanent=not is_transient(exc),
        ) from exc

    _check_chat_type(chat, settings)
    return chat


def _check_chat_id_shape(settings: Settings) -> None:
    """Catch the most common misconfiguration before touching the network.

    Supergroup ids are always ``-100...``. A plain negative number is a *basic*
    group id, which is either stale or a group that was never upgraded - and a
    basic group supports neither topics nor member restrictions.
    """
    chat_id = settings.chat_id

    if isinstance(chat_id, str):
        # Settings normalises this, but be defensive: a numeric string still has
        # to be shape checked, and a @username has nothing to check.
        stripped = chat_id.strip()
        if not stripped or stripped.startswith("@"):
            return
        try:
            chat_id = int(stripped)
        except ValueError:
            raise PreflightError(
                f"CHAT_ID {chat_id!r} is neither a numeric group id nor an @username."
            ) from None

    text = str(chat_id)
    if text.startswith("-100"):
        return
    if chat_id < 0:
        raise PreflightError(
            f"CHAT_ID {chat_id} is a basic group id, not a supergroup id.\n"
            "\n"
            "snitch needs a supergroup: 'restrictChatMember' (the mute) and forum\n"
            "topics (WHITELIST_TOPIC_IDS) do not exist in a basic group. Basic\n"
            "group ids look like -123456789; supergroup ids look like -1001234567890.\n"
            "\n"
            "Telegram also assigns a NEW id when a group is upgraded to a supergroup,\n"
            "so if this group was ever upgraded or had Topics enabled, this number is\n"
            "stale. Enable Topics in the group settings, then send /id to the bot to\n"
            "read the current CHAT_ID."
        )
    raise PreflightError(
        f"CHAT_ID {chat_id} is not a chat id. Group ids are negative and start with\n"
        "-100, e.g. -1001234567890. Forward a group message to @userinfobot to get it."
    )


def _check_chat_type(chat: Chat, settings: Settings) -> None:
    """Warn or fail when the chat cannot support the configured features."""
    if chat.type != "group":
        return

    needs_supergroup = settings.mute_enabled or bool(settings.whitelist_topic_ids)
    detail = (
        f"CHAT_ID {settings.chat_id} is a basic group, which supports neither the mute\n"
        "(restrictChatMember) nor forum topics (WHITELIST_TOPIC_IDS). Only message\n"
        "deletion will work. Enable Topics in the group settings to upgrade it to a\n"
        "supergroup - note that this changes CHAT_ID, so re-read it with /id afterwards."
    )
    if needs_supergroup:
        raise PreflightError(detail)
    logger.warning("%s", detail)


async def check_rights(bot: Bot, settings: Settings, bot_id: int) -> None:
    """Verify the admin capabilities the configured punishment relies on."""
    try:
        member = await bot.get_chat_member(chat_id=settings.chat_id, user_id=bot_id)
    except TelegramAPIError as exc:
        raise PreflightError(
            f"cannot read the bot's own member record in {settings.chat_id!r}: {_describe(exc)}",
            permanent=not is_transient(exc),
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


def check_config(settings: Settings, directory: Directory) -> None:
    """Reject configurations that are valid but could never do anything."""
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


def check_topic_hint(chat: Chat, settings: Settings) -> None:
    """Warn when topic whitelisting is configured but the chat has no topics."""
    if not settings.whitelist_topic_ids:
        return
    if not getattr(chat, "is_forum", False):
        logger.warning(
            "WHITELIST_TOPIC_IDS is set but %s has no topics enabled, so no message "
            "will ever carry a message_thread_id and the whitelist will never apply. "
            "Enable 'Topics' in the chat settings.",
            settings.chat_id,
        )
        return
    logger.info(
        "topic whitelist active: %s (general=%s)",
        sorted(settings.whitelist_thread_ids) or "none",
        settings.whitelist_general,
    )


def _describe(exc: TelegramAPIError) -> str:
    """Human readable string for a Telegram error."""
    return str(getattr(exc, "message", None) or exc)
