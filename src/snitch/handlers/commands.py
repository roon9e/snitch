"""Bot commands.

Only ``/id`` is open to everyone; the rest are gated on ``ADMIN_IDS`` or on being
a chat administrator. ``/check`` is the tuning tool: it replays the rule over the
recent message buffer so detection can be validated before ``MUTE_ENABLED`` is
turned on.
"""

from __future__ import annotations

import logging
from html import escape

from aiogram import Bot, Router
from aiogram.exceptions import TelegramAPIError
from aiogram.filters import Command, CommandObject
from aiogram.types import Message

from snitch.config import Settings
from snitch.detection import detect, is_whitelisted
from snitch.directory import DirectoryHolder
from snitch.handlers.watch import RecentSamples
from snitch.services.audit import AuditLog
from snitch.services.moderator import Moderator

logger = logging.getLogger(__name__)

_HELP = (
    "<b>snitch</b> - enforcing a no-contact rule between restricted users.\n\n"
    "<code>/id</code> - chat id, your user id, current topic id\n"
    "<code>/status</code> - active config, restricted users, recent punishments\n"
    "<code>/check</code> - replay the rule over recent messages (tuning aid)\n"
    "<code>/unmute &lt;user_id|@username&gt;</code> - lift a restriction early\n"
    "<code>/help</code> - this text"
)


def build_router(
    bot: Bot,
    settings: Settings,
    directory: DirectoryHolder,
    moderator: Moderator,
    samples: RecentSamples,
    audit: AuditLog,
) -> Router:
    """Wire up the command handlers with their dependencies.

    A fresh ``Router`` is returned per call: an ``aiogram`` Router can only be
    attached to a single parent, so sharing a module level one would make the
    second ``build_router`` call fail.
    """
    router = Router(name="commands")

    async def _is_authorized(message: Message) -> bool:
        if message.from_user is None:
            return False
        if message.from_user.id in settings.admin_ids:
            return True
        try:
            member = await bot.get_chat_member(
                chat_id=settings.chat_id,
                user_id=message.from_user.id,
            )
        except TelegramAPIError:
            return False
        return member.status in ("creator", "administrator", "owner")

    @router.message(Command("id"))
    async def cmd_id(message: Message) -> None:
        """Report the identifiers you need to fill in ``.env``."""
        thread = (
            message.message_thread_id
            if message.message_thread_id is not None
            else "General topic (no message_thread_id)"
        )
        user = message.from_user
        await message.answer(
            "Identities for your <code>.env</code>\n\n"
            f"<code>CHAT_ID</code> = {message.chat.id}\n"
            f"<code>your user id</code> = {user.id if user else 'n/a'}\n"
            f"<code>message_thread_id</code> = {thread}",
            disable_web_page_preview=True,
        )

    @router.message(Command("help", "start"))
    async def cmd_help(message: Message) -> None:
        await message.answer(_HELP, disable_web_page_preview=True)

    @router.message(Command("status"))
    async def cmd_status(message: Message) -> None:
        if not await _is_authorized(message):
            await _deny(message)
            return

        lines = ["<b>Active configuration</b>"]
        for key, value in settings.redacted_summary().items():
            if key == "bot_token":
                continue
            lines.append(f"<code>{key}</code> = {escape(str(value))}")

        lines.append("")
        current = directory.current
        lines.append(f"<b>Restricted users ({len(current)})</b>")
        if not current:
            lines.append("- <i>none resolved</i>")
        for entry in current.entries:
            status = await moderator.member_status(settings.chat_id, entry.user_id)
            handle = f"@{entry.username}" if entry.username else str(entry.user_id)
            lines.append(f"- {escape(handle)} (<code>{entry.user_id}</code>): {status}")

        for reference in current.unresolved:
            lines.append(f"- <i>unresolved: {escape(reference)}</i>")
        for note in current.stale_usernames:
            lines.append(f"- <i>drift: {escape(note)}</i>")

        recent = audit.tail(5)
        if recent:
            lines.append("")
            lines.append("<b>Last violations</b>")
            lines.extend(f"<code>{escape(line[:400])}</code>" for line in reversed(recent))

        await message.answer(
            "\n".join(lines),
            disable_web_page_preview=True,
        )

    @router.message(Command("check"))
    async def cmd_check(message: Message) -> None:
        if not await _is_authorized(message):
            await _deny(message)
            return

        buffered = samples.all()
        if not buffered:
            await message.answer("No messages buffered yet. Try again in a minute.")
            return

        lines = [f"<b>Replaying the rule over {len(buffered)} recent messages</b>", ""]
        lines.append(
            f"detectors: replies={settings.detect_replies}, "
            f"mentions={settings.detect_mentions}, "
            f"bare={settings.detect_bare_usernames}"
        )
        lines.append("")

        would_block = 0
        current_directory = directory.current
        for sample in buffered:
            current = detect(sample.message, settings, current_directory)
            verdict = "BLOCK" if current else "pass"
            if current:
                would_block += 1
            note = (
                current.summary()
                if current
                else ("whitelisted topic" if is_whitelisted(sample.message, settings) else "-")
            )
            lines.append(f"<code>{sample.message.message_id}</code> {verdict} {escape(note)}")

        lines.append("")
        lines.append(f"<b>{would_block} of {len(buffered)}</b> would be blocked now.")
        await message.answer(
            "\n".join(lines)[:4000],
            disable_web_page_preview=True,
        )

    @router.message(Command("unmute"))
    async def cmd_unmute(message: Message, command: CommandObject) -> None:
        if not await _is_authorized(message):
            await _deny(message)
            return
        argument = (command.args or "").strip()
        if not argument:
            await message.answer("Usage: <code>/unmute &lt;user_id|@username&gt;</code>")
            return

        reference: int | str
        if argument.lstrip("-").isdigit():
            reference = int(argument)
        else:
            user_id = directory.current.find_by_username(argument)
            if user_id is None:
                await message.answer(
                    f"{escape(argument)} is not in RESTRICTED_USERS, so there is nothing "
                    f"to unmute. This command only lifts snitch's own mutes."
                )
                return
            reference = user_id

        try:
            await moderator.unmute(settings.chat_id, reference)
        except TelegramAPIError as exc:
            logger.warning("unmute failed for %s: %s", reference, exc)
            await message.answer(f"Could not lift the restriction: {escape(str(exc))}")
            return
        await message.answer(
            f"Restrictions lifted for <code>{reference}</code>.", disable_web_page_preview=True
        )

    async def _deny(message: Message) -> None:
        logger.warning(
            "denied %s (%s): not in ADMIN_IDS and not a chat admin",
            message.from_user.id if message.from_user else "?",
            message.from_user.username if message.from_user else "?",
        )
        await message.answer("This command is for chat administrators only.")

    return router
