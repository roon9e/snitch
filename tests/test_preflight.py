"""Startup guards.

The point of preflight is to refuse to run rather than silently guard nothing, so
these tests pin down the fatal conditions and the messages operators will read.
"""

from __future__ import annotations

from typing import Any

import pytest
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import (
    Chat,
    ChatMemberAdministrator,
    ChatMemberMember,
    ChatMemberOwner,
    User,
)

from snitch import preflight
from snitch.preflight import PreflightError
from tests.conftest import ALICE_ID, BOB_ID, make_directory, make_settings, make_user


class PreflightBot:
    """Serves just the four calls preflight makes."""

    def __init__(
        self,
        *,
        member_status: str = "administrator",
        can_delete_messages: bool = True,
        can_restrict_members: bool = True,
        is_forum: bool = True,
        get_me_error: Exception | None = None,
        get_chat_error: Exception | None = None,
    ) -> None:
        self.member_status = member_status
        self.can_delete_messages = can_delete_messages
        self.can_restrict_members = can_restrict_members
        self.is_forum = is_forum
        self.get_me_error = get_me_error
        self.get_chat_error = get_chat_error
        self.bot_user = make_user(999, "snitchbot", is_bot=True)

    async def get_me(self) -> User:
        if self.get_me_error:
            raise self.get_me_error
        return self.bot_user

    async def get_chat(self, chat_id: Any) -> Chat:
        if self.get_chat_error:
            raise self.get_chat_error
        return Chat.model_construct(id=chat_id, type="supergroup", is_forum=self.is_forum)

    async def get_chat_member(self, **kwargs: Any) -> Any:
        if kwargs.get("user_id") == self.bot_user.id:
            if self.member_status == "creator":
                return ChatMemberOwner.model_construct(
                    status="creator", user=self.bot_user, is_anonymous=False
                )
            if self.member_status == "member":
                return ChatMemberMember.model_construct(status="member", user=self.bot_user)
            return ChatMemberAdministrator.model_construct(
                status="administrator",
                user=self.bot_user,
                is_anonymous=False,
                can_delete_messages=self.can_delete_messages,
                can_restrict_members=self.can_restrict_members,
            )
        return ChatMemberMember.model_construct(
            status="member", user=make_user(int(kwargs["user_id"]), "alice")
        )


def api_error(text: str) -> TelegramBadRequest:
    return TelegramBadRequest(method=None, message=text)


# ===========================================================================
# fatal: the token
# ===========================================================================
async def test_invalid_token_is_fatal():
    bot = PreflightBot(get_me_error=api_error("Bad Request: Unauthorized"))

    with pytest.raises(PreflightError, match="BOT_TOKEN looks invalid"):
        await preflight.run(bot, make_settings(), make_directory())  # type: ignore[arg-type]


# ===========================================================================
# fatal: the chat
# ===========================================================================
async def test_unreadable_chat_is_fatal():
    bot = PreflightBot(get_chat_error=api_error("Bad Request: chat not found"))

    with pytest.raises(PreflightError, match="cannot read CHAT_ID"):
        await preflight.run(bot, make_settings(), make_directory())  # type: ignore[arg-type]


# ===========================================================================
# fatal: admin rights
# ===========================================================================
async def test_non_admin_bot_is_fatal():
    bot = PreflightBot(member_status="member")

    with pytest.raises(PreflightError, match="not an administrator"):
        await preflight.run(bot, make_settings(), make_directory())  # type: ignore[arg-type]


async def test_missing_delete_right_is_fatal_when_deletion_is_on():
    bot = PreflightBot(can_delete_messages=False)

    with pytest.raises(PreflightError, match="Delete messages"):
        await preflight.run(bot, make_settings(), make_directory())  # type: ignore[arg-type]


async def test_missing_restrict_right_is_fatal_when_muting_is_on():
    bot = PreflightBot(can_restrict_members=False)
    settings = make_settings(mute_enabled=True)

    with pytest.raises(PreflightError, match="Ban users"):
        await preflight.run(bot, settings, make_directory())  # type: ignore[arg-type]


async def test_chat_owner_passes_without_admin_rights():
    """An owner has every right implicitly; must not be reported as missing any."""
    bot = PreflightBot(
        member_status="creator", can_delete_messages=False, can_restrict_members=False
    )

    await preflight.run(bot, make_settings(mute_enabled=True), make_directory())  # type: ignore[arg-type]


async def test_healthy_configuration_passes():
    bot = PreflightBot()

    await preflight.run(bot, make_settings(), make_directory())  # type: ignore[arg-type]


# ===========================================================================
# fatal: the rule itself is inert
# ===========================================================================
async def test_no_restricted_users_is_fatal():
    bot = PreflightBot()

    with pytest.raises(PreflightError, match="RESTRICTED_USERS is empty"):
        await preflight.run(  # type: ignore[arg-type]
            bot, make_settings(restricted_users=[]), make_directory()
        )


async def test_nothing_resolved_is_fatal():
    """Everyone left the group: the bot must say so rather than guard nothing."""
    bot = PreflightBot()

    with pytest.raises(PreflightError, match="no entry in RESTRICTED_USERS"):
        await preflight.run(bot, make_settings(), make_directory(entries=()))  # type: ignore[arg-type]


async def test_all_detectors_off_is_fatal():
    bot = PreflightBot()
    settings = make_settings(
        detect_replies=False, detect_mentions=False, detect_bare_usernames=False
    )

    with pytest.raises(PreflightError, match="every detector is disabled"):
        await preflight.run(bot, settings, make_directory())  # type: ignore[arg-type]


async def test_no_punishment_configured_is_fatal():
    bot = PreflightBot()
    settings = make_settings(delete_message=False, mute_enabled=False)

    with pytest.raises(PreflightError, match="nothing else would happen"):
        await preflight.run(bot, settings, make_directory())  # type: ignore[arg-type]


async def test_whitelist_without_topics_warns_but_passes(caplog):
    """Not fatal: the group may simply have topics disabled, and the bot should run."""
    bot = PreflightBot(is_forum=False)

    with caplog.at_level("WARNING"):
        await preflight.run(bot, make_settings(), make_directory())  # type: ignore[arg-type]

    assert any("not a forum supergroup" in record.message for record in caplog.records)


async def test_no_whitelist_is_fine_on_a_forum():
    bot = PreflightBot(is_forum=True)

    await preflight.run(  # type: ignore[arg-type]
        bot, make_settings(whitelist_topic_ids=[]), make_directory()
    )


async def test_bare_detection_without_usernames_warns_but_passes(caplog):
    bot = PreflightBot()

    with caplog.at_level("WARNING"):
        await preflight.run(  # type: ignore[arg-type]
            bot, make_settings(), make_directory(entries=((ALICE_ID, None), (BOB_ID, None)))
        )

    assert any("no restricted user has a public username" in r.message for r in caplog.records)
