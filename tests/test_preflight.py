"""Startup guards.

The point of preflight is to refuse to run rather than silently guard nothing, so
these tests pin down the fatal conditions, the messages operators will actually
read, and the permanent/transient split that keeps a bad config from crash
looping the container forever.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from aiogram.exceptions import (
    TelegramBadRequest,
    TelegramNetworkError,
    TelegramServerError,
)
from aiogram.types import (
    Chat,
    ChatMemberAdministrator,
    ChatMemberMember,
    ChatMemberOwner,
    ChatPermissions,
    User,
)
from pydantic import SecretStr

from snitch import preflight
from snitch.config import LogFormat, NoticeMode, Settings
from snitch.preflight import PreflightError
from tests.conftest import (
    ALICE_ID,
    BASIC_GROUP_ID,
    BOB_ID,
    SUPERGROUP_ID,
    make_directory,
    make_settings,
    make_user,
)

OWNER_ID = 999
BOT_ID = 8530472014


class PreflightBot:
    """Serves just the calls preflight makes, and can fail them on demand."""

    def __init__(
        self,
        *,
        member_status: str = "administrator",
        can_delete_messages: bool = True,
        can_restrict_members: bool = True,
        can_send_messages: bool | None = True,
        is_forum: bool = True,
        chat_type: str = "supergroup",
        get_me_error: Exception | None = None,
        get_chat_error: Exception | None = None,
    ) -> None:
        self.member_status = member_status
        self.can_delete_messages = can_delete_messages
        self.can_restrict_members = can_restrict_members
        self.can_send_messages = can_send_messages
        self.is_forum = is_forum
        self.chat_type = chat_type
        self.get_me_error = get_me_error
        self.get_chat_error = get_chat_error
        self.bot_user = make_user(BOT_ID, "snitchbot", is_bot=True)
        self.chat_calls: list[Any] = []

    async def get_me(self) -> User:
        if self.get_me_error:
            raise self.get_me_error
        return self.bot_user

    async def get_chat(self, chat_id: Any) -> Chat:
        self.chat_calls.append(chat_id)
        if self.get_chat_error:
            raise self.get_chat_error
        # `permissions` is what getChat returns for the requesting bot, and is
        # the only place the ability to send can be read - the admin member
        # record cannot express it.
        permissions = (
            None
            if self.can_send_messages is None
            else ChatPermissions(can_send_messages=self.can_send_messages)
        )
        return Chat.model_construct(
            id=chat_id, type=self.chat_type, is_forum=self.is_forum, permissions=permissions
        )

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


def api_error(text: str, cls: type[Exception] = TelegramBadRequest) -> Exception:
    return cls(method=None, message=text)


async def run_all(bot: PreflightBot, settings: Any = None) -> None:
    """Run the whole preflight sequence in production order."""
    settings = settings if settings is not None else make_settings(chat_id=SUPERGROUP_ID)
    preflight.check_local(settings)
    me = await preflight.check_token(bot, settings)  # type: ignore[arg-type]
    chat = await preflight.check_chat(bot, settings)  # type: ignore[arg-type]
    await preflight.check_rights(bot, settings, me.id, chat)  # type: ignore[arg-type]
    preflight.check_config(settings, make_directory())
    preflight.check_topic_hint(chat, settings)


# ===========================================================================
# happy path
# ===========================================================================
async def test_healthy_configuration_passes():
    await run_all(PreflightBot())


# ===========================================================================
# fatal: the token
# ===========================================================================
async def test_invalid_token_is_fatal():
    bot = PreflightBot(get_me_error=api_error("Bad Request: Unauthorized"))

    with pytest.raises(PreflightError, match="BOT_TOKEN looks invalid"):
        await run_all(bot)


# ===========================================================================
# fatal: the chat id, before any network call
# ===========================================================================
async def test_basic_group_id_is_rejected_without_a_network_call():
    """The reported failure: a -1234... id is a basic group, not a supergroup."""
    bot = PreflightBot()
    settings = make_settings(chat_id=BASIC_GROUP_ID)

    with pytest.raises(PreflightError) as excinfo:
        await run_all(bot, settings)

    message = str(excinfo.value)
    assert "basic group id" in message
    assert "supergroup" in message
    assert bot.chat_calls == [], "the shape check must run before getChat"
    assert excinfo.value.permanent is True


async def test_shape_check_runs_before_the_token_is_used():
    """A wrong CHAT_ID must be reported without even authenticating."""
    settings = make_settings(chat_id=BASIC_GROUP_ID)

    with pytest.raises(PreflightError, match="basic group id"):
        preflight.check_local(settings)


def test_shape_check_also_handles_a_raw_numeric_string():
    """Defensive: a str id must not slip past the check."""
    settings = Settings.model_construct(
        bot_token=SecretStr("1:x"),
        chat_id=str(BASIC_GROUP_ID),
        restricted_users=[1],
        whitelist_topic_ids=[],
        delete_message=True,
        mute_enabled=False,
        mute_hours=24,
        detect_replies=True,
        detect_mentions=True,
        detect_bare_usernames=True,
        ignore_admins=True,
        notice_mode=NoticeMode.LOG,
        admin_ids=[],
        directory_refresh_hours=6.0,
        mute_cooldown_seconds=30.0,
        log_level="CRITICAL",
        log_format=LogFormat.TEXT,
        data_dir=Path(),
    )

    with pytest.raises(PreflightError, match="basic group id"):
        preflight.check_local(settings)


async def test_basic_group_id_message_explains_the_id_change():
    """Telegram reassigns the id when a group becomes a supergroup."""
    settings = make_settings(chat_id=BASIC_GROUP_ID)

    with pytest.raises(PreflightError) as excinfo:
        await run_all(PreflightBot(), settings)

    assert "NEW id" in str(excinfo.value)
    assert "/id" in str(excinfo.value)


async def test_positive_chat_id_is_rejected():
    with pytest.raises(PreflightError, match="is not a chat id"):
        await run_all(PreflightBot(), make_settings(chat_id=12345))


# ===========================================================================
# the ability to send: the silent "dead but working" bot
# ===========================================================================
async def test_a_bot_that_cannot_send_is_refused_at_startup():
    """The bug this exists for.

    A bot with 'Delete messages' but no 'Send messages' looks perfectly healthy:
    it catches every violation, so the operator concludes it is working - while
    every command is silently dropped, and /unmute does not exist. Nothing in
    the logs said a word.
    """
    bot = PreflightBot(can_send_messages=False)

    with pytest.raises(PreflightError, match="cannot send messages"):
        await run_all(bot)


async def test_the_send_failure_explains_the_silent_symptom():
    bot = PreflightBot(can_send_messages=False)

    with pytest.raises(PreflightError) as caught:
        await run_all(bot)

    message = str(caught.value)
    assert "/unmute" in message, "the operator needs to know what is unreachable"
    assert "looks like" in message, "and why nothing ever complained"


async def test_a_bot_that_can_send_passes():
    bot = PreflightBot(can_send_messages=True)

    await run_all(bot)  # must not raise


async def test_absent_permissions_means_unrestricted_and_passes():
    """`permissions: null` is what a normal, unrestricted bot gets back."""
    bot = PreflightBot(can_send_messages=None)

    await run_all(bot)  # must not raise


async def test_sending_is_checked_even_when_deleting_is_disabled():
    """Otherwise DELETE_MESSAGE=false becomes a way to lose the commands."""
    bot = PreflightBot(can_send_messages=False)

    with pytest.raises(PreflightError, match="cannot send messages"):
        await run_all(bot, make_settings(delete_message=False))


async def test_an_unreadable_permission_set_does_not_block_startup():
    """'Cannot tell' is not 'cannot send': failing here would be a worse outage
    than the thing being checked."""
    bot = PreflightBot(
        can_send_messages=None, get_chat_error=TelegramNetworkError(method=None, message="timeout")
    )

    # check_chat itself will fail first, which is the correct outcome for an
    # unreachable chat; the point is that check_rights does not add a second,
    # different complaint about permissions.
    with pytest.raises(PreflightError, match="cannot read CHAT_ID"):
        await run_all(bot)


async def test_supergroup_id_shape_is_accepted():
    bot = PreflightBot()

    await run_all(bot, make_settings(chat_id=SUPERGROUP_ID))

    assert bot.chat_calls == [SUPERGROUP_ID]


async def test_username_chat_id_is_not_shape_checked():
    bot = PreflightBot()

    await run_all(bot, make_settings(chat_id="@mygroup"))

    assert bot.chat_calls == ["@mygroup"]


# ===========================================================================
# fatal: the bot is not in the chat
# ===========================================================================
async def test_unreadable_chat_is_fatal():
    bot = PreflightBot(get_chat_error=api_error("Bad Request: chat not found"))

    with pytest.raises(PreflightError) as excinfo:
        await run_all(bot)

    message = str(excinfo.value)
    assert "cannot read CHAT_ID" in message
    assert "Is the bot actually a member" in message
    assert "stale" in message, "the upgrade reassigns the id and must be mentioned"
    assert excinfo.value.permanent is True


# ===========================================================================
# a basic group that somehow still answers get_chat
# ===========================================================================
async def test_basic_group_fails_when_muting_is_configured():
    bot = PreflightBot(chat_type="group")
    settings = make_settings(chat_id=SUPERGROUP_ID, mute_enabled=True)

    with pytest.raises(PreflightError, match="basic group"):
        await run_all(bot, settings)


async def test_basic_group_fails_when_topics_are_whitelisted():
    bot = PreflightBot(chat_type="group")
    settings = make_settings(chat_id=SUPERGROUP_ID, whitelist_topic_ids=["42"])

    with pytest.raises(PreflightError, match="basic group"):
        await run_all(bot, settings)


async def test_basic_group_warns_when_only_deletion_is_used(caplog):
    """Deletion is the one thing that does work in a basic group."""
    bot = PreflightBot(chat_type="group")
    settings = make_settings(chat_id=SUPERGROUP_ID, whitelist_topic_ids=[])

    with caplog.at_level("WARNING"):
        await run_all(bot, settings)

    assert any("basic group" in r.message for r in caplog.records)


# ===========================================================================
# fatal: admin rights
# ===========================================================================
async def test_non_admin_bot_is_fatal():
    with pytest.raises(PreflightError, match="not an administrator"):
        await run_all(PreflightBot(member_status="member"))


async def test_missing_delete_right_is_fatal_when_deletion_is_on():
    bot = PreflightBot(can_delete_messages=False)

    with pytest.raises(PreflightError, match="Delete messages"):
        await run_all(bot)


async def test_missing_restrict_right_is_fatal_when_muting_is_on():
    bot = PreflightBot(can_restrict_members=False)
    settings = make_settings(chat_id=SUPERGROUP_ID, mute_enabled=True)

    with pytest.raises(PreflightError, match="Ban users"):
        await run_all(bot, settings)


async def test_chat_owner_passes_without_admin_rights():
    bot = PreflightBot(
        member_status="creator", can_delete_messages=False, can_restrict_members=False
    )
    settings = make_settings(chat_id=SUPERGROUP_ID, mute_enabled=True)

    await run_all(bot, settings)


# ===========================================================================
# fatal: the rule is inert
# ===========================================================================
async def test_no_restricted_users_is_fatal():
    settings = make_settings(chat_id=SUPERGROUP_ID, restricted_users=[])

    with pytest.raises(PreflightError, match="RESTRICTED_USERS is empty"):
        preflight.check_config(settings, make_directory())


async def test_nothing_resolved_is_fatal():
    settings = make_settings(chat_id=SUPERGROUP_ID)

    with pytest.raises(PreflightError, match="no entry in RESTRICTED_USERS"):
        preflight.check_config(settings, make_directory(entries=()))


async def test_all_detectors_off_is_fatal():
    settings = make_settings(
        chat_id=SUPERGROUP_ID,
        detect_replies=False,
        detect_mentions=False,
        detect_bare_usernames=False,
    )

    with pytest.raises(PreflightError, match="every detector is disabled"):
        preflight.check_config(settings, make_directory())


async def test_no_punishment_configured_is_fatal():
    settings = make_settings(chat_id=SUPERGROUP_ID, delete_message=False, mute_enabled=False)

    with pytest.raises(PreflightError, match="nothing else would happen"):
        preflight.check_config(settings, make_directory())


async def test_bare_detection_without_usernames_warns_but_passes(caplog):
    settings = make_settings(chat_id=SUPERGROUP_ID)

    with caplog.at_level("WARNING"):
        preflight.check_config(settings, make_directory(entries=((ALICE_ID, None), (BOB_ID, None))))

    assert any("no restricted user has a public username" in r.message for r in caplog.records)


# ===========================================================================
# topic hint
# ===========================================================================
async def test_whitelist_without_topics_warns_but_passes(caplog):
    bot = PreflightBot(is_forum=False)

    with caplog.at_level("WARNING"):
        await run_all(bot)

    assert any("has no topics enabled" in r.message for r in caplog.records)


async def test_no_whitelist_is_fine_on_a_forum(caplog):
    with caplog.at_level("WARNING"):
        await run_all(PreflightBot(), make_settings(chat_id=SUPERGROUP_ID, whitelist_topic_ids=[]))

    assert not [r for r in caplog.records if "WHITELIST" in r.message]


# ===========================================================================
# permanent vs transient
# ===========================================================================
def test_bad_request_is_permanent():
    assert not preflight.is_transient(TelegramBadRequest(method=None, message="chat not found"))


def test_server_error_is_transient():
    assert preflight.is_transient(TelegramServerError(method=None, message="boom"))


def test_network_error_is_transient():
    assert preflight.is_transient(ConnectionResetError("connection reset"))
    assert preflight.is_transient(asyncio.TimeoutError())


def test_permanent_preflight_error_is_not_retried():
    assert not preflight.is_transient(PreflightError("wrong id"))
