"""Punishment orchestration: delete-then-mute, with a fake Telegram client.

The fakes record calls and can be told to fail, which is how the ordering
guarantee (delete before mute) and the "one bad API call must not take the
dispatcher down" guarantee are pinned down.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import (
    ChatMemberAdministrator,
    ChatMemberMember,
    ChatMemberOwner,
    ChatMemberRestricted,
    Message,
)

from snitch.detection import detect
from snitch.services.audit import AuditLog
from snitch.services.moderator import Moderator, MuteOutcome
from snitch.services.notifier import Notifier
from tests.conftest import (
    ALICE_ID,
    CHAT_ID,
    make_holder,
    make_message,
    make_settings,
    make_user,
)


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------
class FakeBot:
    """Records every moderation call; optionally raises."""

    def __init__(
        self,
        *,
        member_status: str = "member",
        until_date: datetime | None = None,
        delete_error: Exception | None = None,
        restrict_error: Exception | None = None,
        member_error: Exception | None = None,
    ) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.member_status = member_status
        self.until_date = until_date
        self.delete_error = delete_error
        self.restrict_error = restrict_error
        self.member_error = member_error

    async def delete_messages(self, **kwargs: Any) -> bool:
        """Records one entry per call, so batch size is visible in tests.

        This is the only deletion path the bot has now - a single message goes
        through deleteMessages with a one-element list.
        """
        self.calls.append(("delete", kwargs))
        if self.delete_error:
            raise self.delete_error
        return True

    async def get_chat_member(self, **kwargs: Any) -> Any:
        self.calls.append(("get_chat_member", kwargs))
        if self.member_error:
            raise self.member_error
        user = make_user(int(kwargs["user_id"]), "alice")
        # model_construct skips validation: these fakes only need the fields the
        # bot actually reads, and ChatMemberRestricted requires 19 of them.
        if self.member_status == "restricted":
            return ChatMemberRestricted.model_construct(
                status="restricted",
                user=user,
                is_member=True,
                can_send_messages=False,
                until_date=self.until_date,
            )
        if self.member_status == "administrator":
            return ChatMemberAdministrator.model_construct(
                status="administrator",
                user=user,
                is_anonymous=False,
                can_delete_messages=True,
                can_restrict_members=True,
            )
        if self.member_status == "creator":
            return ChatMemberOwner.model_construct(status="creator", user=user, is_anonymous=False)
        return ChatMemberMember.model_construct(status="member", user=user)

    async def restrict_chat_member(self, **kwargs: Any) -> bool:
        self.calls.append(("restrict", kwargs))
        if self.restrict_error:
            raise self.restrict_error
        return True

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


def api_error(text: str) -> TelegramBadRequest:
    """Build a TelegramBadRequest carrying the server's message text."""
    return TelegramBadRequest(method=None, message=text)


def build_moderator(bot: FakeBot, tmp_path: Path, **overrides: Any) -> tuple[Moderator, AuditLog]:
    settings = make_settings(tmp_path=tmp_path, **overrides)
    audit = AuditLog(tmp_path)
    moderator = Moderator(
        bot=bot,  # type: ignore[arg-type]
        settings=settings,
        directory=make_holder(),
        audit=audit,
        notifier=Notifier(bot, settings),  # type: ignore[arg-type]
    )
    return moderator, audit


def violation_message(**overrides: Any) -> Message:
    return make_message(
        make_user(ALICE_ID, "alice"),
        text="hey @bob",
        **overrides,
    )


# ===========================================================================
# deletion
# ===========================================================================
async def test_violation_deletes_the_message(tmp_path):
    bot = FakeBot()
    moderator, _ = build_moderator(bot, tmp_path)

    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert result.deleted is True
    # A lone violation goes through deleteMessages with a one-element list:
    # batching changes how the request is shaped, not that it is made.
    assert ("delete", {"chat_id": CHAT_ID, "message_ids": [1]}) in bot.calls


async def test_delete_happens_before_mute(tmp_path):
    """The message must vanish first; the mute is the slower, secondary step."""
    bot = FakeBot()
    moderator, _ = build_moderator(bot, tmp_path, mute_enabled=True, mute_cooldown_seconds=0)

    message = violation_message()
    await moderator.handle(message, _detect(message))

    assert bot.names().index("delete") < bot.names().index("restrict")


async def test_delete_disabled_skips_the_call(tmp_path):
    bot = FakeBot()
    moderator, _ = build_moderator(bot, tmp_path, delete_message=False)

    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert "delete" not in bot.names()
    assert result.deleted is False


async def test_already_deleted_message_is_not_an_error(tmp_path):
    """A message that vanished between the update and our call is a success."""
    bot = FakeBot(delete_error=api_error("Bad Request: message to delete not found"))
    moderator, _ = build_moderator(bot, tmp_path)

    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert result.deleted is True
    assert result.delete_error is None


async def test_delete_failure_is_reported_not_raised(tmp_path):
    bot = FakeBot(delete_error=api_error("Forbidden: not enough rights to delete"))
    moderator, _ = build_moderator(bot, tmp_path)

    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert result.deleted is False
    assert "not enough rights" in (result.delete_error or "")


# ===========================================================================
# muting
# ===========================================================================
async def test_mute_disabled_by_default(tmp_path):
    bot = FakeBot()
    moderator, _ = build_moderator(bot, tmp_path)

    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert result.mute is MuteOutcome.DISABLED
    assert "restrict" not in bot.names()


async def test_mute_applies_the_configured_duration(tmp_path):
    bot = FakeBot()
    moderator, _ = build_moderator(
        bot, tmp_path, mute_enabled=True, mute_hours=6, mute_cooldown_seconds=0
    )

    before = datetime.now(tz=timezone.utc)
    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert result.mute is MuteOutcome.APPLIED
    assert result.mute_until is not None
    assert before + timedelta(hours=5, minutes=59) <= result.mute_until
    assert result.mute_until <= before + timedelta(hours=6, minutes=1)


async def test_mute_sends_independent_permissions(tmp_path):
    """Without use_independent_chat_permissions, Telegram's implication rules
    can quietly re-grant posting rights."""
    bot = FakeBot()
    moderator, _ = build_moderator(bot, tmp_path, mute_enabled=True, mute_cooldown_seconds=0)

    await moderator.handle(violation_message(), _detect(violation_message()))

    restrict = next(kwargs for name, kwargs in bot.calls if name == "restrict")
    assert restrict["use_independent_chat_permissions"] is True
    assert restrict["permissions"].can_send_messages is False
    assert restrict["permissions"].can_send_other_messages is False


async def test_mute_preserves_unrelated_rights(tmp_path):
    """A mute must not also strip invite/pin/topic rights."""
    bot = FakeBot()
    moderator, _ = build_moderator(bot, tmp_path, mute_enabled=True, mute_cooldown_seconds=0)

    await moderator.handle(violation_message(), _detect(violation_message()))

    permissions = next(k for n, k in bot.calls if n == "restrict")["permissions"]
    assert permissions.can_invite_users is True
    assert permissions.can_change_info is True
    assert permissions.can_pin_messages is True
    assert permissions.can_manage_topics is True


async def test_already_muted_user_is_not_muted_again(tmp_path):
    """A message flood must not turn an N hour penalty into an indefinite one."""
    bot = FakeBot(
        member_status="restricted",
        until_date=datetime.now(tz=timezone.utc) + timedelta(hours=5),
    )
    moderator, _ = build_moderator(bot, tmp_path, mute_enabled=True, mute_cooldown_seconds=0)

    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert result.mute is MuteOutcome.ALREADY_MUTED
    assert "restrict" not in bot.names()
    assert result.deleted is True, "deletion must still happen for an already-muted user"


async def test_expired_restriction_can_be_muted_again(tmp_path):
    bot = FakeBot(
        member_status="restricted",
        until_date=datetime.now(tz=timezone.utc) - timedelta(hours=1),
    )
    moderator, _ = build_moderator(bot, tmp_path, mute_enabled=True, mute_cooldown_seconds=0)

    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert result.mute is MuteOutcome.APPLIED


async def test_permanent_restriction_is_left_alone(tmp_path):
    bot = FakeBot(member_status="restricted", until_date=None)
    moderator, _ = build_moderator(bot, tmp_path, mute_enabled=True, mute_cooldown_seconds=0)

    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert result.mute is MuteOutcome.ALREADY_MUTED


@pytest.mark.parametrize("status", ["administrator", "creator"])
async def test_admins_are_never_restricted(tmp_path, status):
    """Telegram rejects this; the bot must not waste the call or crash."""
    bot = FakeBot(member_status=status)
    moderator, _ = build_moderator(bot, tmp_path, mute_enabled=True, mute_cooldown_seconds=0)

    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert result.mute is MuteOutcome.NOT_PERMITTED
    assert "restrict" not in bot.names()
    assert result.deleted is True


async def test_cooldown_prevents_api_storms(tmp_path):
    bot = FakeBot()
    moderator, _ = build_moderator(bot, tmp_path, mute_enabled=True, mute_cooldown_seconds=300)

    for message_id in range(1, 6):
        message = make_message(make_user(ALICE_ID, "alice"), text="hey @bob", message_id=message_id)
        await moderator.handle(message, _detect(message))

    restricts = [name for name in bot.names() if name == "restrict"]
    assert len(restricts) == 1, "the cooldown must collapse the burst into one mute"

    await moderator.flush_deletes()

    # Every message is still deleted - but the burst cost two calls, not five.
    deleted_ids = sorted(
        message_id
        for _, kwargs in bot.calls
        if kwargs.get("message_ids")
        for message_id in kwargs["message_ids"]
    )
    assert deleted_ids == [1, 2, 3, 4, 5]
    assert bot.names().count("delete") == 2, "batched, not one call per message"


async def test_mute_failure_is_reported_not_raised(tmp_path):
    bot = FakeBot(restrict_error=api_error("Bad Request: not enough rights to restrict"))
    moderator, _ = build_moderator(bot, tmp_path, mute_enabled=True, mute_cooldown_seconds=0)

    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert result.mute is MuteOutcome.FAILED
    assert "not enough rights" in (result.mute_error or "")


async def test_member_lookup_failure_is_reported_not_raised(tmp_path):
    bot = FakeBot(member_error=api_error("Bad Request: user not found"))
    moderator, _ = build_moderator(bot, tmp_path, mute_enabled=True, mute_cooldown_seconds=0)

    result = await moderator.handle(violation_message(), _detect(violation_message()))

    assert result.mute is MuteOutcome.FAILED


# ===========================================================================
# audit trail
# ===========================================================================
async def test_violation_is_written_to_the_audit_log(tmp_path):
    bot = FakeBot()
    moderator, audit = build_moderator(bot, tmp_path, mute_enabled=True, mute_cooldown_seconds=0)

    message = violation_message()
    await moderator.handle(message, _detect(message))

    lines = audit.tail()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "violation"
    assert record["user_id"] == ALICE_ID
    assert record["message_excerpt"] == "hey @bob"
    assert record["deleted"] is True
    assert record["mute"] == MuteOutcome.APPLIED.value


async def test_audit_records_the_thread_id(tmp_path):
    bot = FakeBot()
    moderator, audit = build_moderator(bot, tmp_path)

    message = violation_message(thread_id=7)
    await moderator.handle(message, _detect(message))

    assert json.loads(audit.tail()[0])["thread_id"] == 7


async def test_audit_survives_an_unwritable_directory(tmp_path):
    """A broken DATA_DIR must degrade to container logs, never crash the bot."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("this is a file, not a directory")

    audit = AuditLog(blocker / "nested")
    assert audit.enabled is False
    audit.record(event="violation")  # must not raise


# ===========================================================================
# unmute
# ===========================================================================
async def test_unmute_lifts_every_restriction(tmp_path):
    bot = FakeBot()
    moderator, _ = build_moderator(bot, tmp_path)

    await moderator.unmute(CHAT_ID, ALICE_ID)

    restrict = next(kwargs for name, kwargs in bot.calls if name == "restrict")
    assert restrict["until_date"] == 0
    assert restrict["permissions"].can_send_messages is True
    assert restrict["permissions"].can_send_other_messages is True


# ---------------------------------------------------------------------------
def _detect(message: Message) -> Any:
    from tests.conftest import make_directory

    return detect(message, make_settings(), make_directory())
