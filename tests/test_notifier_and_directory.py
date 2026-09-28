"""The NOTICE_MODE behaviours and RESTRICTED_USERS resolution."""

from __future__ import annotations

import json
from typing import Any

from aiogram.exceptions import TelegramBadRequest
from aiogram.types import ChatMemberAdministrator, ChatMemberMember, ChatMemberRestricted

from snitch.config import normalize_username
from snitch.directory import DirectoryHolder, resolve
from snitch.services.notifier import Notifier, build_notice_text, describe_user
from tests.conftest import ALICE_ID, BOB_ID, CHAT_ID, make_message, make_settings, make_user


# ===========================================================================
# notifier
# ===========================================================================
class NotifierBot:
    def __init__(self, error: Exception | None = None) -> None:
        self.sent: list[dict[str, Any]] = []
        self.error = error

    async def send_message(self, **kwargs: Any) -> Any:
        if self.error:
            raise self.error
        self.sent.append(kwargs)
        return make_message(make_user(1, "snitchbot", is_bot=True), text=str(kwargs.get("text")))


def offender(**overrides: Any) -> Any:
    return make_message(make_user(ALICE_ID, "alice"), text="hey @bob", **overrides)


def detection() -> Any:
    from snitch.detection import Detection, Target, TargetKind

    return Detection(targets=(Target(kind=TargetKind.REPLY, user_id=BOB_ID, detail="reply"),))


async def test_log_mode_sends_nothing(caplog):
    bot = NotifierBot()
    notifier = Notifier(bot, make_settings(notice_mode="log"))  # type: ignore[arg-type]

    with caplog.at_level("WARNING"):
        await notifier.notify(offender(), detection(), 24)

    assert bot.sent == []
    assert any("violation" in record.message for record in caplog.records)


async def test_none_mode_is_silent(caplog):
    bot = NotifierBot()
    notifier = Notifier(bot, make_settings(notice_mode="none"))  # type: ignore[arg-type]

    with caplog.at_level("WARNING"):
        await notifier.notify(offender(), detection(), None)

    assert bot.sent == []
    assert not [r for r in caplog.records if "violation" in r.message]


async def test_chat_mode_announces_in_the_same_topic():
    bot = NotifierBot()
    notifier = Notifier(bot, make_settings(notice_mode="chat"))  # type: ignore[arg-type]

    await notifier.notify(offender(thread_id=7), detection(), 24)

    assert len(bot.sent) == 1
    assert bot.sent[0]["chat_id"] == CHAT_ID
    assert bot.sent[0]["message_thread_id"] == 7
    assert "@alice" in bot.sent[0]["text"]
    assert "24h" in bot.sent[0]["text"]


async def test_dm_mode_does_not_announce_in_public():
    bot = NotifierBot()
    notifier = Notifier(bot, make_settings(notice_mode="dm"))  # type: ignore[arg-type]

    await notifier.notify(offender(), detection(), None)

    assert len(bot.sent) == 1
    assert bot.sent[0]["chat_id"] == ALICE_ID, "the notice must go to the offender, not the group"
    assert "@alice" not in bot.sent[0]["text"]


async def test_chat_notice_failure_does_not_raise():
    bot = NotifierBot(error=TelegramBadRequest(method=None, message="Bad Request: chat not found"))
    notifier = Notifier(bot, make_settings(notice_mode="chat"))  # type: ignore[arg-type]

    await notifier.notify(offender(), detection(), None)


async def test_dm_failure_is_tolerated():
    """The usual cause is that the offender never started the bot in private."""
    bot = NotifierBot(
        error=TelegramBadRequest(method=None, message="Forbidden: bot can't initiate conversation")
    )
    notifier = Notifier(bot, make_settings(notice_mode="dm"))  # type: ignore[arg-type]

    await notifier.notify(offender(), detection(), None)


def test_notice_text_omits_the_mute_when_there_was_none():
    text = build_notice_text(
        actor="@alice", detection=detection(), muted_for_hours=None, include_actor=True
    )

    assert "@alice" in text
    assert "Muted" not in text


def test_notice_text_mentions_the_mute_length():
    text = build_notice_text(
        actor="@alice", detection=detection(), muted_for_hours=6, include_actor=True
    )

    assert "Muted for 6h" in text


def test_describe_user_prefers_the_username():
    assert describe_user(offender()) == "@alice"


def test_describe_user_falls_back_to_the_name():
    message = make_message(make_user(ALICE_ID, None, first_name="Alice", last_name="B"))

    assert describe_user(message) == "Alice B"


def test_describe_user_falls_back_to_the_id():
    message = make_message(make_user(ALICE_ID, None, first_name="  "))

    assert describe_user(message) == str(ALICE_ID)


# ===========================================================================
# directory resolution
# ===========================================================================
class ResolveBot:
    """Maps user references to member records, with a rename available."""

    def __init__(self, mapping: dict[Any, Any], error_for: Any = None) -> None:
        self.mapping = mapping
        self.error_for = error_for
        self.lookups: list[Any] = []

    async def get_chat_member(self, **kwargs: Any) -> Any:
        reference = kwargs["user_id"]
        self.lookups.append(reference)
        if reference == self.error_for or reference in self.error_for if self.error_for else False:
            raise TelegramBadRequest(method=None, message="Bad Request: user not found")
        if reference not in self.mapping:
            raise TelegramBadRequest(method=None, message="Bad Request: user not found")
        return self.mapping[reference]


async def test_numeric_ids_resolve_to_current_usernames():
    bot = ResolveBot(
        {ALICE_ID: ChatMemberMember(status="member", user=make_user(ALICE_ID, "alice"))}
    )
    settings = make_settings(restricted_users=[ALICE_ID])

    directory = await resolve(bot, settings)  # type: ignore[arg-type]

    assert directory.user_ids == frozenset({ALICE_ID})
    assert directory.usernames == {"alice": ALICE_ID}
    assert directory.unresolved == ()
    assert directory.stale_usernames == ()


async def test_usernames_resolve_to_ids():
    bot = ResolveBot(
        {"@alice": ChatMemberMember(status="member", user=make_user(ALICE_ID, "alice"))}
    )
    settings = make_settings(restricted_users=["@alice"])

    directory = await resolve(bot, settings)  # type: ignore[arg-type]

    assert directory.user_ids == frozenset({ALICE_ID})
    assert directory.entries[0].configured_as == "@alice"


async def test_renamed_user_is_reported_as_drift():
    """A username in .env that now points elsewhere must be loud, not silent."""
    bot = ResolveBot(
        {"@alice": ChatMemberMember(status="member", user=make_user(ALICE_ID, "alice_new"))}
    )
    settings = make_settings(restricted_users=["@alice"])

    directory = await resolve(bot, settings)  # type: ignore[arg-type]

    assert len(directory.stale_usernames) == 1
    assert "alice_new" in directory.stale_usernames[0]


async def test_unresolvable_user_is_reported_but_does_not_raise():
    bot = ResolveBot({})
    settings = make_settings(restricted_users=[ALICE_ID, BOB_ID])

    directory = await resolve(bot, settings)  # type: ignore[arg-type]

    assert len(directory) == 0
    assert set(directory.unresolved) == {str(ALICE_ID), str(BOB_ID)}


async def test_one_good_and_one_missing_user():
    bot = ResolveBot(
        {ALICE_ID: ChatMemberMember(status="member", user=make_user(ALICE_ID, "alice"))}
    )
    settings = make_settings(restricted_users=[ALICE_ID, BOB_ID])

    directory = await resolve(bot, settings)  # type: ignore[arg-type]

    assert directory.user_ids == frozenset({ALICE_ID})
    assert directory.unresolved == (str(BOB_ID),)


async def test_restricted_member_with_a_mute_still_resolves():
    from datetime import datetime, timedelta, timezone

    bot = ResolveBot(
        {
            ALICE_ID: ChatMemberRestricted.model_construct(
                status="restricted",
                user=make_user(ALICE_ID, "alice"),
                is_member=True,
                until_date=datetime.now(tz=timezone.utc) + timedelta(hours=3),
            )
        }
    )
    settings = make_settings(restricted_users=[ALICE_ID])

    directory = await resolve(bot, settings)  # type: ignore[arg-type]

    assert directory.user_ids == frozenset({ALICE_ID})


async def test_admin_entry_resolves():
    bot = ResolveBot(
        {
            ALICE_ID: ChatMemberAdministrator.model_construct(
                status="administrator", user=make_user(ALICE_ID, "alice"), is_anonymous=False
            )
        }
    )
    settings = make_settings(restricted_users=[ALICE_ID])

    assert (await resolve(bot, settings)).user_ids == frozenset({ALICE_ID})  # type: ignore[arg-type]


# ===========================================================================
# directory lookups used by the rule engine
# ===========================================================================
def holder() -> DirectoryHolder:
    from tests.conftest import make_directory

    return DirectoryHolder(make_directory())


def test_matches_by_id():
    assert holder().current.matches(user_id=ALICE_ID)


def test_matches_by_username_in_any_form():
    directory = holder().current
    for reference in ("alice", "@alice", "ALICE", "https://t.me/alice"):
        assert directory.matches(username=reference), reference


def test_does_not_match_an_unknown_user():
    directory = holder().current
    assert not directory.matches(user_id=999, username="carol")


def test_find_by_username():
    assert holder().current.find_by_username("@alice") == ALICE_ID
    assert holder().current.find_by_username("nobody") is None
    assert holder().current.find_by_username("x") is None


def test_label_includes_username_and_id():
    assert holder().current.label(ALICE_ID) == f"@alice ({ALICE_ID})"


def test_label_falls_back_to_the_id():
    assert holder().current.label(4242) == "4242"


def test_holder_replace_swaps_the_snapshot():
    from tests.conftest import make_directory

    holder_ = holder()
    replacement = make_directory(entries=((999, "carol"),))

    holder_.replace(replacement)

    assert holder_.current.user_ids == frozenset({999})
    assert not holder_.current.matches(user_id=ALICE_ID)
    assert len(holder_) == 1


def test_audit_records_are_valid_json(tmp_path):
    from snitch.services.audit import AuditLog

    audit = AuditLog(tmp_path)
    audit.record(event="violation", user_id=ALICE_ID, targets=["reply(id=222)"])

    record = json.loads(audit.tail()[0])
    assert record["user_id"] == ALICE_ID
    assert record["ts"].endswith("+00:00")


def test_normalize_username_is_used_for_labels():
    assert normalize_username("https://t.me/Alice") == "alice"
