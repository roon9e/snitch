"""The watcher pipeline: the gating order, end to end.

These tests exercise the whole decision path (scope -> whitelist -> detection ->
admin check -> punishment) against a fake bot, which is where an ordering mistake
would let the bot delete a message it should have ignored.
"""

from __future__ import annotations

from typing import Any

import pytest
from aiogram.types import (
    ChatMemberAdministrator,
    ChatMemberMember,
    ChatMemberOwner,
)

from snitch.handlers.watch import RecentSamples, Watcher
from snitch.wordlist import WordList
from tests.conftest import (
    ALICE_ID,
    BOB_ID,
    OTHER_CHAT_ID,
    STRANGER_ID,
    make_holder,
    make_message,
    make_settings,
    make_user,
)


class SpyBot:
    """Only the admin lookup matters here; punishment is stubbed out."""

    def __init__(self, status: str = "member") -> None:
        self.status = status
        self.lookups: list[Any] = []

    async def get_chat_member(self, **kwargs: Any) -> Any:
        self.lookups.append(kwargs)
        user = make_user(int(kwargs["user_id"]), "alice")
        if self.status == "administrator":
            return ChatMemberAdministrator.model_construct(
                status="administrator", user=user, is_anonymous=False
            )
        if self.status == "creator":
            return ChatMemberOwner.model_construct(status="creator", user=user, is_anonymous=False)
        return ChatMemberMember.model_construct(status="member", user=user)


class RecordingModerator:
    """Captures violations without touching Telegram."""

    def __init__(self) -> None:
        self.handled: list[tuple[int, str]] = []

    async def handle(self, message: Any, detection: Any) -> Any:
        self.handled.append((message.message_id, detection.summary()))
        from snitch.services.moderator import MuteOutcome, ViolationResult

        return ViolationResult(
            deleted=True,
            delete_error=None,
            mute=MuteOutcome.DISABLED,
        )


def build_watcher(
    bot: SpyBot | None = None,
    *,
    samples: RecentSamples | None = None,
    wordlist: WordList | None = None,
    **overrides: Any,
) -> tuple[Watcher, SpyBot, RecordingModerator, RecentSamples]:
    spy = bot or SpyBot()
    moderator = RecordingModerator()
    buffer_ = samples if samples is not None else RecentSamples()
    settings = make_settings(**overrides)
    watcher = Watcher(
        bot=spy,  # type: ignore[arg-type]
        settings=settings,
        directory=make_holder(),
        moderator=moderator,  # type: ignore[arg-type]
        samples=buffer_,
        wordlist=wordlist,
    )
    return watcher, spy, moderator, buffer_


def build_wordlist(tmp_path: Any, body: str) -> WordList:
    path = tmp_path / "wordlist.txt"
    path.write_text(body, encoding="utf-8")
    wordlist = WordList(path, min_reload_interval=0.0)
    wordlist.reload()
    return wordlist


def alice_replies_to_bob(**overrides: Any) -> Any:
    return make_message(
        make_user(ALICE_ID, "alice"),
        text="sure thing",
        reply_to_sender=make_user(BOB_ID, "bob"),
        **overrides,
    )


# ===========================================================================
# messages that must be ignored outright
# ===========================================================================
async def test_message_from_another_chat_is_ignored():
    watcher, _, moderator, _ = build_watcher()

    result = await watcher.handle(alice_replies_to_bob(chat_id=OTHER_CHAT_ID))

    assert result is None
    assert moderator.handled == []


async def test_message_from_an_unrestricted_user_is_ignored():
    watcher, _, moderator, _ = build_watcher()
    message = make_message(
        make_user(STRANGER_ID, "stranger"),
        text="hey @alice",
        reply_to_sender=make_user(ALICE_ID, "alice"),
    )

    assert await watcher.handle(message) is None
    assert moderator.handled == []


# ===========================================================================
# the word blacklist, in the pipeline
# ===========================================================================
async def test_a_restricted_user_using_a_banned_word_is_punished(tmp_path):
    """The whole point: a word is enough, with no other user addressed."""
    wordlist = build_wordlist(tmp_path, "forbidden\n")
    watcher, _, moderator, _ = build_watcher(wordlist=wordlist)

    await watcher.handle(make_message(make_user(ALICE_ID, "alice"), text="this is forbidden"))

    assert len(moderator.handled) == 1
    assert "forbidden" in moderator.handled[0][1]


async def test_an_unrestricted_user_using_a_banned_word_is_ignored(tmp_path):
    """Scoped deliberately: the blacklist punishes the people you listed, not
    the whole chat. A filter that mutes every member of a busy group over a word
    mistake is one nobody keeps switched on."""
    wordlist = build_wordlist(tmp_path, "forbidden\n")
    watcher, _, moderator, _ = build_watcher(wordlist=wordlist)

    message = make_message(make_user(STRANGER_ID, "stranger"), text="this is forbidden")

    assert await watcher.handle(message) is None
    assert moderator.handled == []


async def test_a_banned_word_in_a_whitelisted_topic_is_ignored(tmp_path):
    """The whitelist is the one place the operator said nothing happens. Adding a
    second rule later must not quietly extend enforcement into it."""
    wordlist = build_wordlist(tmp_path, "forbidden\n")
    watcher, _, moderator, _ = build_watcher(
        wordlist=wordlist,
        whitelist_thread_ids="42",
    )

    message = make_message(make_user(ALICE_ID, "alice"), text="forbidden", thread_id=42)

    assert await watcher.handle(message) is None
    assert moderator.handled == []


async def test_a_banned_word_from_an_admin_is_skipped(tmp_path):
    wordlist = build_wordlist(tmp_path, "forbidden\n")
    bot = SpyBot(status="administrator")
    watcher, _, moderator, _ = build_watcher(bot, wordlist=wordlist)

    await watcher.handle(make_message(make_user(ALICE_ID, "alice"), text="forbidden"))

    assert moderator.handled == []


async def test_a_word_and_a_contact_are_both_reported(tmp_path):
    """They are independent rules; one message can trip both."""
    wordlist = build_wordlist(tmp_path, "forbidden\n")
    watcher, _, moderator, _ = build_watcher(wordlist=wordlist)

    await watcher.handle(
        make_message(
            make_user(ALICE_ID, "alice"),
            text="forbidden",
            reply_to_sender=make_user(BOB_ID, "bob"),
        )
    )

    assert len(moderator.handled) == 1
    summary = moderator.handled[0][1]
    assert "reply" in summary
    assert "forbidden" in summary


async def test_a_banned_word_in_a_caption_is_caught(tmp_path):
    """Entities live on the caption for media, and so does the text to filter."""
    wordlist = build_wordlist(tmp_path, "forbidden\n")
    watcher, _, moderator, _ = build_watcher(wordlist=wordlist)

    message = make_message(make_user(ALICE_ID, "alice"), caption="look at this forbidden thing")

    await watcher.handle(message)

    assert len(moderator.handled) == 1


async def test_no_wordlist_configured_means_no_word_rule():
    watcher, _, moderator, _ = build_watcher()

    await watcher.handle(make_message(make_user(ALICE_ID, "alice"), text="forbidden"))

    assert moderator.handled == []


async def test_an_empty_wordlist_is_harmless(tmp_path):
    wordlist = build_wordlist(tmp_path, "# nothing here yet\n")
    watcher, _, moderator, _ = build_watcher(wordlist=wordlist)

    await watcher.handle(make_message(make_user(ALICE_ID, "alice"), text="anything at all"))

    assert moderator.handled == []


async def test_the_watcher_picks_up_an_edited_file(tmp_path):
    """No restart: the reason this is a file rather than an env var."""
    wordlist = build_wordlist(tmp_path, "first\n")
    watcher, _, moderator, _ = build_watcher(wordlist=wordlist)
    await watcher.handle(make_message(make_user(ALICE_ID, "alice"), text="second"))
    assert moderator.handled == []

    (tmp_path / "wordlist.txt").write_text("second\n", encoding="utf-8")

    await watcher.handle(make_message(make_user(ALICE_ID, "alice"), text="second"))

    assert len(moderator.handled) == 1


async def test_a_word_hit_is_still_buffered_for_check(tmp_path):
    """Otherwise /check would under-report, and /check is the tuning aid."""
    wordlist = build_wordlist(tmp_path, "forbidden\n")
    watcher, _, _, samples = build_watcher(wordlist=wordlist)

    await watcher.handle(make_message(make_user(ALICE_ID, "alice"), text="forbidden"))

    assert samples.all()[0].was_violation is True


async def test_bot_messages_are_ignored():
    watcher, _, moderator, _ = build_watcher()
    message = make_message(
        make_user(ALICE_ID, "alice"),
        text="sure",
        is_bot=True,
        reply_to_sender=make_user(BOB_ID, "bob"),
    )

    assert await watcher.handle(message) is None
    assert moderator.handled == []


async def test_channel_posts_are_ignored():
    """sender_chat means an anonymous admin or channel post - no person to punish."""
    watcher, _, moderator, _ = build_watcher()
    message = make_message(
        None,
        text="sure",
        sender_chat=make_message(None).chat,
        reply_to_sender=make_user(BOB_ID, "bob"),
    )

    assert await watcher.handle(message) is None
    assert moderator.handled == []


async def test_message_with_no_violation_is_ignored():
    watcher, _, moderator, _ = build_watcher()
    message = make_message(
        make_user(ALICE_ID, "alice"),
        text="just thinking out loud",
    )

    assert await watcher.handle(message) is None
    assert moderator.handled == []


# ===========================================================================
# the whitelist
# ===========================================================================
async def test_whitelisted_topic_is_never_punished():
    watcher, spy, moderator, _ = build_watcher()
    message = alice_replies_to_bob(thread_id=42)

    assert await watcher.handle(message) is None
    assert moderator.handled == []
    assert spy.lookups == [], "a whitelisted message must cost zero API calls"


async def test_whitelisted_general_topic_is_never_punished():
    watcher, _, moderator, _ = build_watcher(whitelist_topic_ids=["general"])

    assert await watcher.handle(alice_replies_to_bob()) is None
    assert moderator.handled == []


async def test_non_whitelisted_topic_is_punished():
    watcher, _, moderator, _ = build_watcher()

    result = await watcher.handle(alice_replies_to_bob(thread_id=7))

    assert result is not None
    assert len(moderator.handled) == 1


# ===========================================================================
# the admin exemption
# ===========================================================================
@pytest.mark.parametrize("status", ["administrator", "creator"])
async def test_admins_are_exempt_when_ignore_admins_is_on(status):
    watcher, _, moderator, _ = build_watcher(SpyBot(status=status), ignore_admins=True)

    assert await watcher.handle(alice_replies_to_bob()) is None
    assert moderator.handled == []


async def test_admins_are_still_moderated_when_ignore_admins_is_off():
    """Some groups may deliberately want moderators held to the rule too."""
    watcher, spy, moderator, _ = build_watcher(SpyBot(status="creator"), ignore_admins=False)

    assert await watcher.handle(alice_replies_to_bob()) is not None
    assert len(moderator.handled) == 1
    assert spy.lookups == [], "no admin lookup is needed when the check is off"


async def test_admin_lookup_is_cached():
    """A flood of violations must not mean a flood of getChatMember calls."""
    watcher, spy, _, _ = build_watcher(mute_cooldown_seconds=0)

    for message_id in range(1, 4):
        await watcher.handle(alice_replies_to_bob(message_id=message_id))

    assert len(spy.lookups) == 1


# ===========================================================================
# cost of a quiet group
# ===========================================================================
async def test_a_busy_but_compliant_group_costs_no_api_calls():
    """Everything before the admin check is local; only proven violations pay."""
    watcher, spy, moderator, _ = build_watcher()

    for message_id in range(1, 21):
        # compliant messages from a restricted user
        await watcher.handle(
            make_message(
                make_user(ALICE_ID, "alice"),
                text="just chatting",
                message_id=message_id,
            )
        )
        # messages from everybody else
        await watcher.handle(
            make_message(
                make_user(STRANGER_ID, "stranger"),
                text="hello @alice",
                message_id=100 + message_id,
            )
        )

    assert spy.lookups == []
    assert moderator.handled == []


# ===========================================================================
# the sample buffer behind /check
# ===========================================================================
async def test_samples_buffer_violations_and_clean_messages():
    watcher, _, _, samples = build_watcher()

    await watcher.handle(alice_replies_to_bob(message_id=1))
    await watcher.handle(make_message(make_user(ALICE_ID, "alice"), text="hello", message_id=2))

    assert len(samples) == 2
    assert samples.all()[0].was_violation is True
    assert samples.all()[1].was_violation is False


async def test_whitelisted_messages_are_not_buffered():
    """A whitelisted topic returning early must not pollute the /check report."""
    watcher, _, _, samples = build_watcher()

    await watcher.handle(alice_replies_to_bob(thread_id=42))

    assert len(samples) == 0


async def test_sample_buffer_is_bounded():
    watcher, _, _, samples = build_watcher()

    for message_id in range(1, 60):
        await watcher.handle(
            make_message(make_user(ALICE_ID, "alice"), text="chatter", message_id=message_id)
        )

    assert len(samples) == 50


async def test_samples_retain_the_original_message_object():
    """Sample objects must hold a real Message so /check can replay detection."""
    watcher, _, _, samples = build_watcher()

    message = alice_replies_to_bob()
    await watcher.handle(message)

    stored = samples.all()[0]
    assert stored.message is message
    assert stored.message.date.tzinfo is not None
    assert stored.message.reply_to_message is not None
