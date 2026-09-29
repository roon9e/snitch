"""Admin commands, driven through a real ``Dispatcher``.

Feeding genuine ``Update`` objects means the ``Command`` filter, the
``CommandObject`` argument parsing and the handler wiring are all exercised, not
just the handler bodies.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import pytest
from aiogram import Dispatcher, Router
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import (
    Chat,
    ChatMemberAdministrator,
    ChatMemberMember,
    ChatMemberOwner,
    Message,
    Update,
)

from snitch.bot import UpdateMiddleware
from snitch.handlers.commands import build_router
from snitch.handlers.watch import RecentSamples, Watcher
from snitch.services.audit import AuditLog
from snitch.services.moderator import Moderator
from snitch.services.notifier import Notifier
from snitch.wordlist import WordList
from tests.conftest import (
    ALICE_ID,
    BOB_ID,
    CHAT_ID,
    STRANGER_ID,
    make_holder,
    make_message,
    make_settings,
    make_user,
)

OWNER_ID = 777
RESTRICTOR_ID = 888


class CommandBot:
    """Records the replies the bot sends and the member lookups it makes."""

    #: aiogram's FSM middleware and update logging read ``bot.id``.
    id = 1

    def __init__(self, *, caller_status: str = "creator", restricted: bool = True) -> None:
        self.caller_status = caller_status
        self.restricted = restricted
        self.sent: list[dict[str, Any]] = []
        self.deleted: list[dict[str, Any]] = []
        self.restricted_users: list[Any] = []
        self.lookups: list[Any] = []

    async def send_message(self, **kwargs: Any) -> Message:
        self.sent.append(kwargs)
        return make_message(
            make_user(1, "snitchbot", is_bot=True),
            text=str(kwargs.get("text", "")),
            message_id=len(self.sent),
        )

    async def get_chat_member(self, **kwargs: Any) -> Any:
        self.lookups.append(kwargs)
        user_id = int(kwargs["user_id"])
        if user_id == OWNER_ID:
            user = make_user(OWNER_ID, "owner")
            if self.caller_status == "creator":
                return ChatMemberOwner.model_construct(
                    status="creator", user=user, is_anonymous=False
                )
            return ChatMemberAdministrator.model_construct(
                status="administrator", user=user, is_anonymous=False
            )
        if user_id == RESTRICTOR_ID:
            user = make_user(RESTRICTOR_ID, "outsider")
            if self.caller_status == "member":
                return ChatMemberMember.model_construct(status="member", user=user)
            return ChatMemberAdministrator.model_construct(
                status="administrator", user=user, is_anonymous=False
            )
        return ChatMemberMember.model_construct(
            status="member", user=make_user(user_id, f"user{user_id}")
        )

    async def delete_messages(self, **kwargs: Any) -> bool:
        self.deleted.append(kwargs)
        return True

    async def restrict_chat_member(self, **kwargs: Any) -> bool:
        self.restricted_users.append(kwargs)
        return True

    async def __call__(self, method: Any) -> Any:
        """aiogram dispatches short replies through ``bot(method)``."""
        # __api_method__ is camelCase ("sendMessage"); the fakes are snake_case.
        name = re.sub(r"(?<!^)(?=[A-Z])", "_", method.__api_method__).lower()
        handler = getattr(self, name, None)
        if handler is None:
            raise NotImplementedError(f"{method.__api_method__} is not faked")
        return await handler(**method.model_dump(exclude_none=True))

    @property
    def replies(self) -> list[str]:
        return [str(item.get("text", "")) for item in self.sent]


def build_dispatcher(
    bot: CommandBot,
    tmp_path: Any,
    *,
    wordlist: WordList | None = None,
    **overrides: Any,
) -> Dispatcher:
    settings = make_settings(tmp_path=tmp_path, **overrides)
    directory = make_holder()
    audit = AuditLog(tmp_path)
    moderator = Moderator(
        bot=bot,  # type: ignore[arg-type]
        settings=settings,
        directory=directory,
        audit=audit,
        notifier=Notifier(bot, settings),  # type: ignore[arg-type]
    )
    samples = RecentSamples()
    watcher = Watcher(
        bot=bot,  # type: ignore[arg-type]
        settings=settings,
        directory=directory,
        moderator=moderator,
        samples=samples,
    )
    dispatcher = Dispatcher()
    # Mirrors src/snitch/bot.py: the update middleware sits in front of every
    # command in production, so a command test that skips it is not testing the
    # path the bot actually runs.
    dispatcher.update.outer_middleware(UpdateMiddleware(started_at=datetime.now(tz=timezone.utc)))
    dispatcher.include_router(
        build_router(
            bot,  # type: ignore[arg-type]
            settings,
            directory,
            moderator,
            samples,
            audit,
            wordlist,
        )
    )

    # Mirrors src/snitch/bot.py: the watcher must be its own included router.
    # A catch-all registered with dispatcher.message.register(...) is checked
    # before included routers and would shadow the commands.
    watch_router = Router(name="watcher")

    async def watch(message: Message) -> None:
        await watcher.handle(message)

    watch_router.message.register(watch)
    dispatcher.include_router(watch_router)
    return dispatcher


def update_from(text: str, sender_id: int = OWNER_ID, message_id: int = 1) -> Update:
    user = make_user(sender_id, f"user{sender_id}")
    chat = Chat(id=CHAT_ID, type="supergroup")
    message = Message(
        message_id=message_id,
        date=datetime.now(tz=timezone.utc),
        chat=chat,
        from_user=user,
        text=text,
    )
    return Update(update_id=message_id, message=message)


# ===========================================================================
# /id  (open to everyone)
# ===========================================================================
async def test_id_reports_the_identifiers_needed_for_env(tmp_path):
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from("/id"))  # type: ignore[arg-type]

    reply = bot.replies[0]
    assert str(CHAT_ID) in reply
    assert str(OWNER_ID) in reply
    assert "message_thread_id" in reply


async def test_id_works_for_a_non_admin(tmp_path):
    bot = CommandBot(caller_status="member")
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from("/id", sender_id=RESTRICTOR_ID))  # type: ignore[arg-type]

    assert str(CHAT_ID) in bot.replies[0]


# ===========================================================================
# authorization
# ===========================================================================
@pytest.mark.parametrize("command", ["/status", "/check"])
async def test_privileged_commands_are_denied_to_plain_members(tmp_path, command):
    bot = CommandBot(caller_status="member")
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from(command, sender_id=RESTRICTOR_ID))  # type: ignore[arg-type]

    assert "administrators only" in bot.replies[0]


@pytest.mark.parametrize("command", ["/status", "/check"])
async def test_admin_ids_grant_access_without_chat_admin_rights(tmp_path, command):
    bot = CommandBot(caller_status="member")
    dispatcher = build_dispatcher(bot, tmp_path, admin_ids=[RESTRICTOR_ID])

    await dispatcher.feed_update(bot, update_from(command, sender_id=RESTRICTOR_ID))  # type: ignore[arg-type]

    assert "administrators only" not in bot.replies[0]


async def test_unmute_is_denied_to_plain_members(tmp_path):
    bot = CommandBot(caller_status="member")
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from("/unmute 111", sender_id=RESTRICTOR_ID))  # type: ignore[arg-type]

    assert bot.restricted_users == []
    assert "administrators only" in bot.replies[0]


# ===========================================================================
# /check
# ===========================================================================
async def test_check_reports_when_nothing_is_buffered(tmp_path):
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from("/check"))  # type: ignore[arg-type]

    assert "No messages buffered" in bot.replies[0]


async def test_commands_and_the_watcher_coexist_on_one_dispatcher(tmp_path):
    """Regression: a catch-all on dispatcher.message shadows included routers.

    The watcher used to be registered with @dispatcher.message(), which is
    matched before any included router - so /id, /status, /check and /unmute
    never ran at all. Both must now work on the same Dispatcher.
    """
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    # 1. the watcher must act on a violating message
    violation = make_message(
        make_user(ALICE_ID, "alice"),
        text="sure thing",
        reply_to_sender=make_user(BOB_ID, "bob"),
    )
    await dispatcher.feed_update(bot, Update(update_id=1, message=violation))  # type: ignore[arg-type]
    assert bot.deleted, "the watcher did not delete the violating message"

    # 2. a command must still be handled on the same dispatcher
    await dispatcher.feed_update(bot, update_from("/id", message_id=2))  # type: ignore[arg-type]

    assert bot.replies, "the command router was shadowed by the watcher"
    assert str(CHAT_ID) in bot.replies[-1]


def loaded_wordlist(tmp_path: Any, body: str) -> WordList:
    """A word list read from a real file, as it would be in production."""
    path = tmp_path / "wordlist.txt"
    path.write_text(body, encoding="utf-8")
    wordlist = WordList(path, min_reload_interval=0.0)
    wordlist.reload()
    return wordlist


async def test_blacklist_reports_a_loaded_file(tmp_path):
    """A file-based rule fails in ways a config switch cannot: a volume that was
    not mounted, a typo in a regex, a wrong path. This answers "is it live?"."""
    bot = CommandBot()
    wordlist = loaded_wordlist(tmp_path, "alpha\nbeta\n")
    dispatcher = build_dispatcher(bot, tmp_path, wordlist=wordlist)

    await dispatcher.feed_update(bot, update_from("/blacklist", message_id=9))  # type: ignore[arg-type]

    reply = bot.replies[-1]
    assert "active entries</code> = 2" in reply
    assert "alpha" in reply


async def test_blacklist_says_so_when_the_file_is_missing(tmp_path):
    bot = CommandBot()
    wordlist = WordList(tmp_path / "absent.txt", min_reload_interval=0.0)
    dispatcher = build_dispatcher(bot, tmp_path, wordlist=wordlist)

    await dispatcher.feed_update(bot, update_from("/blacklist", message_id=10))  # type: ignore[arg-type]

    reply = bot.replies[-1]
    assert "does not exist" in reply
    assert "without a restart" in reply


async def test_blacklist_surfaces_unusable_lines(tmp_path):
    """Silently ignoring a third of someone's list is the worst outcome."""
    bot = CommandBot()
    wordlist = loaded_wordlist(tmp_path, "good\nre:[unclosed\n")
    dispatcher = build_dispatcher(bot, tmp_path, wordlist=wordlist)

    await dispatcher.feed_update(bot, update_from("/blacklist", message_id=11))  # type: ignore[arg-type]

    assert "unusable lines</code> = 1" in bot.replies[-1]


async def test_blacklist_is_admin_only(tmp_path):
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path, wordlist=WordList(tmp_path / "w.txt"))

    await dispatcher.feed_update(  # type: ignore[arg-type]
        bot, update_from("/blacklist", sender_id=STRANGER_ID, message_id=12)
    )

    assert "administrators only" in bot.replies[-1]


async def test_help_mentions_blacklist(tmp_path):
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from("/help", message_id=13))  # type: ignore[arg-type]

    assert "/blacklist" in bot.replies[-1]


async def test_check_output_lists_blocked_messages(tmp_path):
    """A real violation reaches the buffer, then /check reports it.

    This is the regression test for /check raising UnboundLocalError when it
    tried to iterate its own sample buffer.
    """
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    # A restricted user replies to another restricted user in a topic that is
    # not whitelisted, so the watcher buffers it.
    violation = make_message(
        make_user(ALICE_ID, "alice"),
        text="sure thing",
        reply_to_sender=make_user(BOB_ID, "bob"),
    )
    await dispatcher.feed_update(bot, Update(update_id=1, message=violation))  # type: ignore[arg-type]

    await dispatcher.feed_update(bot, update_from("/check", message_id=2))  # type: ignore[arg-type]

    reply = bot.replies[-1]
    assert "would be blocked" in reply
    assert "BLOCK" in reply
    assert "reply" in reply


async def test_check_marks_whitelisted_messages(tmp_path):
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    whitelisted = make_message(
        make_user(ALICE_ID, "alice"),
        text="sure thing",
        reply_to_sender=make_user(BOB_ID, "bob"),
        thread_id=42,
    )
    await dispatcher.feed_update(bot, Update(update_id=1, message=whitelisted))  # type: ignore[arg-type]

    await dispatcher.feed_update(bot, update_from("/check", message_id=2))  # type: ignore[arg-type]

    assert "No messages buffered" in bot.replies[-1], (
        "whitelisted messages return before the buffer, so /check stays clean"
    )


# ===========================================================================
# /status
# ===========================================================================
async def test_status_lists_restricted_users_without_the_token(tmp_path):
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from("/status"))  # type: ignore[arg-type]

    reply = bot.replies[0]
    assert "@alice" in reply
    assert "@bob" in reply
    assert "TEST_TOKEN" not in reply
    assert "bot_token" not in reply


async def test_status_reports_recent_violations(tmp_path):
    bot = CommandBot()
    settings = make_settings(tmp_path=tmp_path)
    audit = AuditLog(tmp_path)
    audit.record(event="violation", user_id=ALICE_ID, deleted=True)

    directory = make_holder()
    moderator = Moderator(
        bot=bot,  # type: ignore[arg-type]
        settings=settings,
        directory=directory,
        audit=audit,
        notifier=Notifier(bot, settings),  # type: ignore[arg-type]
    )
    dispatcher = Dispatcher()
    dispatcher.include_router(
        build_router(bot, settings, directory, moderator, RecentSamples(), audit)  # type: ignore[arg-type]
    )

    await dispatcher.feed_update(bot, update_from("/status"))  # type: ignore[arg-type]

    reply = bot.replies[0]
    assert "Last violations" in reply
    # The audit line is embedded as escaped JSON, so only the key survives.
    assert "user_id" in reply
    assert str(ALICE_ID) in reply


# ===========================================================================
# /unmute
# ===========================================================================
async def test_unmute_lifts_the_restriction_by_numeric_id(tmp_path):
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from(f"/unmute {ALICE_ID}"))  # type: ignore[arg-type]

    assert bot.restricted_users[0]["user_id"] == ALICE_ID
    assert bot.restricted_users[0]["until_date"] == 0
    assert "Restrictions lifted" in bot.replies[0]


async def test_unmute_resolves_a_username(tmp_path):
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from("/unmute @alice"))  # type: ignore[arg-type]

    assert bot.restricted_users[0]["user_id"] == ALICE_ID


async def test_unmute_requires_an_argument(tmp_path):
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from("/unmute"))  # type: ignore[arg-type]

    assert bot.restricted_users == []
    assert "Usage" in bot.replies[0]


async def test_unmute_refuses_a_user_outside_the_restricted_set(tmp_path):
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from("/unmute @carol"))  # type: ignore[arg-type]

    assert bot.restricted_users == []
    assert "nothing to unmute" in bot.replies[0]


async def test_unmute_reports_a_telegram_failure(tmp_path):
    bot = CommandBot()

    async def failing_restrict(**kwargs: Any) -> bool:  # noqa: ARG001 - must accept the call
        raise TelegramBadRequest(method=None, message="Bad Request: not enough rights")

    bot.restrict_chat_member = failing_restrict  # type: ignore[method-assign]
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from(f"/unmute {ALICE_ID}"))  # type: ignore[arg-type]

    assert "Could not lift" in bot.replies[0]


# ===========================================================================
# help
# ===========================================================================
async def test_help_lists_the_available_commands(tmp_path):
    bot = CommandBot()
    dispatcher = build_dispatcher(bot, tmp_path)

    await dispatcher.feed_update(bot, update_from("/help"))  # type: ignore[arg-type]

    reply = bot.replies[0]
    for command in ("/id", "/status", "/check", "/unmute"):
        assert command in reply
