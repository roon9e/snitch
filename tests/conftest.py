"""Shared fixtures and message builders.

Tests build real ``aiogram`` model objects rather than mocks, so the rule engine
is exercised against the same shapes the library parses off the wire.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from aiogram.types import (
    Chat,
    ChatMemberMember,
    ExternalReplyInfo,
    Message,
    MessageEntity,
    MessageOriginUser,
    User,
)

from snitch.config import Settings
from snitch.directory import Directory, DirectoryEntry, DirectoryHolder

CHAT_ID = -1001234567890
OTHER_CHAT_ID = -1009999999999
#: A real supergroup id shape. Telegram assigns these a fresh value whenever a
#: basic group is upgraded, which is why a stale one is a common misconfiguration.
SUPERGROUP_ID = -1003963946702
#: A basic (non-supergroup) group id, which cannot support topics or restrictions.
BASIC_GROUP_ID = -3963946702

ALICE_ID = 111
BOB_ID = 222
CAROL_ID = 333
STRANGER_ID = 999


# ---------------------------------------------------------------------------
# model builders
# ---------------------------------------------------------------------------
def make_user(
    user_id: int,
    username: str | None = None,
    is_bot: bool = False,
    first_name: str | None = None,
    last_name: str | None = None,
) -> User:
    return User(
        id=user_id,
        is_bot=is_bot,
        first_name=first_name if first_name is not None else (username or f"user{user_id}").title(),
        last_name=last_name,
        username=username,
    )


def make_chat(chat_id: int = CHAT_ID) -> Chat:
    return Chat(id=chat_id, type="supergroup")


def make_member(user: User) -> ChatMemberMember:
    return ChatMemberMember(status="member", user=user)


def make_mention_entity_from_text(text: str, snippet: str, user_id: int) -> MessageEntity:
    """A ``@mention`` entity positioned exactly where ``snippet`` occurs.

    Telegram populates ``url`` as ``tg://user?id=<id>`` for mentions, which is
    what the engine prefers over a username lookup.
    """
    offset = text.index(snippet)
    return MessageEntity(
        type="mention",
        offset=offset,
        length=len(snippet),
        url=f"tg://user?id={user_id}",
    )


def make_mention_text_mention(user: User, offset: int, length: int) -> MessageEntity:
    """A tap-to-mention entity, which carries the ``User`` object directly."""
    return MessageEntity(type="text_mention", offset=offset, length=length, user=user)


def make_message(
    sender: User | None = None,
    *,
    text: str | None = None,
    entities: list[MessageEntity] | None = None,
    caption: str | None = None,
    caption_entities: list[MessageEntity] | None = None,
    message_id: int = 1,
    chat_id: int = CHAT_ID,
    thread_id: int | None = None,
    reply_to: Message | None = None,
    reply_to_sender: User | None = None,
    external_reply_sender: User | None = None,
    sender_chat: Chat | None = None,
    is_bot: bool = False,
) -> Message:
    if reply_to_sender is not None:
        reply_to = make_message(reply_to_sender, message_id=message_id - 1, chat_id=chat_id)
    external_reply = None
    if external_reply_sender is not None:
        external_reply = ExternalReplyInfo(
            origin=MessageOriginUser(
                date=datetime.now(tz=timezone.utc),
                sender_user=external_reply_sender,
            )
        )
    return Message(
        message_id=message_id,
        date=datetime.now(tz=timezone.utc),
        chat=make_chat(chat_id),
        from_user=sender.model_copy(update={"is_bot": is_bot}) if sender else None,
        sender_chat=sender_chat,
        text=text,
        entities=entities,
        caption=caption,
        caption_entities=caption_entities,
        message_thread_id=thread_id,
        reply_to_message=reply_to,
        external_reply=external_reply,
    )


# ---------------------------------------------------------------------------
# config / directory fixtures
# ---------------------------------------------------------------------------
def make_settings(tmp_path: Path | None = None, **overrides: Any) -> Settings:
    """Build a ``Settings`` without touching the real environment or ``.env``."""
    base: dict[str, Any] = {
        "bot_token": "123456:TEST_TOKEN",
        "chat_id": CHAT_ID,
        "restricted_users": [ALICE_ID, BOB_ID],
        "whitelist_topic_ids": ["42"],
        "delete_message": True,
        "mute_enabled": False,
        "mute_hours": 24,
        "log_level": "CRITICAL",
        "data_dir": tmp_path or Path(),
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


def make_directory(
    entries: tuple[tuple[int, str | None], ...] = (
        (ALICE_ID, "alice"),
        (BOB_ID, "bob"),
    ),
) -> Directory:
    return Directory(
        entries=tuple(
            DirectoryEntry(user_id=user_id, username=username, configured_as=str(user_id))
            for user_id, username in entries
        )
    )


def make_directory_with_carol() -> Directory:
    """Alice, Bob and Carol.

    Detection tests need a third restricted user: with only alice and bob, the
    natural construction is "alice does something to bob", which made it easy to
    accidentally write "alice targets alice" - the exact false positive that
    shipping the bot must not produce.
    """
    return make_directory(
        (
            (ALICE_ID, "alice"),
            (BOB_ID, "bob"),
            (CAROL_ID, "carol"),
        )
    )


def make_holder(directory: Directory | None = None) -> DirectoryHolder:
    return DirectoryHolder(directory or make_directory())


@pytest.fixture
def alice() -> User:
    return make_user(ALICE_ID, "alice")


@pytest.fixture
def bob() -> User:
    return make_user(BOB_ID, "bob")


@pytest.fixture
def stranger() -> User:
    return make_user(STRANGER_ID, "stranger")
