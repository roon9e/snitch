"""The rule engine.

This module is deliberately free of I/O: every function here is a pure
transformation of a :class:`aiogram.types.Message` plus configuration into a
decision. That keeps the only interesting logic in the project fully unit
testable without a network, a bot token, or an event loop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from aiogram.types import Message, MessageEntity

from snitch.config import Settings
from snitch.directory import Directory

#: ``mention`` entities are not guaranteed to expose ``url``, but in practice
#: Telegram populates it as ``tg://user?id=<id>``. Parsing it gives us an exact
#: id with no username lookup; we still fall back to the username map.
_TG_USER_URL_RE = re.compile(r"^tg://user\?id=(?P<id>-?\d+)$")


class TargetKind(str, Enum):
    """How a restricted user was addressed."""

    REPLY = "reply"
    EXTERNAL_REPLY = "external_reply"
    MENTION = "mention"
    TEXT_MENTION = "text_mention"
    BARE_USERNAME = "bare_username"


@dataclass(frozen=True, slots=True)
class Target:
    """One restricted user addressed by the offending message."""

    kind: TargetKind
    user_id: int | None = None
    username: str | None = None
    detail: str = ""

    def describe(self) -> str:
        """Human readable label used in log lines and admin commands."""
        who = f"id={self.user_id}" if self.user_id is not None else f"@{self.username}"
        return f"{self.kind.value}({who})"


@dataclass(frozen=True, slots=True)
class Detection:
    """The set of restricted users a message addresses."""

    targets: tuple[Target, ...] = field(default_factory=tuple)

    def __bool__(self) -> bool:
        return bool(self.targets)

    @property
    def user_ids(self) -> frozenset[int]:
        """Known numeric ids among the targets."""
        return frozenset(t.user_id for t in self.targets if t.user_id is not None)

    def summary(self) -> str:
        """Compact, log-friendly rendering of every target."""
        return ", ".join(target.describe() for target in self.targets)


NO_DETECTION = Detection()

#: Detectors run in descending order of trustworthiness, so when the same user is
#: found twice the first hit is the one worth reporting. A structured signal
#: (a real reply, a real mention entity) always beats the fuzzy text scan.
_DETECTOR_ORDER: tuple[str, ...] = (
    TargetKind.REPLY.value,
    TargetKind.EXTERNAL_REPLY.value,
    TargetKind.TEXT_MENTION.value,
    TargetKind.MENTION.value,
    TargetKind.BARE_USERNAME.value,
)


def _dedupe(targets: list[Target]) -> tuple[Target, ...]:
    """Collapse multiple hits on the same user, keeping the strongest signal.

    Without this, a single ``@mention`` is seen twice - once by the entity
    detector and once by the bare-text scan - and the user would be announced
    and audited as if they had committed two separate offences.
    """
    priority = {kind: index for index, kind in enumerate(_DETECTOR_ORDER)}
    best: dict[int | str, Target] = {}

    for target in targets:
        key: int | str = target.user_id if target.user_id is not None else f"@{target.username}"
        incumbent = best.get(key)
        if incumbent is None or priority[target.kind.value] < priority[incumbent.kind.value]:
            best[key] = target

    return tuple(sorted(best.values(), key=lambda t: priority[t.kind.value]))


# ---------------------------------------------------------------------------
# topic whitelist
# ---------------------------------------------------------------------------
def is_whitelisted(message: Message, settings: Settings) -> bool:
    """Whether ``message`` was posted in a topic that bypasses the rule.

    The General topic of a forum supergroup is identified by the *absence* of
    ``message_thread_id``, which is why it gets its own config alias.
    """
    thread_id = message.message_thread_id
    if thread_id is None:
        return settings.whitelist_general
    return thread_id in settings.whitelist_thread_ids


# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------
def _reply_target(message: Message, directory: Directory) -> Target | None:
    """Target of an in-chat reply, if any."""
    replied = message.reply_to_message
    if replied is None or replied.from_user is None:
        return None
    user = replied.from_user
    if directory.matches(user.id, user.username):
        return Target(
            kind=TargetKind.REPLY,
            user_id=user.id,
            username=user.username,
            detail=f"reply to message {replied.message_id}",
        )
    return None


def _external_reply_target(message: Message, directory: Directory) -> Target | None:
    """Target of a reply that crosses forum topics or chats (Bot API 7.0+).

    ``external_reply`` is a newer field that older aiogram builds may not expose
    at all, hence the defensive ``getattr``. The origin shape also changed
    across Bot API versions, so both layouts are accepted.
    """
    external = getattr(message, "external_reply", None)
    if external is None:
        return None
    origin = getattr(external, "origin", None)
    if origin is None:
        return None

    # Bot API 9+: MessageOriginUser.sender_user
    user = getattr(origin, "sender_user", None)
    if user is None:
        # Bot API 7.x/8.x: origin.message.from_user
        user = getattr(getattr(origin, "message", None), "from_user", None)
    if user is None:
        return None

    if directory.matches(user.id, user.username):
        return Target(
            kind=TargetKind.EXTERNAL_REPLY,
            user_id=user.id,
            username=user.username,
            detail="reply across topics",
        )
    return None


def _entity_targets(
    message: Message,
    directory: Directory,
) -> list[Target]:
    """Targets found in mention / text-mention entities.

    ``Message.text`` and ``Message.caption`` are searched for entities because
    entities can be attached to either.
    """
    found: list[Target] = []
    for text, entities in (
        (message.text, message.entities),
        (message.caption, message.caption_entities),
    ):
        if not text or not entities:
            continue
        for entity in entities:
            target = _entity_target(entity, text, directory)
            if target is not None and target not in found:
                found.append(target)
    return found


def _entity_target(
    entity: MessageEntity,
    text: str,
    directory: Directory,
) -> Target | None:
    """Resolve a single entity to a restricted user, if it is one."""
    if entity.type == "text_mention":
        user = getattr(entity, "user", None)
        if user is not None and directory.matches(user.id, user.username):
            return Target(
                kind=TargetKind.TEXT_MENTION,
                user_id=user.id,
                username=user.username,
                detail="tap-to-mention",
            )
        return None

    if entity.type != "mention":
        return None

    # Prefer the exact id Telegram embeds in the entity url when present.
    url = getattr(entity, "url", None) or ""
    match = _TG_USER_URL_RE.match(url)
    if match is not None:
        user_id = int(match.group("id"))
        if user_id in directory.user_ids:
            return Target(
                kind=TargetKind.MENTION,
                user_id=user_id,
                detail="mention",
            )

    snippet = text[entity.offset : entity.offset + entity.length]
    username = (snippet or "").lstrip("@").lower() or None
    if username and directory.matches(username=username):
        return Target(
            kind=TargetKind.MENTION,
            # Resolve to the id so that every target can be deduplicated by
            # identity, whichever detector produced it.
            user_id=directory.find_by_username(username),
            username=username,
            detail=f"@{username}",
        )
    return None


def _bare_username_targets(
    message: Message,
    directory: Directory,
) -> list[Target]:
    """Targets found by scanning the raw text for restricted usernames.

    This is the fuzzy signal: it catches ``hey alice`` style references that
    carry no mention entity, and it can be evaded by dropping the "@" or by
    renaming the account.
    """
    if not directory.usernames:
        return []

    found: list[Target] = []
    for text in (message.text, message.caption):
        if not text:
            continue
        lowered = text.lower()
        for username, user_id in directory.usernames.items():
            for pattern in (rf"@{re.escape(username)}\b", rf"\b{re.escape(username)}\b"):
                if re.search(pattern, lowered):
                    found.append(
                        Target(
                            kind=TargetKind.BARE_USERNAME,
                            user_id=user_id,
                            username=username,
                            detail=f"text contains @{username}",
                        )
                    )
                    break
    return found


def detect(message: Message, settings: Settings, directory: Directory) -> Detection:
    """Run every enabled detector and collect the restricted users addressed.

    Each detector runs independently so that ``.env`` switches are meaningful,
    and duplicates are collapsed so a single ``@mention`` is reported once.
    """
    if not settings.detection_enabled or not directory:
        return NO_DETECTION

    targets: list[Target] = []

    if settings.detect_replies:
        for candidate in (
            _reply_target(message, directory),
            _external_reply_target(message, directory),
        ):
            if candidate is not None:
                targets.append(candidate)

    if settings.detect_mentions:
        targets.extend(_entity_targets(message, directory))

    if settings.detect_bare_usernames:
        targets.extend(_bare_username_targets(message, directory))

    if not targets:
        return NO_DETECTION
    return Detection(targets=_dedupe(targets))
