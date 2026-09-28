"""Resolution of ``RESTRICTED_USERS`` into canonical user ids and usernames.

``.env`` may name users by numeric id or by ``@username``. Telegram usernames are
mutable, so this module keeps a live mapping: at boot (and on a timer) every
configured reference is resolved through ``getChatMember``, which yields both the
permanent id and the account's current username. A configured username that no
longer resolves to the same account produces a loud warning rather than a silent
gap in the rule.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from aiogram import Bot
from aiogram.exceptions import TelegramAPIError

from snitch.config import Settings, normalize_username

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DirectoryEntry:
    """A restricted user as the bot currently understands them."""

    user_id: int
    username: str | None = None
    configured_as: str = ""


@dataclass(slots=True)
class Directory:
    """A snapshot of the restricted set, refreshed periodically."""

    entries: tuple[DirectoryEntry, ...] = field(default_factory=tuple)
    unresolved: tuple[str, ...] = field(default_factory=tuple)
    stale_usernames: tuple[str, ...] = field(default_factory=tuple)

    # --- lookups used by the rule engine ----------------------------------
    @property
    def user_ids(self) -> frozenset[int]:
        """Numeric ids of every resolved restricted user."""
        return frozenset(entry.user_id for entry in self.entries)

    @property
    def usernames(self) -> dict[str, int]:
        """Lowercase username -> id, for bare-text scanning."""
        return {
            entry.username: entry.user_id for entry in self.entries if entry.username is not None
        }

    def matches(self, user_id: int | None = None, username: str | None = None) -> bool:
        """Whether a user is restricted, by id or by (normalized) username."""
        if user_id is not None and user_id in self.user_ids:
            return True
        if username:
            normalized = normalize_username(username)
            return normalized is not None and normalized in self.usernames
        return False

    def find_by_username(self, username: str) -> int | None:
        """Resolve any user reference form to a restricted user id, or ``None``."""
        normalized = normalize_username(username)
        if normalized is None:
            return None
        return self.usernames.get(normalized)

    def label(self, user_id: int) -> str:
        """``@alice (123)`` style label for logs and admin replies."""
        for entry in self.entries:
            if entry.user_id == user_id:
                return f"@{entry.username} ({user_id})" if entry.username else str(user_id)
        return str(user_id)

    def __bool__(self) -> bool:
        return bool(self.entries)

    def __len__(self) -> int:
        return len(self.entries)


class DirectoryHolder:
    """A swappable slot holding the current :class:`Directory` snapshot.

    ``Directory`` is an immutable snapshot, but the restricted set has to be
    refreshable at runtime (usernames drift). Handing every component this holder
    instead of a ``Directory`` means a refresh is a single attribute assignment
    and no consumer can be left holding a stale copy.
    """

    def __init__(self, directory: Directory) -> None:
        self._current = directory

    @property
    def current(self) -> Directory:
        """The active snapshot."""
        return self._current

    def replace(self, directory: Directory) -> None:
        """Install a freshly resolved snapshot."""
        self._current = directory

    def __len__(self) -> int:
        return len(self._current)

    def __bool__(self) -> bool:
        return bool(self._current)


async def resolve(bot: Bot, settings: Settings) -> Directory:
    """Resolve every configured reference against the live chat.

    Never raises: a reference we cannot resolve is reported in
    :attr:`Directory.unresolved` so the caller can warn and carry on.
    """
    entries: dict[int, DirectoryEntry] = {}
    unresolved: list[str] = []
    stale: list[str] = []

    for ref in settings.restricted_users:
        entry, problem = await _lookup(bot, settings, ref, configured_as=ref)
        if entry is None:
            unresolved.append(str(ref))
            logger.debug("could not resolve %r: %s", ref, problem)
            continue

        if isinstance(ref, str):
            configured_name = normalize_username(ref) or ref
            if entry.username != configured_name:
                stale.append(
                    f"{ref} now resolves to @{entry.username or '<no username>'} ({entry.user_id})"
                )
        entries.setdefault(entry.user_id, entry)

    directory = Directory(
        entries=tuple(sorted(entries.values(), key=lambda item: item.user_id)),
        unresolved=tuple(unresolved),
        stale_usernames=tuple(stale),
    )
    _log_summary(directory, settings)
    return directory


async def _lookup(
    bot: Bot,
    settings: Settings,
    reference: int | str,
    *,
    configured_as: int | str,
) -> tuple[DirectoryEntry | None, str | None]:
    """Look one reference up in the chat. Returns ``(entry, problem)``."""
    try:
        # The Bot API accepts either a numeric id or an @username here; aiogram
        # annotates the parameter as int only, which is narrower than the API.
        member = await bot.get_chat_member(
            chat_id=settings.chat_id,
            user_id=reference,  # type: ignore[arg-type]
        )
    except TelegramAPIError as exc:
        return None, str(exc)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("unexpected lookup failure for %r", reference, exc_info=exc)
        return None, str(exc)

    user = member.user
    return (
        DirectoryEntry(
            user_id=user.id,
            username=normalize_username(user.username) if user.username else None,
            configured_as=str(configured_as),
        ),
        None,
    )


def _log_summary(directory: Directory, settings: Settings) -> None:
    chat = settings.chat_id
    if not directory:
        logger.warning("no restricted users resolved from chat %s - the rule is inert", chat)
    else:
        labels = ", ".join(
            f"@{entry.username} ({entry.user_id})" if entry.username else str(entry.user_id)
            for entry in directory.entries
        )
        logger.info("restricted users resolved (%d): %s", len(directory), labels)

    for reference in directory.unresolved:
        logger.warning(
            "RESTRICTED_USERS entry %r could not be resolved in chat %s - the user may "
            "not be a member, in which case the rule cannot apply to them",
            reference,
            chat,
        )
    for note in directory.stale_usernames:
        logger.warning("RESTRICTED_USERS username drift: %s", note)
