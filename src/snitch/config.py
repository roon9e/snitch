"""Typed, validated configuration loaded from the environment / ``.env`` file.

Everything the bot does is driven from here, so parsing is strict and happens
once at startup: a malformed id or an out-of-range mute duration is a hard boot
failure rather than a surprise discovered hours later.
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Final

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

#: 366 days in hours. Telegram treats any restriction longer than this as
#: permanent, so we refuse to build one by accident.
MAX_MUTE_HOURS: Final[int] = 8784

#: Alias accepted in ``WHITELIST_TOPIC_IDS`` for the supergroup's General topic.
#: Messages in the General topic carry no ``message_thread_id``.
GENERAL_TOPIC: Final[str] = "general"

_USERNAME_RE: Final[re.Pattern[str]] = re.compile(r"^@?(?P<name>[A-Za-z0-9_]{4,32})$")
_LINK_PREFIXES: Final[tuple[str, ...]] = ("https://t.me/", "http://t.me/", "t.me/", "tg://")


class NoticeMode(str, Enum):
    """What to do after a violation, besides deleting the message."""

    LOG = "log"
    CHAT = "chat"
    DM = "dm"
    NONE = "none"


class LogFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


def normalize_username(raw: str) -> str | None:
    """Reduce any user reference to a bare lowercase username, or ``None``.

    Accepts ``@alice``, ``alice``, ``https://t.me/alice`` and friends so that
    pasting a profile link into ``.env`` just works.
    """
    value = raw.strip()
    if not value:
        return None
    for prefix in _LINK_PREFIXES:
        if value.lower().startswith(prefix):
            value = value[len(prefix) :]
            break
    value = value.split("?", 1)[0].split("/", 1)[0]
    match = _USERNAME_RE.match(value)
    return match.group("name").lower() if match else None


def _split_csv(raw: Any) -> list[str]:
    """Turn a raw settings value into a list of non-empty, stripped strings.

    Accepts either a single comma separated string (the normal environment
    variable case) or a sequence, and splits the elements of a sequence too, so
    ``"1,2"`` and ``["1,2"]`` behave identically.
    """
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set, frozenset)):
        items: list[str] = []
        for element in raw:
            items.extend(str(element).split(","))
    else:
        items = str(raw).split(",")
    return [item.strip() for item in items if item.strip()]


class Settings(BaseSettings):
    """Bot configuration.

    The list-valued fields use ``NoDecode`` so that pydantic-settings hands the
    raw string to our validator instead of trying (and failing) to JSON-decode
    ``111111111,222222222``.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- required ---------------------------------------------------------
    bot_token: SecretStr
    chat_id: int | str

    # --- the rule ---------------------------------------------------------
    restricted_users: Annotated[list[int | str], NoDecode] = Field(default_factory=list)
    whitelist_topic_ids: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- punishment -------------------------------------------------------
    delete_message: bool = True
    mute_enabled: bool = False
    mute_hours: int = Field(default=24, ge=1, le=MAX_MUTE_HOURS)

    # --- detection --------------------------------------------------------
    detect_replies: bool = True
    detect_mentions: bool = True
    detect_bare_usernames: bool = True

    # --- behaviour --------------------------------------------------------
    ignore_admins: bool = True
    notice_mode: NoticeMode = NoticeMode.LOG
    admin_ids: Annotated[list[int], NoDecode] = Field(default_factory=list)
    directory_refresh_hours: float = Field(default=6.0, ge=0.1, le=720.0)
    mute_cooldown_seconds: float = Field(default=30.0, ge=0.0, le=3600.0)

    # --- observability ----------------------------------------------------
    log_level: str = "INFO"
    log_format: LogFormat = LogFormat.TEXT
    data_dir: Path = Path("data")

    # ------------------------------------------------------------------
    # validators
    # ------------------------------------------------------------------
    @field_validator("restricted_users", mode="before")
    @classmethod
    def _parse_restricted_users(cls, raw: Any) -> list[int | str]:
        refs: list[int | str] = []
        seen: set[int | str] = set()
        for item in _split_csv(raw):
            key = item.lower()
            if key.lstrip("-").isdigit():
                ref: int | str = int(item)
            else:
                username = normalize_username(item)
                if username is None:
                    raise ValueError(
                        f"RESTRICTED_USERS entry {item!r} is neither a numeric user id "
                        f"nor a valid @username"
                    )
                ref = f"@{username}"
            if ref not in seen:
                seen.add(ref)
                refs.append(ref)
        return refs

    @field_validator("admin_ids", mode="before")
    @classmethod
    def _parse_admin_ids(cls, raw: Any) -> list[int]:
        ids: list[int] = []
        for item in _split_csv(raw):
            if not item.lstrip("-").isdigit():
                raise ValueError(f"ADMIN_IDS entry {item!r} is not a numeric user id")
            user_id = int(item)
            if user_id not in ids:
                ids.append(user_id)
        return ids

    @field_validator("whitelist_topic_ids", mode="before")
    @classmethod
    def _parse_whitelist_topic_ids(cls, raw: Any) -> list[str]:
        topics: list[str] = []
        for item in _split_csv(raw):
            key = item.lower()
            # "general" / "0" must be checked before the numeric branch, since
            # "0" is a digit but is the documented alias for the General topic.
            if key in (GENERAL_TOPIC, "0"):
                normalized = GENERAL_TOPIC
            elif key.lstrip("-").isdigit():
                normalized = str(int(item))
            else:
                raise ValueError(
                    f"WHITELIST_TOPIC_IDS entry {item!r} is not a topic id; "
                    f'use a number or "{GENERAL_TOPIC}"'
                )
            if normalized not in topics:
                topics.append(normalized)
        return topics

    @field_validator("bot_token")
    @classmethod
    def _validate_token(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("BOT_TOKEN must not be empty")
        return value

    @field_validator("chat_id")
    @classmethod
    def _normalize_chat_id(cls, value: int | str) -> int | str:
        """Coerce a numeric CHAT_ID to ``int``, leaving ``@username`` alone.

        Without this, pydantic's smart union keeps an environment-supplied
        ``CHAT_ID=-100123`` as a *string* because ``str`` is a valid member of
        ``int | str``. Anything that inspects the id - the supergroup shape check
        in particular - would then silently take the wrong branch.
        """
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        if not stripped:
            raise ValueError("CHAT_ID must not be empty")
        if stripped.startswith("@"):
            return stripped
        try:
            return int(stripped)
        except ValueError as exc:
            raise ValueError(
                f"CHAT_ID {value!r} is neither a numeric group id nor an @username"
            ) from exc

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
        upper = value.strip().upper()
        if upper not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(allowed)}")
        return upper

    # ------------------------------------------------------------------
    # derived helpers
    # ------------------------------------------------------------------
    @property
    def token(self) -> str:
        """The raw bot token."""
        return self.bot_token.get_secret_value()

    @property
    def whitelist_thread_ids(self) -> frozenset[int]:
        """Numeric forum topic ids that bypass the rule."""
        return frozenset(int(topic) for topic in self.whitelist_topic_ids if topic != GENERAL_TOPIC)

    @property
    def whitelist_general(self) -> bool:
        """Whether the supergroup's General topic bypasses the rule."""
        return GENERAL_TOPIC in self.whitelist_topic_ids

    @property
    def detection_enabled(self) -> bool:
        """Whether any detection signal is switched on."""
        return self.detect_replies or self.detect_mentions or self.detect_bare_usernames

    def whitelisted_topic_ids(self) -> frozenset[int]:
        """Public alias of :attr:`whitelist_thread_ids` (readability at call sites)."""
        return self.whitelist_thread_ids

    def redacted_summary(self) -> dict[str, object]:
        """Config as a dict, safe to print or log."""
        return {
            "chat_id": self.chat_id,
            "bot_token": "***redacted***",
            "restricted_users": list(self.restricted_users),
            "whitelist_topic_ids": list(self.whitelist_topic_ids),
            "delete_message": self.delete_message,
            "mute_enabled": self.mute_enabled,
            "mute_hours": self.mute_hours,
            "detect_replies": self.detect_replies,
            "detect_mentions": self.detect_mentions,
            "detect_bare_usernames": self.detect_bare_usernames,
            "ignore_admins": self.ignore_admins,
            "notice_mode": self.notice_mode.value,
            "log_level": self.log_level,
            "log_format": self.log_format.value,
            "data_dir": str(self.data_dir),
        }
