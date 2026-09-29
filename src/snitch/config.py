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
from urllib.parse import unquote, urlsplit

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

#: Proxy schemes ``aiohttp_socks.parse_proxy_url`` can actually parse. Note that
#: ``socks5h`` is NOT accepted even though many tools take it - and it is
#: unnecessary here, because aiogram hardcodes ``rdns=True``, so DNS is always
#: resolved by the proxy rather than locally.
PROXY_SCHEMES: Final[tuple[str, ...]] = ("socks5", "socks4", "http", "https")

#: Port assumed when the URL omits one.
DEFAULT_PROXY_PORTS: Final[dict[str, int]] = {
    "socks5": 1080,
    "socks4": 1080,
    "http": 8080,
    "https": 8080,
}


class NoticeMode(str, Enum):
    """What to do after a violation, besides deleting the message."""

    LOG = "log"
    CHAT = "chat"
    DM = "dm"
    NONE = "none"


class LogFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


class ProxyConfig:
    """An outbound proxy for every Telegram API call, given as one URL.

    Existence is derived from ``PROXY_URL`` being non-empty rather than a
    separate on/off flag, so "enabled but no host" is not a reachable state.

    The password inside the URL is treated as a secret: it is never logged, never
    included in :meth:`Settings.redacted_summary`, and is added to the log
    scrubber so it cannot leak through an exception message.
    """

    def __init__(self, url: str = "") -> None:
        self._url = url.strip()
        self._parts = urlsplit(self._url) if self._url else None

    @property
    def enabled(self) -> bool:
        """Whether a proxy was configured."""
        return bool(self._url)

    @property
    def port(self) -> int | None:
        """The explicit port from the URL, or ``None`` if it was omitted."""
        return self._parts.port if self._parts is not None else None

    @property
    def host(self) -> str:
        """The proxy hostname, or empty."""
        return (self._parts.hostname or "") if self._parts is not None else ""

    @property
    def effective_port(self) -> int:
        """The port that will actually be dialled, applying the scheme default."""
        if self.port is not None:
            return self.port
        return DEFAULT_PROXY_PORTS.get(
            (self._parts.scheme.lower() if self._parts is not None else ""), 1080
        )

    @property
    def url(self) -> str:
        """The URL to hand to ``AiohttpSession``."""
        return self._url

    @property
    def password(self) -> str:
        """The proxy password, decoded. Empty if there is none."""
        if self._parts is None or self._parts.password is None:
            return ""
        return unquote(self._parts.password)

    @property
    def password_encoded(self) -> str:
        """The proxy password exactly as it appears in the URL.

        A connection error or a log line containing the raw URL shows the
        percent-encoded form, so both spellings must be scrubbed.
        """
        if self._parts is None or self._parts.password is None:
            return ""
        return self._parts.password

    @property
    def redacted(self) -> str:
        """Safe to log: the password is replaced, never printed."""
        if self._parts is None:
            return "disabled"
        host = self._parts.hostname or ""
        if self._parts.port:
            host = f"{host}:{self._parts.port}"
        if self._parts.username:
            return f"{self._parts.scheme}://{self._parts.username}:***@{host}"
        return f"{self._parts.scheme}://***@{host}"

    def __bool__(self) -> bool:
        return self.enabled

    def __repr__(self) -> str:
        return f"ProxyConfig({self.redacted})"


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

    # --- network ----------------------------------------------------------
    #: Outbound proxy for every Telegram API call, e.g.
    #: ``socks5://user:password@127.0.0.1:1080``. Empty means direct.
    #:
    #: ``repr=False`` because a pydantic repr lists raw field values, and this
    #: one embeds a password. ``bot_token`` is a SecretStr and safe by
    #: construction; a bare str is not, so it is hidden from repr/str outright.
    #: Use redacted_summary() for a dump that is safe to print.
    proxy_url: str = Field(default="", repr=False)

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

    # --- network tuning ---------------------------------------------------
    #: Per-request timeout, in seconds, for calls to the Telegram API. Lower it
    #: when a proxy stalls: aiohttp's default is 30s, and the SOCKS connect
    #: timeout defaults to 60s, so an unresponsive proxy can leave the bot blind
    #: for up to a minute per attempt. Polling retries on its own, so a shorter
    #: value means faster recovery rather than fewer retries.
    request_timeout: float = Field(default=30.0, ge=5.0, le=300.0)

    #: Confirms you have checked @BotFather -> /setprivacy for this bot and it
    #: reads Disable. Privacy mode is not queryable through the Bot API, so
    #: snitch cannot tell whether it is deaf for this reason; left false, it
    #: keeps reminding you. Set it once you have verified it - it is a permanent
    #: property of the bot, not of the chat, so it never changes back.
    privacy_mode_verified: bool = False

    #: Act on messages that predate this process. Telegram replays a backlog
    #: through getUpdates after downtime, so leaving this false is what stops a
    #: restarting bot from retroactively deleting messages and starting mutes
    #: for offences that already happened days ago. Set it to true only if you
    #: deliberately want the backlog processed on the next start.
    process_backlog: bool = False

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

    @field_validator("proxy_url")
    @classmethod
    def _validate_proxy_url(cls, value: str) -> str:
        """Validate the proxy URL up front, with messages worth reading.

        Rejecting a bad proxy here matters: the alternative is a connection error
        several layers down that looks like a Telegram outage.
        """
        url = value.strip()
        if not url:
            return ""

        parts = urlsplit(url)
        scheme = parts.scheme.lower()

        if scheme == "socks5h":
            raise ValueError(
                "PROXY_URL must not use socks5h: aiohttp_socks rejects that scheme. "
                "Use socks5 - DNS is already resolved by the proxy, so socks5h adds "
                "nothing here."
            )
        if scheme not in PROXY_SCHEMES:
            raise ValueError(
                f"PROXY_URL scheme {scheme or '(missing)'!r} is not supported; "
                f"use one of: {', '.join(PROXY_SCHEMES)}"
            )
        if not parts.hostname:
            raise ValueError(
                f"PROXY_URL {ProxyConfig(url).redacted!r} has no host; expected something "
                f"like {scheme}://user:password@127.0.0.1:1080"
            )
        try:
            port = parts.port
        except ValueError as exc:
            raise ValueError(f"PROXY_URL has an invalid port: {exc}") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError(f"PROXY_URL port {port} is out of range")
        if parts.username and parts.password is None:
            raise ValueError(
                "PROXY_URL has a username but no password; give both or neither. "
                "A username with an empty password is rejected by most SOCKS servers."
            )
        if parts.password and not parts.username:
            raise ValueError("PROXY_URL has a password but no username; give both or neither.")

        return url

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
    def proxy(self) -> ProxyConfig:
        """The validated outbound proxy."""
        return ProxyConfig(self.proxy_url)

    @property
    def secrets(self) -> tuple[str, ...]:
        """Every value that must never reach a log sink.

        Includes both spellings of a proxy password: percent-decoded, which is
        what connection errors tend to contain, and percent-encoded, which is
        what the raw ``PROXY_URL`` contains.
        """
        proxy = self.proxy
        unique: list[str] = []
        for value in (self.token, proxy.password_encoded, proxy.password):
            if value and value not in unique:
                unique.append(value)
        return tuple(unique)

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
            "proxy_url": self.proxy.redacted,
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
            "request_timeout": self.request_timeout,
            "process_backlog": self.process_backlog,
            "privacy_mode_verified": self.privacy_mode_verified,
            "data_dir": str(self.data_dir),
        }
