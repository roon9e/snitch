"""Self-diagnosis for the "the bot started but nothing happens" failure.

The most common reason snitch looks alive but never acts is that privacy mode is
still enabled in @BotFather. With privacy mode on, Telegram never delivers other
people's messages - and in a group it does not even deliver bare ``/commands``,
only ``/command@botusername``. So the operator cannot ask the bot what is wrong:
the diagnostic channel is exactly the thing that is broken.

This module closes that loop. The monitor records every incoming update and, if
the bot has been running for a while without seeing any, logs the checklist.
No command required.

The checklist is assembled per instance rather than fixed, because "no messages"
has several causes and only some of them apply to a given deployment. Two that
matter: a bot running behind a proxy goes silent when the proxy stalls, which is
indistinguishable from privacy mode by looking at logs alone; and once an
operator has confirmed privacy mode in @BotFather, repeating that advice forever
buries the causes that are still live.
"""

from __future__ import annotations

import asyncio
import logging
import time
from types import TracebackType

logger = logging.getLogger(__name__)

#: Do not complain until the bot has had a fair chance to receive something.
DEFAULT_GRACE_SECONDS = 600.0

#: How often the background task wakes up.
DEFAULT_CHECK_INTERVAL_SECONDS = 60.0

#: After the first warning, stay quiet for this long before repeating it.
DEFAULT_REPEAT_SECONDS = 3600.0

_PRIVACY_MODE = """\
Privacy mode is still ON. @BotFather -> /setprivacy -> pick this bot -> Disable.
     Without this, Telegram does not deliver other people's messages and (in a
     group) not even bare /commands, so this bot is effectively deaf."""

_NOT_A_MEMBER = "The bot is not a member of the group, or CHAT_ID points at a different one."

_QUIET_GROUP = """\
The group is quiet: no messages at all in the configured chat. This is harmless
     and the warning stops once traffic arrives."""


class LivenessMonitor:
    """Warns when the bot has been up but has not heard anything.

    Deliberately warning-only: a quiet group is a perfectly normal state, and
    the bot must not refuse to run because nobody has posted in ten minutes.
    """

    def __init__(
        self,
        grace_seconds: float = DEFAULT_GRACE_SECONDS,
        check_interval: float = DEFAULT_CHECK_INTERVAL_SECONDS,
        repeat_seconds: float = DEFAULT_REPEAT_SECONDS,
        *,
        privacy_mode_verified: bool = False,
        proxy: str | None = None,
        bot_username: str | None = None,
    ) -> None:
        self._grace = grace_seconds
        self._interval = check_interval
        self._repeat = repeat_seconds
        self._started = time.monotonic()
        self._last_seen: float | None = None
        self._count = 0
        self._last_warning: float | None = None
        self._privacy_mode_verified = privacy_mode_verified
        self._proxy = proxy
        self._bot_username = bot_username

    # ------------------------------------------------------------------
    def record(self) -> None:
        """Note that an update arrived."""
        self._count += 1
        self._last_seen = time.monotonic()

    @property
    def update_count(self) -> int:
        """How many updates have been received since start."""
        return self._count

    @property
    def seconds_since_last_update(self) -> float:
        """Seconds since the last update, or since start if there was none."""
        return time.monotonic() - (self._last_seen or self._started)

    def should_warn(self, now: float | None = None) -> bool:
        """Whether a "cannot see the chat" warning is due."""
        moment = now if now is not None else time.monotonic()
        if self._count > 0:
            return False
        if moment - self._started < self._grace:
            return False
        if self._last_warning is None:
            return True
        return moment - self._last_warning >= self._repeat

    def checklist(self) -> str:
        """The warning text, assembled from the causes that still apply here."""
        causes: list[str] = []
        if not self._privacy_mode_verified:
            causes.append(_PRIVACY_MODE)
        if self._proxy is not None:
            causes.append(
                f"The proxy is down or stalling. Every update arrives through {self._proxy},\n"
                "     and a proxy that accepts the connection then goes quiet is "
                "indistinguishable\n     from this by reading logs. Check /status, and lower "
                "REQUEST_TIMEOUT\n     so a stalled connection is abandoned sooner."
            )
        causes.append(_NOT_A_MEMBER)
        causes.append(_QUIET_GROUP)

        lines = [
            f"no messages received in {self.seconds_since_last_update / 60:.0f} minutes"
            " - snitch is connected but cannot see the chat.",
            "In order of likelihood:",
            *(f"  {index}. {cause}" for index, cause in enumerate(causes, start=1)),
        ]
        if not self._privacy_mode_verified:
            # The advice stands even when the handle is unknown; only the @name
            # is conditional. Hardcoding a username here would send every other
            # operator to the wrong bot.
            target = f"@{self._bot_username} /id" if self._bot_username else "/id"
            lines.append(
                "To check the command path itself, message the bot DIRECTLY in private\n"
                f"     ({target}). Private chats ignore privacy mode, so if that works but\n"
                "     the group does not, privacy mode is the cause."
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    async def run(self) -> None:
        """Background loop; cancelled during shutdown."""
        try:
            while True:
                await asyncio.sleep(self._interval)
                if self.should_warn():
                    self._last_warning = time.monotonic()
                    logger.warning(self.checklist())
        except asyncio.CancelledError:
            logger.debug("liveness monitor cancelled")
            raise

    def __enter__(self) -> LivenessMonitor:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None
