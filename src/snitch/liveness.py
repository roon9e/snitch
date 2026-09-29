"""Self-diagnosis for the "the bot started but nothing happens" failure.

The most common reason snitch looks alive but never acts is that privacy mode is
still enabled in @BotFather. With privacy mode on, Telegram never delivers other
people's messages - and in a group it does not even deliver bare ``/commands``,
only ``/command@botusername``. So the operator cannot ask the bot what is wrong:
the diagnostic channel is exactly the thing that is broken.

This module closes that loop. The monitor records every incoming update and, if
the bot has been running for a while without seeing any, logs the checklist.
No command required.
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

_NO_UPDATES = """\
no messages received in %.0f minutes - snitch is connected but cannot see the chat.
In order of likelihood:
  1. Privacy mode is still ON. @BotFather -> /setprivacy -> pick this bot ->
     Disable. Without this, Telegram does not deliver other people's messages
     and (in a group) not even bare /commands, so this bot is effectively deaf.
  2. The bot is not a member of the group, or CHAT_ID points at a different one.
  3. The group is quiet: no messages at all in the configured chat. This is
     harmless and the warning stops once traffic arrives.
To check the command path itself, message the bot DIRECTLY in private
(@snitch_punish_bot /id). Private chats ignore privacy mode, so if that works
but the group does not, privacy mode is the cause."""


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
    ) -> None:
        self._grace = grace_seconds
        self._interval = check_interval
        self._repeat = repeat_seconds
        self._started = time.monotonic()
        self._last_seen: float | None = None
        self._count = 0
        self._last_warning: float | None = None

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

    # ------------------------------------------------------------------
    async def run(self) -> None:
        """Background loop; cancelled during shutdown."""
        try:
            while True:
                await asyncio.sleep(self._interval)
                if self.should_warn():
                    self._last_warning = time.monotonic()
                    logger.warning(_NO_UPDATES, self.seconds_since_last_update / 60)
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
