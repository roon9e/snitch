"""Package entrypoint: configuration, logging, signal handling, shutdown."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import signal
import sys
from types import FrameType

from aiogram.exceptions import TelegramAPIError
from pydantic import ValidationError

from snitch.bot import ALLOWED_UPDATES, App, build_app, create_bot
from snitch.config import Settings
from snitch.logging_conf import configure_logging
from snitch.preflight import PreflightError

logger = logging.getLogger(__name__)

#: Telegram client construction is validated by the library, but a bad token is
#: clearer when we say so ourselves.
_VALID_TOKEN_SHAPE = ":"


def main() -> int:
    """Console entrypoint. Returns a process exit code."""
    try:
        # BOT_TOKEN and CHAT_ID come from the environment, so mypy cannot see
        # them being satisfied here.
        settings = Settings()  # type: ignore[call-arg]
    except ValidationError as exc:
        return _fail(_format_settings_error(exc))
    except OSError as exc:
        return _fail(f"could not read the configuration: {exc}")

    configure_logging(settings)

    if _VALID_TOKEN_SHAPE not in settings.token:
        return _fail(
            "BOT_TOKEN does not look like a Telegram token (expected '<id>:<secret>'). "
            "Get one from @BotFather via /token."
        )

    logger.info("starting snitch")
    logger.debug("effective configuration: %s", settings.redacted_summary())

    try:
        return asyncio.run(run(settings))
    except KeyboardInterrupt:  # pragma: no cover - interactive
        logger.info("interrupted")
        return 130


async def run(settings: Settings) -> int:
    """Build, poll, and shut down cleanly. Returns an exit code."""
    try:
        app = await _build_with_retry(settings)
    except PreflightError as exc:
        # A permanent failure is the operator's to fix, so exit immediately and
        # let the container stop rather than crash-looping on the same message.
        return _fail(str(exc))
    except TelegramAPIError as exc:
        return _fail(f"Telegram rejected the request: {exc}")

    _install_signal_handlers(app)
    logger.info("polling for updates (allowed: %s)", ", ".join(ALLOWED_UPDATES))
    try:
        await app.dispatcher.start_polling(
            app.bot,
            allowed_updates=ALLOWED_UPDATES,
            handle_signals=False,
        )
    except (TelegramAPIError, asyncio.CancelledError) as exc:
        logger.error("polling stopped: %s", exc)
        return 1
    finally:
        await app.shutdown()
    return 0


#: Startup attempts, and the delay before each retry. Only transient failures
#: (Telegram 5xx, rate limits, network errors) consume these.
STARTUP_ATTEMPTS = 5
STARTUP_BACKOFF_SECONDS = (5, 15, 30, 60)


async def _build_with_retry(settings: Settings) -> App:
    """Build the app, retrying only failures that could plausibly resolve."""
    last: PreflightError | None = None
    for attempt in range(1, STARTUP_ATTEMPTS + 1):
        try:
            return await build_app(settings)
        except PreflightError as exc:
            last = exc
            if exc.permanent or attempt == STARTUP_ATTEMPTS:
                raise
            delay = STARTUP_BACKOFF_SECONDS[min(attempt, len(STARTUP_BACKOFF_SECONDS)) - 1]
            logger.warning(
                "startup attempt %d/%d failed (%s); retrying in %ds",
                attempt,
                STARTUP_ATTEMPTS,
                exc,
                delay,
            )
            await asyncio.sleep(delay)
    # Unreachable in practice: the loop returns, or raises on the last attempt.
    raise last or PreflightError("startup failed")


def _install_signal_handlers(app: App) -> None:
    """Stop polling on SIGINT/SIGTERM so Docker stops the container gracefully.

    Called from inside the running loop, on the main thread, because
    ``signal.signal`` is only legal there.
    """
    loop = asyncio.get_running_loop()
    # Strong references to in-flight shutdown tasks; without one the event loop
    # may garbage collect a task that has not started yet.
    pending: set[asyncio.Task[None]] = set()

    def _stop(signal_name: str) -> None:
        logger.info("received %s, shutting down", signal_name)
        # The signal callback is synchronous but Dispatcher.stop_polling is a
        # coroutine (aiogram >= 3.30), so it has to be scheduled. Older releases
        # were synchronous, hence the awaitable check.
        outcome = app.dispatcher.stop_polling()
        if inspect.isawaitable(outcome):
            task = loop.create_task(outcome)
            pending.add(task)
            task.add_done_callback(pending.discard)

    def _fallback(signum: int, _frame: FrameType | None) -> None:
        # Only reached on platforms without loop signal handlers (Windows).
        _stop(signal.Signals(signum).name)

    for signame in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, signame, None)
        if sig is None:  # pragma: no cover - not present on every platform
            continue
        try:
            loop.add_signal_handler(sig, _stop, signame)
        except NotImplementedError:  # pragma: no cover - Windows
            with contextlib.suppress(ValueError, OSError, RuntimeError):
                signal.signal(sig, _fallback)
        except RuntimeError:  # pragma: no cover - not on the main thread
            logger.debug("could not install a %s handler on the event loop", signame)


def _fail(message: str) -> int:
    """Report a fatal startup problem on stderr and return an exit code."""
    sys.stderr.write(f"\nsnitch: {message}\n\n")
    sys.stderr.flush()
    return 1


def _format_settings_error(exc: ValidationError) -> str:
    """Turn a pydantic error into an actionable message."""
    lines = ["the configuration is invalid:"]
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "(root)"
        lines.append(f"  - {location}: {error['msg']}")
    lines.append("")
    lines.append("Start from .env.example and check the highlighted values.")
    return "\n".join(lines)


__all__ = ["App", "create_bot", "main", "run"]

if __name__ == "__main__":
    sys.exit(main())
