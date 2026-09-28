"""Bot assembly: dependency graph, middleware chain and shutdown behaviour.

Long polling is used deliberately: the container needs no inbound port, no TLS
certificate and no webhook secret token, which removes a whole class of
deployment failure from a bot that only ever talks to one group.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass

from aiogram import BaseMiddleware, Bot, Dispatcher, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import Message, TelegramObject, Update

from snitch import preflight
from snitch.config import Settings
from snitch.directory import DirectoryHolder, resolve
from snitch.handlers.commands import build_router as build_command_router
from snitch.handlers.watch import RecentSamples, Watcher
from snitch.services.audit import AuditLog
from snitch.services.moderator import Moderator
from snitch.services.notifier import Notifier

logger = logging.getLogger(__name__)

#: Only new messages are needed. Narrowing this keeps the update payload small.
ALLOWED_UPDATES = ["message"]


@dataclass(slots=True)
class App:
    """The wired-up application plus the task that keeps the directory fresh."""

    bot: Bot
    dispatcher: Dispatcher
    settings: Settings
    directory: DirectoryHolder
    refresher: asyncio.Task[None] | None = None

    async def shutdown(self) -> None:
        """Cancel background work and close the HTTP session."""
        if self.refresher is not None and not self.refresher.done():
            self.refresher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.refresher
        await self.bot.session.close()
        logger.info("shutdown complete")


class DebugMiddleware(BaseMiddleware):
    """One debug line per update. Cheap, and invaluable when tuning detection."""

    async def __call__(
        self,
        handler: object,
        event: TelegramObject,
        data: dict[str, object],
    ) -> object:
        logger.debug("update: %s", event.model_dump(exclude_none=True))
        return await handler(event, data)  # type: ignore[operator]


def create_bot(settings: Settings) -> Bot:
    """Construct the Telegram client."""
    return Bot(
        token=settings.token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )


async def build_app(settings: Settings) -> App:
    """Create every component, verify the environment, and return the app."""
    bot = create_bot(settings)
    try:
        # Validate the token before anything else, so a bad token produces one
        # clear line instead of a screen of failed user lookups.
        me = await preflight.check_token(bot)
        directory = DirectoryHolder(await resolve(bot, settings))
        await preflight.run(bot, settings, directory.current, me=me)
    except BaseException:
        # Never leak the aiohttp session on a failed startup.
        await bot.session.close()
        raise

    audit = AuditLog(settings.data_dir)
    if audit.enabled:
        logger.info("audit log -> %s", audit.path)
    else:
        logger.warning("audit log is disabled; violations will only reach the container log")

    moderator = Moderator(
        bot=bot,
        settings=settings,
        directory=directory,
        audit=audit,
        notifier=Notifier(bot, settings),
    )
    samples = RecentSamples()
    watcher = Watcher(
        bot=bot,
        settings=settings,
        directory=directory,
        moderator=moderator,
        samples=samples,
    )

    dispatcher = Dispatcher()
    dispatcher.update.outer_middleware(DebugMiddleware())

    # Both are included as sub-routers, in priority order. A catch-all
    # registered directly with `dispatcher.message.register(...)` is checked
    # before any included router's filters and would therefore shadow the
    # command handlers completely - no command would ever run.
    dispatcher.include_router(
        build_command_router(bot, settings, directory, moderator, samples, audit)
    )

    watch_router = Router(name="watcher")

    @watch_router.message()
    async def _watch(message: Message) -> None:
        await watcher.handle(message)

    dispatcher.include_router(watch_router)

    _register_error_handler(dispatcher)

    app = App(bot=bot, dispatcher=dispatcher, settings=settings, directory=directory)
    app.refresher = asyncio.create_task(
        _refresh_directory(bot, settings, directory),
        name="snitch-directory-refresh",
    )
    return app


async def _refresh_directory(
    bot: Bot,
    settings: Settings,
    directory: DirectoryHolder,
) -> None:
    """Periodically re-resolve RESTRICTED_USERS so username drift is noticed."""
    interval = settings.directory_refresh_hours * 3600
    logger.info("directory will be refreshed every %.1fh", interval)
    try:
        while True:
            await asyncio.sleep(interval)
            logger.info("refreshing restricted user directory")
            directory.replace(await resolve(bot, settings))
    except asyncio.CancelledError:
        logger.debug("directory refresher cancelled")
        raise


def _register_error_handler(dispatcher: Dispatcher) -> None:
    @dispatcher.error()
    async def _on_error(event: Update, exception: Exception) -> bool:
        logger.error(
            "unhandled error while processing update %s",
            event.update_id,
            exc_info=exception,
        )
        # Returning True acknowledges the update so a single bad message cannot
        # wedge the polling loop.
        return True
