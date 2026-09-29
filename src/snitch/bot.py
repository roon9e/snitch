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
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.enums import ParseMode
from aiogram.types import Message, TelegramObject, Update

from snitch import preflight
from snitch.config import Settings
from snitch.directory import DirectoryHolder, resolve
from snitch.handlers.commands import build_router as build_command_router
from snitch.handlers.watch import RecentSamples, Watcher
from snitch.liveness import LivenessMonitor
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
    liveness: LivenessMonitor
    refresher: asyncio.Task[None] | None = None
    watcher_task: asyncio.Task[None] | None = None

    async def shutdown(self) -> None:
        """Cancel background work and close the HTTP session."""
        for task in (self.refresher, self.watcher_task):
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        await self.bot.session.close()
        logger.info("shutdown complete")


class DebugMiddleware(BaseMiddleware):
    """Records every update for the liveness monitor, and optionally logs it.

    The dump is guarded by an explicit level check: ``model_dump`` is a full
    pydantic serialisation, and evaluating the argument would run it for every
    message in the group even with logging at INFO.
    """

    def __init__(self, liveness: LivenessMonitor | None = None) -> None:
        self._liveness = liveness

    async def __call__(
        self,
        handler: object,
        event: TelegramObject,
        data: dict[str, object],
    ) -> object:
        if self._liveness is not None:
            self._liveness.record()
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("update: %s", event.model_dump(exclude_none=True))
        return await handler(event, data)  # type: ignore[operator]


def create_bot(settings: Settings) -> Bot:
    """Construct the Telegram client, routed through the proxy if configured.

    ``AiohttpSession(proxy=...)`` swaps aiohttp's ``TCPConnector`` for
    ``aiohttp_socks.ProxyConnector``, and hardcodes ``rdns=True`` - so hostnames
    are resolved *by the proxy*. That matters: a resolver that is itself blocked
    would otherwise fail the connection before the proxy is ever used.
    """
    session = AiohttpSession(proxy=settings.proxy.url) if settings.proxy.enabled else None
    kwargs: dict[str, object] = {}
    if session is not None:
        kwargs["session"] = session
    return Bot(
        token=settings.token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
        **kwargs,  # type: ignore[arg-type]
    )


async def build_app(settings: Settings) -> App:
    """Create every component, verify the environment, and return the app.

    Checks run in dependency order so the first thing an operator sees is the
    real problem: token, then chat, then the restricted users. Resolving users
    before checking the chat produces a screen of "could not be resolved"
    warnings that are all just consequences of the bot not being in the group.
    """
    bot = create_bot(settings)
    if settings.proxy.enabled:
        logger.info("routing Telegram traffic through %s", settings.proxy.redacted)
    try:
        preflight.check_local(settings)
        me = await preflight.check_token(bot, settings)
        chat = await preflight.check_chat(bot, settings)
        directory = DirectoryHolder(await resolve(bot, settings))
        await preflight.check_rights(bot, settings, me.id)
        preflight.check_config(settings, directory.current)
        preflight.check_topic_hint(chat, settings)
    except BaseException:
        # Never leak the aiohttp session on a failed startup.
        await bot.session.close()
        raise

    # Privacy mode is invisible from the Bot API - there is no way to query it -
    # so say so loudly, where the operator will actually see it in the logs.
    logger.info(
        "reminder: snitch cannot verify privacy mode. If nothing is ever deleted, "
        "check @BotFather -> /setprivacy -> %s -> Disable.",
        me.username,
    )

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

    liveness = LivenessMonitor()
    dispatcher = Dispatcher()
    dispatcher.update.outer_middleware(DebugMiddleware(liveness))

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

    app = App(
        bot=bot,
        dispatcher=dispatcher,
        settings=settings,
        directory=directory,
        liveness=liveness,
    )
    app.refresher = asyncio.create_task(
        _refresh_directory(bot, settings, directory),
        name="snitch-directory-refresh",
    )
    app.watcher_task = asyncio.create_task(liveness.run(), name="snitch-liveness")
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
