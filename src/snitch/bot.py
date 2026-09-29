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
from datetime import datetime, timezone

from aiogram import BaseMiddleware, Bot, Dispatcher, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.dispatcher.event.bases import UNHANDLED
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
from snitch.wordlist import WordList

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
    started_at: datetime
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


class UpdateMiddleware(BaseMiddleware):
    """Guards the update stream, then records it for the liveness monitor.

    Two jobs, in this order:

    1. Drop updates that predate this process. Telegram replays a backlog
       through ``getUpdates`` after downtime, so a restarting bot would otherwise
       act on messages sent while it was down - deleting them, and starting a
       mute *now* for an offence from days ago. Actions belong to the moment
       they happen, not to whenever the bot next runs.
    2. Record the surviving update, so "no messages received" in the liveness
       warning means no messages were actually processed. A swallowed backlog
       must not look like a healthy group.

    The dump is guarded by an explicit level check: ``model_dump`` is a full
    pydantic serialisation, and evaluating the argument would run it for every
    message in the group even with logging at INFO.
    """

    def __init__(
        self,
        liveness: LivenessMonitor | None = None,
        started_at: datetime | None = None,
        process_backlog: bool = False,
    ) -> None:
        self._liveness = liveness
        self._started_at = started_at or datetime.now(tz=timezone.utc)
        # Compared at second granularity: Telegram's message dates are whole
        # seconds, so a message sent in the same second the bot started could
        # otherwise be dropped for arriving microseconds "early".
        self._floor = self._started_at.replace(microsecond=0)
        self._process_backlog = process_backlog
        self._skipped = 0

    def is_replay(self, message: Message) -> bool:
        """Whether ``message`` predates this process and must not be acted on."""
        if self._process_backlog:
            return False
        return message.date.replace(tzinfo=timezone.utc) < self._floor

    async def __call__(
        self,
        handler: object,
        event: TelegramObject,
        data: dict[str, object],
    ) -> object:
        message = _message_of(event)
        if message is not None and self.is_replay(message):
            self._skipped += 1
            # A backlog can be large after downtime; log the first few and then
            # stay quiet, so a big replay does not bury the reason it started.
            if self._skipped <= 5:
                logger.info(
                    "ignoring message %s from %s: it predates this process (started %s). "
                    "Telegram replays a backlog after downtime; acting on it now would "
                    "retroactively delete messages and start mutes for old offences.",
                    message.message_id,
                    message.date.isoformat(),
                    self._started_at.isoformat(timespec="seconds"),
                )
            elif self._skipped == 6:
                logger.info("further replayed updates will not be logged individually")
            return UNHANDLED

        if self._liveness is not None:
            self._liveness.record()
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("update: %s", event.model_dump(exclude_none=True))
        return await handler(event, data)  # type: ignore[operator]


def _message_of(event: TelegramObject) -> Message | None:
    """The message an update carries, if any."""
    if isinstance(event, Message):
        return event
    message = getattr(event, "message", None)
    return message if isinstance(message, Message) else None


def create_bot(settings: Settings) -> Bot:
    """Construct the Telegram client, routed through the proxy if configured.

    ``AiohttpSession(proxy=...)`` swaps aiohttp's ``TCPConnector`` for
    ``aiohttp_socks.ProxyConnector``, and hardcodes ``rdns=True`` - so hostnames
    are resolved *by the proxy*. That matters: a resolver that is itself blocked
    would otherwise fail the connection before the proxy is ever used.
    """
    session = (
        AiohttpSession(proxy=settings.proxy.url, timeout=settings.request_timeout)
        if settings.proxy.enabled
        else AiohttpSession(timeout=settings.request_timeout)
    )
    return Bot(
        token=settings.token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
        session=session,
    )


async def build_app(settings: Settings, started_at: datetime | None = None) -> App:
    """Create every component, verify the environment, and return the app.

    Checks run in dependency order so the first thing an operator sees is the
    real problem: token, then chat, then the restricted users. Resolving users
    before checking the chat produces a screen of "could not be resolved"
    warnings that are all just consequences of the bot not being in the group.

    ``started_at`` is the floor for the replay guard. It is passed in rather than
    read from the clock here so that it reflects the real process start and not
    the moment preflight finished, which can be tens of seconds later on a slow
    proxy.
    """
    started_at = started_at or datetime.now(tz=timezone.utc)
    bot = create_bot(settings)
    if settings.proxy.enabled:
        logger.info("routing Telegram traffic through %s", settings.proxy.redacted)
    try:
        preflight.check_local(settings)
        await preflight.check_proxy(settings)
        me = await preflight.check_token(bot, settings)
        chat = await preflight.check_chat(bot, settings)
        directory = DirectoryHolder(await resolve(bot, settings))
        await preflight.check_rights(bot, settings, me.id, chat)
        preflight.check_config(settings, directory.current)
        preflight.check_topic_hint(chat, settings)
    except BaseException:
        # Never leak the aiohttp session on a failed startup.
        await bot.session.close()
        raise

    # Privacy mode is invisible from the Bot API - there is no way to query it -
    # so say so loudly, where the operator will actually see it in the logs.
    # PRIVACY_MODE_VERIFIED is the operator telling us they have checked, so the
    # reminder stops rather than repeating forever about a solved problem.
    if settings.privacy_mode_verified:
        logger.info("privacy mode confirmed checked (PRIVACY_MODE_VERIFIED=true)")
    else:
        logger.info(
            "reminder: snitch cannot verify privacy mode. If nothing is ever deleted, "
            "check @BotFather -> /setprivacy -> %s -> Disable. Once you have checked it, "
            "set PRIVACY_MODE_VERIFIED=true so this stops being repeated.",
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
    wordlist = WordList(settings.wordlist_path)
    wordlist.reload()
    if wordlist.size:
        logger.info(
            "word blacklist: %d entries from %s (%d unusable lines ignored)",
            wordlist.size,
            wordlist.path,
            wordlist.skipped,
        )
    elif wordlist.path.exists():
        logger.warning(
            "word blacklist: %s exists but yielded no usable entries; the word rule is inactive",
            wordlist.path,
        )
    else:
        logger.info(
            "word blacklist: no list at %s, so the word rule is inactive "
            "(create the file and it is picked up without a restart)",
            wordlist.path,
        )

    watcher = Watcher(
        bot=bot,
        settings=settings,
        directory=directory,
        moderator=moderator,
        samples=samples,
        wordlist=wordlist,
    )

    liveness = LivenessMonitor(
        privacy_mode_verified=settings.privacy_mode_verified,
        # The checklist names the proxy when there is one, because a stalled
        # proxy looks exactly like a deaf bot from the logs alone. Redacted, so
        # the password never reaches the warning.
        proxy=settings.proxy.redacted if settings.proxy.enabled else None,
        bot_username=me.username,
    )
    if settings.process_backlog:
        logger.warning(
            "PROCESS_BACKLOG is true: messages sent before %s will be acted on. "
            "Delete and mute are retrospective - a mute for a three day old "
            "offence starts now.",
            started_at.isoformat(timespec="seconds"),
        )
    else:
        logger.info(
            "ignoring any message sent before %s (Telegram replays a backlog "
            "after downtime; set PROCESS_BACKLOG=true to override)",
            started_at.isoformat(timespec="seconds"),
        )

    dispatcher = Dispatcher()
    dispatcher.update.outer_middleware(
        UpdateMiddleware(
            liveness=liveness,
            started_at=started_at,
            process_backlog=settings.process_backlog,
        )
    )

    # Both are included as sub-routers, in priority order. A catch-all
    # registered directly with `dispatcher.message.register(...)` is checked
    # before any included router's filters and would therefore shadow the
    # command handlers completely - no command would ever run.
    dispatcher.include_router(
        build_command_router(bot, settings, directory, moderator, samples, audit, wordlist)
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
        started_at=started_at,
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
