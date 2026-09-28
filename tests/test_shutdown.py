"""Signal handling and startup/shutdown wiring.

``Dispatcher.stop_polling`` is a coroutine in current aiogram, but the signal
callback the event loop invokes is synchronous. These tests pin down that the
shutdown coroutine actually gets scheduled instead of being created and dropped -
the failure mode being a container that ignores ``docker stop`` and is SIGKILLed
mid-request.
"""

from __future__ import annotations

import asyncio
import signal
from typing import Any

import pytest
from pydantic import ValidationError

from snitch import __main__ as entrypoint
from snitch.bot import App
from snitch.config import Settings


class StubDispatcher:
    """Records stop_polling calls, as a coroutine like real aiogram."""

    def __init__(self) -> None:
        self.calls = 0

    async def stop_polling(self) -> None:
        self.calls += 1


class StubSession:
    async def close(self) -> None:
        return None


class StubBot:
    def __init__(self) -> None:
        self.session = StubSession()


def make_app(refresher: asyncio.Task[None] | None = None) -> App:
    """A real App wired to stub collaborators."""
    return App(
        bot=StubBot(),  # type: ignore[arg-type]
        dispatcher=StubDispatcher(),  # type: ignore[arg-type]
        settings=Settings(_env_file=None, bot_token="1:x", chat_id=-100),  # type: ignore[call-arg]
        directory=None,  # type: ignore[arg-type]
        refresher=refresher,
    )


@pytest.fixture
def captured_loop_handler(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, Any, tuple]]:
    """Capture what gets registered with the event loop's signal handler."""
    captured: list[tuple[Any, Any, tuple]] = []

    def fake_add_signal_handler(self: Any, sig: Any, callback: Any, *args: Any) -> None:  # noqa: ARG001
        captured.append((sig, callback, args))

    monkeypatch.setattr(asyncio.AbstractEventLoop, "add_signal_handler", fake_add_signal_handler)
    return captured


@pytest.fixture
def captured_signal_handler(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, Any]]:
    """Capture the Windows fallback path (``signal.signal``)."""
    captured: list[tuple[Any, Any]] = []

    def fake_signal(sig: Any, handler: Any) -> None:
        captured.append((sig, handler))

    monkeypatch.setattr(signal, "signal", fake_signal)
    return captured


@pytest.fixture
def no_loop_signal_support(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the loop reject signal handlers, as Windows does."""

    def raise_not_implemented(self: Any, sig: Any, callback: Any, *args: Any) -> None:
        raise NotImplementedError

    monkeypatch.setattr(asyncio.AbstractEventLoop, "add_signal_handler", raise_not_implemented)


# ===========================================================================
# the event loop path
# ===========================================================================
async def test_signal_handlers_are_registered(captured_loop_handler):
    entrypoint._install_signal_handlers(make_app())

    registered = {sig for sig, _, _ in captured_loop_handler}
    assert signal.SIGINT in registered
    assert signal.SIGTERM in registered


async def test_signal_callback_schedules_the_shutdown_coroutine(captured_loop_handler):
    """The regression: stop_polling() returns a coroutine that must be awaited."""
    app = make_app()
    entrypoint._install_signal_handlers(app)

    _, callback, args = next(e for e in captured_loop_handler if e[0] is signal.SIGTERM)
    callback(*args)  # simulate the event loop delivering the signal

    await asyncio.sleep(0)  # let the scheduled task run
    assert app.dispatcher.calls == 1  # type: ignore[attr-defined]


async def test_each_signal_stops_polling_once(captured_loop_handler):
    app = make_app()
    entrypoint._install_signal_handlers(app)

    for _sig, callback, args in captured_loop_handler:
        callback(*args)
    await asyncio.sleep(0)

    assert app.dispatcher.calls == len(captured_loop_handler)  # type: ignore[attr-defined]


# ===========================================================================
# the Windows fallback
# ===========================================================================
@pytest.mark.usefixtures("no_loop_signal_support")
async def test_falls_back_to_signal_module_when_unsupported(captured_signal_handler):
    entrypoint._install_signal_handlers(make_app())

    registered = {sig for sig, _ in captured_signal_handler}
    assert signal.SIGINT in registered
    assert signal.SIGTERM in registered


@pytest.mark.usefixtures("no_loop_signal_support")
async def test_fallback_handler_also_schedules_shutdown(captured_signal_handler):
    app = make_app()
    entrypoint._install_signal_handlers(app)

    _, handler = next(e for e in captured_signal_handler if e[0] is signal.SIGTERM)
    handler(signal.SIGTERM, None)  # the real signature is (signum, frame)
    await asyncio.sleep(0)

    assert app.dispatcher.calls == 1  # type: ignore[attr-defined]


# ===========================================================================
# app shutdown
# ===========================================================================
async def test_shutdown_cancels_the_refresher():
    async def forever() -> None:
        await asyncio.sleep(3600)

    task = asyncio.create_task(forever())
    await asyncio.sleep(0)
    app = make_app(refresher=task)

    await app.shutdown()

    assert task.cancelled() or task.done()


async def test_shutdown_is_safe_without_a_refresher():
    await make_app(refresher=None).shutdown()


async def test_shutdown_tolerates_an_already_finished_refresher():
    async def quick() -> None:
        return None

    task = asyncio.create_task(quick())
    await task

    await make_app(refresher=task).shutdown()


# ===========================================================================
# the settings error path
# ===========================================================================
def test_settings_errors_name_the_offending_variable():
    with pytest.raises(ValidationError) as excinfo:
        Settings(_env_file=None, bot_token="1:x", chat_id=-100, mute_hours=99999)  # type: ignore[call-arg]

    message = entrypoint._format_settings_error(excinfo.value)

    assert "mute_hours" in message
    assert ".env.example" in message
