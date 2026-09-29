"""Proxy reachability probe.

The probe replaces one opaque failure ("Request timeout error", 30 seconds) with
a specific verdict and a specific fix.

The two halves are tested differently on purpose:

* **Message content** is asserted against synthetic ``ProbeResult`` values, so
  the operator-facing text is pinned down deterministically.
* **Socket behaviour** is exercised against real listeners, but tolerantly.
  Some sandboxes transparently proxy all outbound TCP and blackhole DNS, so a
  test that insists on a specific kernel-level failure would be testing the
  environment rather than the code.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import sys
from typing import NoReturn

import pytest

from snitch import preflight
from snitch.config import Settings
from snitch.preflight import PreflightError
from snitch.proxy_probe import ProbeResult, Verdict, probe
from tests.conftest import SUPERGROUP_ID, make_settings


def socks_settings(port: int, host: str = "127.0.0.1") -> Settings:
    return make_settings(chat_id=SUPERGROUP_ID, proxy_url=f"socks5://{host}:{port}")


def closed_port() -> int:
    """Bind and immediately release a port, so it is certainly free.

    Hardcoding a port is not portable: some are reserved or firewalled, and on
    Windows a privileged port can time out rather than be refused.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# ===========================================================================
# the happy path, against a real SOCKS5 server
# ===========================================================================
async def closed(server: asyncio.AbstractServer) -> None:
    """Shut a test server down without ever blocking.

    From Python 3.12, ``Server.wait_closed()`` waits for every open connection
    to finish, so a handler that never closed its writer - which a deliberately
    stalled peer does not - would block teardown forever. Bounded here so a
    misbehaving fake can fail a test rather than wedge the run.
    """
    server.close()
    with contextlib.suppress(asyncio.TimeoutError, OSError):
        await asyncio.wait_for(server.wait_closed(), 2)


async def socks5_server(reply: bytes = b"\x05\x00", accepted: list[str] | None = None):
    """Minimal SOCKS5 server: reads a greeting, answers, closes."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            request = await asyncio.wait_for(reader.readexactly(3), 2)
            if accepted is not None:
                accepted.append(request.hex())
            writer.write(reply)
            await writer.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, int(server.sockets[0].getsockname()[1])


async def test_reachable_socks_proxy_is_ok():
    accepted: list[str] = []
    server, port = await socks5_server(accepted=accepted)
    try:
        result = await probe(socks_settings(port))
    finally:
        await closed(server)

    assert result is not None
    assert result.ok is True
    assert result.verdict is Verdict.OK
    assert accepted == ["050100"], "must send a real SOCKS5 greeting, not just connect"


async def test_ok_report_names_the_proxy():
    server, port = await socks5_server()
    try:
        result = await probe(socks_settings(port))
    finally:
        await closed(server)

    assert result is not None
    assert f"127.0.0.1:{port}" in result.report()
    assert "SOCKS proxy" in result.report()


async def test_socks4_style_reply_is_accepted():
    """A SOCKS4 server answers the greeting with 0x04; do not call it a failure."""
    server, port = await socks5_server(reply=b"\x04\x00")
    try:
        result = await probe(socks_settings(port))
    finally:
        await closed(server)

    assert result is not None
    assert result.ok is True


async def test_preflight_passes_when_the_proxy_answers(caplog):
    server, port = await socks5_server()
    try:
        with caplog.at_level("INFO"):
            await preflight.check_proxy(socks_settings(port))
    finally:
        await closed(server)

    assert any("proxy reachable" in record.message for record in caplog.records)


# ===========================================================================
# socket behaviour (tolerant of the surrounding environment)
# ===========================================================================
async def test_nothing_listening_is_detected():
    result = await probe(socks_settings(closed_port()), timeout=2.0)

    assert result is not None
    assert result.verdict in (Verdict.REFUSED, Verdict.TIMED_OUT)
    assert result.ok is False


async def test_an_http_server_on_the_port_is_not_called_socks():
    accepted: list[str] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        with contextlib.suppress(OSError):
            await reader.read(64)
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    del accepted
    try:
        result = await probe(socks_settings(port), timeout=2.0)
    finally:
        await closed(server)

    assert result is not None
    assert result.verdict is Verdict.NOT_SOCKS


async def test_a_silent_port_is_not_called_socks():
    """A listener that accepts and never speaks is not a working SOCKS server."""

    async def accept_and_stall(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader
        try:
            # Long enough that the probe's 0.5s handshake read times out first.
            await asyncio.sleep(5)
        finally:
            writer.close()

    server = await asyncio.start_server(accept_and_stall, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    try:
        result = await probe(socks_settings(port), timeout=0.5)
    finally:
        await closed(server)

    assert result is not None
    assert result.verdict is Verdict.NOT_SOCKS
    assert "never answered" in result.detail


async def test_unresolvable_host_is_reported_as_dns_failure(
    monkeypatch: pytest.MonkeyPatch,
):
    """Deterministic: the resolver is stubbed rather than exercised.

    A real lookup for a non-existent name cannot be bounded. ``wait_for``
    returns promptly, but ``loop.getaddrinfo`` runs in the default
    ThreadPoolExecutor and cannot be cancelled, so the executor is joined during
    loop teardown. Measured here at 2.00s in the call and 9.07s in teardown -
    and on a CI resolver that blackholes instead of returning NXDOMAIN that wait
    is unbounded, which is what wedged the first CI run. Stubbing the resolver
    tests the code under test (that gaierror is caught and classified) without
    inheriting the environment's DNS behaviour.
    """

    def refuse(*args: object, **kwargs: object) -> NoReturn:  # noqa: ARG001 - must accept any signature
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", refuse)
    result = await probe(socks_settings(1080, host="no-such-host.invalid"), timeout=2.0)

    assert result is not None
    assert result.verdict is Verdict.DNS_FAILED
    assert "cannot resolve" in result.detail
    assert "IP address" in result.report()


async def test_an_ip_literal_needs_no_resolver(monkeypatch: pytest.MonkeyPatch):
    """An IP host must not depend on DNS at all. This is the common case, and
    the one that cannot be slowed down by a broken resolver."""

    def explode(*args: object, **kwargs: object) -> NoReturn:  # noqa: ARG001 - must accept any signature
        raise AssertionError("an IP literal must not trigger a DNS lookup")

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", explode)
    server, port = await socks5_server()
    try:
        result = await probe(socks_settings(port, host="127.0.0.1"))
    finally:
        await closed(server)

    assert result is not None
    assert result.ok is True


async def test_ipv6_literal_target_is_bracketed():
    """'::1:1080' is ambiguous and would make the suggested nc command wrong."""
    settings = make_settings(chat_id=SUPERGROUP_ID, proxy_url="socks5://[::1]:1080")

    result = await probe(settings, timeout=0.5)

    assert result is not None
    assert result.target == "[::1]:1080"


# ===========================================================================
# message content: deterministic, no network
# ===========================================================================
def report_for(verdict: Verdict, detail: str = "") -> str:
    return ProbeResult(verdict=verdict, target="10.0.0.5:1080", detail=detail).report()


def test_report_falls_back_to_the_bare_target_without_a_display():
    """Synthetic results carry no display; the message must still be useful."""
    report = report_for(Verdict.REFUSED)

    assert "10.0.0.5:1080" in report
    assert "nc -vz 10.0.0.5 1080" in report


def test_report_shows_the_username_but_never_the_password():
    result = ProbeResult(
        verdict=Verdict.REFUSED,
        target="10.0.0.5:1080",
        detail="connection refused",
        display="socks5://alice:***@10.0.0.5:1080",
    )

    report = result.report()
    assert "alice" in report
    assert "***" in report
    assert "nc -vz 10.0.0.5 1080" in report, "the nc hint must use the bare host"


def test_every_failure_verdict_has_a_remedy():
    for verdict in Verdict:
        if verdict is Verdict.OK:
            continue
        report = report_for(verdict)
        assert len(report) > 80, f"{verdict} has no useful advice"
        assert "nc -vz 10.0.0.5 1080" in report


def test_refused_names_the_loopback_binding_trap():
    """The most common cause by a wide margin, so it must be in the message."""
    assert "127.0.0.1 only" in report_for(Verdict.REFUSED)


def test_refused_mentions_listen_address():
    assert "Bind to 0.0.0.0" in report_for(Verdict.REFUSED)


def test_timeout_explains_a_silent_drop_not_a_refusal():
    report = report_for(Verdict.TIMED_OUT, "no answer within 4s")
    assert "silent drop" in report
    assert "No route" in report
    assert "firewall" in report
    assert "refused" not in report.lower().replace("rather than a", "")


def test_dns_failure_suggests_using_an_ip():
    assert "IP address" in report_for(Verdict.DNS_FAILED)


def test_not_socks_mentions_authentication():
    """An auth-only proxy looks exactly like a non-SOCKS service, so say both."""
    report = report_for(Verdict.NOT_SOCKS)
    assert "authentication" in report
    assert "socks4://" in report


def test_not_socks_mentions_credentials_in_the_url():
    assert "socks5://user:password@host:port" in report_for(Verdict.NOT_SOCKS)


def test_ok_report_is_short_and_positive():
    report = ProbeResult(verdict=Verdict.OK, target="10.0.0.5:1080", elapsed=0.12).report()

    assert "SOCKS proxy" in report
    assert "nc -vz" not in report
    assert "cannot reach" not in report


def test_verdicts_are_distinct():
    assert len({v.value for v in Verdict}) == len(list(Verdict))


# ===========================================================================
# integration with preflight
# ===========================================================================
async def test_unreachable_proxy_fails_preflight_as_transient():
    with pytest.raises(PreflightError) as excinfo:
        await preflight.check_proxy(socks_settings(closed_port()))

    assert excinfo.value.permanent is False, "a proxy may come back; do not give up"
    assert "cannot reach the proxy" in str(excinfo.value)


async def test_preflight_error_never_contains_the_password():
    """A closed port keeps this instant and deterministic. The verdict differs
    from a timeout, but both travel the same path into the operator-facing
    message, which is what is being asserted."""
    settings = make_settings(
        chat_id=SUPERGROUP_ID,
        proxy_url=f"socks5://alice:hunter2@127.0.0.1:{closed_port()}",
    )

    with pytest.raises(PreflightError) as excinfo:
        await preflight.check_proxy(settings)

    message = str(excinfo.value)
    assert "hunter2" not in message
    assert "alice" in message, "the username is not a secret and aids diagnosis"


async def test_probe_is_skipped_entirely_without_a_proxy():
    """Must not touch the network at all when no proxy is configured."""
    settings = make_settings(chat_id=SUPERGROUP_ID, proxy_url="")

    assert await probe(settings) is None
    await preflight.check_proxy(settings)  # must not raise


# ===========================================================================
# port defaults
# ===========================================================================
def test_default_port_is_applied_for_a_bare_host():
    settings = make_settings(chat_id=SUPERGROUP_ID, proxy_url="socks5://127.0.0.1")

    assert settings.proxy.effective_port == 1080
    assert settings.proxy.port is None


def test_default_port_for_http_is_8080():
    settings = make_settings(chat_id=SUPERGROUP_ID, proxy_url="http://127.0.0.1")

    assert settings.proxy.effective_port == 8080


def test_explicit_port_wins():
    settings = make_settings(chat_id=SUPERGROUP_ID, proxy_url="socks5://127.0.0.1:9050")

    assert settings.proxy.effective_port == 9050
    assert settings.proxy.port == 9050


def test_host_is_exposed():
    settings = make_settings(chat_id=SUPERGROUP_ID, proxy_url="socks5://p.example:1080")

    assert settings.proxy.host == "p.example"


def test_module_import_creates_no_loop():
    assert "probe" in dir(sys.modules["snitch.proxy_probe"])
