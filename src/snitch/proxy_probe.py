"""Diagnosing an unreachable proxy.

``aiohttp_socks`` reports every failure mode the same way - a timeout - so a
single error string cannot tell you whether the proxy is down, the port is
wrong, DNS is broken, or a firewall is eating packets. Those need completely
different fixes, so a short probe runs before the first API call and turns a
vague 30-second timeout into a specific, actionable verdict.

It is also much faster. Waiting out aiohttp's 30s request timeout to learn
"nothing is listening on that port" is a poor trade when the answer is available
in three seconds.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from snitch.config import Settings

logger = logging.getLogger(__name__)

#: Long enough for a remote proxy on a slow link, short enough that a black
#: hole fails fast rather than stalling startup.
DEFAULT_PROBE_TIMEOUT = 4.0

#: Client greeting: SOCKS5, one method offered, "no authentication required".
#: A SOCKS server does not speak first, so this is the only way to confirm that
#: whatever is on the port is really a SOCKS server and not, say, an HTTP one.
_SOCKS5_GREETING = b"\x05\x01\x00"

#: SOCKS5 auth method numbers (RFC 1928).
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_USERPASS = 0x02

#: Where the Bot API lives. Used for the tunnel check, deliberately without the
#: token: the probe must never send a credential to a third party.
_TELEGRAM_HOST = "api.telegram.org"
_TELEGRAM_PORT = 443

#: SOCKS5 reply codes (RFC 1928 section 6).
_SOCKS_REPLY: dict[int, str] = {
    0x00: "succeeded",
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable - the proxy itself cannot reach the destination",
    0x05: "connection refused by the destination",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


class Verdict(str, Enum):
    """What talking to the proxy actually told us."""

    OK = "ok"
    REFUSED = "refused"
    TIMED_OUT = "timed_out"
    DNS_FAILED = "dns_failed"
    NOT_SOCKS = "not_socks"
    UNREACHABLE = "unreachable"
    #: The proxy is fine, but it declined "no authentication", so credentials
    #: are required. Reported separately because the proxy is demonstrably alive
    #: and the fix is entirely different from a dead one.
    AUTH_REQUIRED = "auth_required"
    #: The proxy accepted a CONNECT to the Telegram API and then went quiet. The
    #: usual cause is packet-level interference inside the tunnel.
    TUNNEL_STALLED = "tunnel_stalled"
    #: The proxy refused the CONNECT with a specific SOCKS reply code.
    TUNNEL_REFUSED = "tunnel_refused"


#: What the operator should do about each verdict: the fixes that actually come
#: up in practice, not generic advice.
_REMEDIES: dict[Verdict, str] = {
    Verdict.REFUSED: (
        "the host answered but nothing is listening on that port.\n"
        "  - Check the port number in PROXY_URL.\n"
        "  - Check the proxy is actually running.\n"
        "  - Common trap: many SOCKS daemons and proxy desktop apps bind to\n"
        "    127.0.0.1 only, so they refuse connections from any other machine.\n"
        "    Bind to 0.0.0.0 or to the LAN address and allow it in the host firewall."
    ),
    Verdict.TIMED_OUT: (
        "nothing answered within {timeout:.0f}s. This is a silent drop rather than a\n"
        "refusal, so the packets are being discarded somewhere along the way:\n"
        "  - No route to that host: check the container's network, and any VPN\n"
        "    the proxy sits behind.\n"
        "  - A firewall between the container and the proxy is dropping packets\n"
        "    instead of rejecting them.\n"
        "  - The host is powered off, asleep, or on a different network."
    ),
    Verdict.DNS_FAILED: (
        "the proxy hostname could not be resolved from inside the container.\n"
        "  - Use the proxy's IP address instead, or check the container's DNS."
    ),
    Verdict.NOT_SOCKS: (
        "the port is open but did not complete a SOCKS handshake, so either\n"
        "something other than a SOCKS server is on it, or the proxy closed the\n"
        "connection when it declined 'no authentication'.\n"
        "  - Check the port number: an HTTP proxy speaks HTTP, not SOCKS.\n"
        "  - If it needs credentials, put them in PROXY_URL:\n"
        "    socks5://user:password@host:port (the probe deliberately offers no\n"
        "    authentication, so an auth-only proxy looks like this).\n"
        "  - If it really is a SOCKS4 proxy, use socks4:// - SOCKS4 does not\n"
        "    answer a SOCKS5 greeting."
    ),
    Verdict.UNREACHABLE: "the network reported an error reaching the proxy.",
    Verdict.AUTH_REQUIRED: (
        "the proxy is alive and speaks SOCKS, but it requires authentication.\n"
        "  - Put the credentials in PROXY_URL: socks5://user:password@host:port\n"
        "  - The probe deliberately offers no authentication, so it cannot verify\n"
        "    them; the real client will authenticate with whatever is configured."
    ),
    Verdict.TUNNEL_REFUSED: (
        "the proxy is healthy but refused to tunnel to {target}: the proxy itself\n"
        "cannot reach the destination. This is about the proxy's own route, not its\n"
        "reachability - it answered instantly.\n"
        "  - The proxy reported: {reason}\n"
        "  - Check the proxy on its own machine, for example:\n"
        "        curl --socks5-hostname 127.0.0.1:1080 https://{host}/\n"
        "  - It may need a different upstream, or it may itself sit behind the same\n"
        "    block it is meant to circumvent."
    ),
    Verdict.TUNNEL_STALLED: (
        "the proxy accepted a CONNECT to {target} and then went silent, which is the\n"
        "signature of interference *inside* the tunnel rather than a broken proxy:\n"
        "  - The proxy answered instantly, so it is running and reachable.\n"
        "  - Traffic is very likely being dropped after the tunnel is established\n"
        "    (TLS-level interference is the usual cause).\n"
        "  - Try a different proxy, a different protocol, or a different port on the\n"
        "    same proxy - some ports are filtered more aggressively than others."
    ),
}


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """The verdict plus the raw detail, for the log and for the operator."""

    verdict: Verdict
    #: Bare ``host:port``, used to build the suggested ``nc`` command.
    target: str
    detail: str = ""
    elapsed: float = 0.0
    #: Redacted proxy form, e.g. ``socks5://alice:***@host:1080``. Shown to the
    #: operator because the username aids diagnosis and is not a secret, while
    #: the password never appears.
    display: str = ""

    @property
    def ok(self) -> bool:
        """Whether the proxy answered and a tunnel to the Bot API was opened."""
        return self.verdict is Verdict.OK

    def report(self) -> str:
        """A full, readable explanation."""
        where = self.display or self.target
        if self.ok:
            return f"SOCKS proxy at {where} answered in {self.elapsed:.2f}s"

        remedy = _REMEDIES[self.verdict].format(
            timeout=DEFAULT_PROBE_TIMEOUT,
            target=f"{_TELEGRAM_HOST}:{_TELEGRAM_PORT}",
            host=_TELEGRAM_HOST,
            reason=self.detail or self.verdict.value,
        )
        host, _, port = self.target.rpartition(":")
        return "\n".join(
            [
                f"cannot reach the Telegram API through {where}: "
                f"{self.detail or self.verdict.value}",
                "",
                remedy,
                "",
                "Check the proxy itself, from the host, where Docker is not in the way:",
                f"  nc -vz {host} {port}",
                f"  curl --socks5-hostname {host}:{port} https://{_TELEGRAM_HOST}/",
            ]
        )


async def probe(
    settings: Settings,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    check_tunnel: bool = True,
) -> ProbeResult | None:
    """Connect to the proxy, then tunnel through it to the Bot API.

    Two stages, because they fail for entirely different reasons and the fixes
    do not overlap:

    1. A SOCKS5 handshake. Answers "is the proxy running and reachable?".
    2. A SOCKS5 ``CONNECT`` to ``api.telegram.org:443``. Answers "can the proxy
       actually get to Telegram?", which is the question when the handshake
       succeeds but every API call times out - and it answers in a second
       instead of waiting out aiohttp's 30s request timeout five times.

    The bot token is never used: the probe speaks to the proxy, not to Telegram.

    Returns ``None`` when no proxy is configured. Never raises.
    """
    proxy = settings.proxy
    if not proxy.enabled:
        return None

    host = proxy.host
    port = proxy.effective_port
    # Bracket IPv6 literals: "::1:1080" is ambiguous and would make the
    # suggested nc command wrong.
    display_host = f"[{host}]" if ":" in host else host
    target = f"{display_host}:{port}"
    display = proxy.redacted
    loop = asyncio.get_running_loop()
    started = loop.time()

    def result(verdict: Verdict, detail: str = "") -> ProbeResult:
        return ProbeResult(
            verdict=verdict,
            target=target,
            detail=detail,
            elapsed=loop.time() - started,
            display=display,
        )

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return result(Verdict.TIMED_OUT, f"no answer within {timeout:.0f}s")
    except socket.gaierror as exc:
        return result(Verdict.DNS_FAILED, f"cannot resolve {host!r}: {exc.strerror or exc}")
    except ConnectionRefusedError:
        return result(Verdict.REFUSED, "connection refused (nothing listening)")
    except OSError as exc:
        return result(Verdict.UNREACHABLE, str(exc) or type(exc).__name__)

    try:
        return await _socks5_session(reader, writer, timeout, result, check_tunnel)
    finally:
        # Every teardown step is bounded. StreamWriter.wait_closed() waits for
        # the transport to finish closing, which against a stalled peer does not
        # return on its own - unbounded, it would hang startup here and block
        # event loop shutdown later.
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), timeout)


async def _socks5_session(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: float,
    result: Callable[[Verdict, str], ProbeResult],
    check_tunnel: bool,
) -> ProbeResult:
    """Greet, optionally CONNECT, and classify. ``result`` builds the outcome."""
    # --- stage 1: greeting ---------------------------------------------
    try:
        writer.write(_SOCKS5_GREETING)
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(2), timeout)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        return result(
            Verdict.NOT_SOCKS,
            "accepted the connection but never answered a SOCKS5 greeting",
        )
    except OSError as exc:
        return result(Verdict.UNREACHABLE, str(exc) or type(exc).__name__)

    if reply[0] not in (0x04, 0x05):
        return result(Verdict.NOT_SOCKS, f"answered with {reply!r}, not a SOCKS version byte")
    if reply[0] == 0x05 and reply[1] != SOCKS5_AUTH_NONE:
        # We offered only "no authentication" and it declined. The proxy is
        # demonstrably alive, so this is a credentials problem, not a dead one.
        method = "username/password" if reply[1] == SOCKS5_AUTH_USERPASS else f"0x{reply[1]:02x}"
        return result(
            Verdict.AUTH_REQUIRED,
            f"the proxy requires authentication (method {method})",
        )
    if not check_tunnel:
        return result(Verdict.OK, "")

    # --- stage 2: CONNECT to the Bot API --------------------------------
    return await _socks5_connect(reader, writer, timeout, result)


async def _socks5_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: float,
    result: Callable[[Verdict, str], ProbeResult],
) -> ProbeResult:
    """Ask the proxy to CONNECT to the Bot API, and classify the reply."""
    destination = _TELEGRAM_HOST.encode()
    request = (
        b"\x05\x01\x00"  # VER=5, CMD=CONNECT, RSV=0
        b"\x03"  # ATYP=domain name
        + bytes([len(destination)])
        + destination
        + _TELEGRAM_PORT.to_bytes(2, "big")
    )
    try:
        writer.write(request)
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(4), timeout)
    except asyncio.TimeoutError:
        # The proxy took the CONNECT and then said nothing: the signature of
        # traffic being dropped once the tunnel is established.
        return result(
            Verdict.TUNNEL_STALLED,
            f"no reply to CONNECT {_TELEGRAM_HOST}:{_TELEGRAM_PORT} within {timeout:.0f}s",
        )
    except (asyncio.IncompleteReadError, OSError) as exc:
        return result(
            Verdict.TUNNEL_STALLED,
            f"the connection dropped during CONNECT: {exc or type(exc).__name__}",
        )

    if header[0] != 0x05:
        return result(Verdict.TUNNEL_REFUSED, f"malformed CONNECT reply {header!r}")

    code = header[1]
    if code != 0x00:
        reason = _SOCKS_REPLY.get(code, f"unknown reply code 0x{code:02x}")
        return result(
            Verdict.TUNNEL_REFUSED,
            f"SOCKS reply 0x{code:02x} ({reason}) for {_TELEGRAM_HOST}:{_TELEGRAM_PORT}",
        )

    # Reply is success. Drain the bound address so the stream is in a sane
    # state; a partial read here is not a failure.
    try:
        atyp = header[3]
        if atyp == 0x01:
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout)
        elif atyp == 0x03:
            length = (await asyncio.wait_for(reader.readexactly(1), timeout))[0]
            await asyncio.wait_for(reader.readexactly(length + 2), timeout)
        else:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError):
        pass

    return result(Verdict.OK, "")
