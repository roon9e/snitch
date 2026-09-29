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


class Verdict(str, Enum):
    """What talking to the proxy actually told us."""

    OK = "ok"
    REFUSED = "refused"
    TIMED_OUT = "timed_out"
    DNS_FAILED = "dns_failed"
    NOT_SOCKS = "not_socks"
    UNREACHABLE = "unreachable"


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
        """Whether the proxy accepted a connection and spoke SOCKS."""
        return self.verdict is Verdict.OK

    def report(self) -> str:
        """A full, readable explanation."""
        where = self.display or self.target
        if self.ok:
            return f"SOCKS proxy at {where} answered in {self.elapsed:.2f}s"

        remedy = _REMEDIES[self.verdict].format(timeout=DEFAULT_PROBE_TIMEOUT)
        host, _, port = self.target.rpartition(":")
        return "\n".join(
            [
                f"cannot reach the proxy at {where}: {self.detail or self.verdict.value}",
                "",
                remedy,
                "",
                "Check from the host, where Docker is not in the way:",
                f"  nc -vz {host} {port}",
            ]
        )


async def probe(settings: Settings, timeout: float = DEFAULT_PROBE_TIMEOUT) -> ProbeResult | None:
    """Connect to the proxy and confirm it speaks SOCKS.

    Returns ``None`` when no proxy is configured. Never raises: the caller
    decides how to report a failure.
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

    reply = b""
    try:
        writer.write(_SOCKS5_GREETING)
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(2), timeout)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()

    if reply and reply[0] not in (0x04, 0x05):
        return result(
            Verdict.NOT_SOCKS,
            f"answered with {reply!r}, not a SOCKS version byte",
        )
    if not reply:
        return result(
            Verdict.NOT_SOCKS,
            "accepted the connection but never answered a SOCKS5 greeting",
        )
    return result(Verdict.OK)
