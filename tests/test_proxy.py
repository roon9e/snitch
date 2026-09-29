"""Proxy configuration and its security properties.

The password in ``PROXY_URL`` is a secret that lives inside a string, which is
exactly the shape that leaks: into a log line, into ``/status``, into a
traceback. Most of these tests are about making sure it cannot.
"""

from __future__ import annotations

import logging

import pytest
from aiogram.exceptions import TelegramNetworkError
from pydantic import ValidationError

from snitch import preflight
from snitch.config import PROXY_SCHEMES, ProxyConfig, Settings
from snitch.logging_conf import configure_logging
from snitch.preflight import PreflightError
from tests.conftest import SUPERGROUP_ID, make_settings
from tests.test_preflight import PreflightBot, api_error

SOCKS = "socks5://127.0.0.1:1080"
AUTHED = "socks5://alice:hunter2@proxy.example.com:1080"


def proxy_settings(url: str = SOCKS, **overrides: object) -> Settings:
    return make_settings(chat_id=SUPERGROUP_ID, proxy_url=url, **overrides)  # type: ignore[arg-type]


# ===========================================================================
# detection
# ===========================================================================
def test_no_proxy_by_default():
    settings = make_settings(chat_id=SUPERGROUP_ID)

    assert settings.proxy_url == ""
    assert settings.proxy.enabled is False
    assert settings.proxy.url == ""
    assert settings.proxy.redacted == "disabled"


def test_socks5_url_is_accepted():
    settings = proxy_settings()

    assert settings.proxy.enabled is True
    assert settings.proxy.url == SOCKS


@pytest.mark.parametrize("scheme", PROXY_SCHEMES)
def test_every_supported_scheme_is_accepted(scheme):
    settings = proxy_settings(f"{scheme}://127.0.0.1:1080")

    assert settings.proxy.enabled is True


def test_port_may_be_omitted():
    """aiohttp_socks defaults sensibly, and the error at connect time is clearer
    than guessing a port here would be."""
    assert proxy_settings("socks5://127.0.0.1").proxy.enabled is True


def test_socks5h_is_rejected_with_a_pointer_to_socks5():
    """aiohttp_socks raises 'Invalid scheme component' on socks5h - so catch it
    here, with the reason, instead of at connector construction."""
    with pytest.raises(ValidationError, match="socks5h"):
        proxy_settings("socks5h://127.0.0.1:1080")


def test_unknown_scheme_is_rejected():
    with pytest.raises(ValidationError, match="not supported"):
        proxy_settings("ftp://127.0.0.1:1080")


def test_missing_scheme_is_rejected():
    with pytest.raises(ValidationError, match="not supported"):
        proxy_settings("127.0.0.1:1080")


def test_missing_host_is_rejected():
    with pytest.raises(ValidationError, match="no host"):
        proxy_settings("socks5://")


def test_bad_port_is_rejected():
    with pytest.raises(ValidationError, match="port"):
        proxy_settings("socks5://127.0.0.1:notaport")


def test_username_without_password_is_rejected():
    with pytest.raises(ValidationError, match="username but no password"):
        proxy_settings("socks5://alice@127.0.0.1:1080")


def test_password_without_username_is_rejected():
    with pytest.raises(ValidationError, match="password but no username"):
        proxy_settings("socks5://:hunter2@127.0.0.1:1080")


def test_credentials_together_are_fine():
    assert proxy_settings(AUTHED).proxy.enabled is True


def test_surrounding_whitespace_is_tolerated():
    assert proxy_settings(f"  {SOCKS}  ").proxy.url == SOCKS


# ===========================================================================
# secrets must not leak
# ===========================================================================
def test_password_is_extracted_for_scrubbing():
    assert proxy_settings(AUTHED).proxy.password == "hunter2"


def test_percent_encoded_password_is_decoded_for_scrubbing():
    """A password with an '@' must be percent-encoded in the URL, and the
    scrubber has to see the *decoded* form, because that is what appears in
    connection errors."""
    settings = proxy_settings("socks5://alice:p%40ss%3Aword@1.2.3.4:1080")

    assert settings.proxy.password == "p@ss:word"


def test_no_password_yields_empty_string():
    assert proxy_settings(SOCKS).proxy.password == ""


def test_secrets_contains_token_and_password():
    settings = proxy_settings(AUTHED)

    assert "hunter2" in settings.secrets
    assert settings.token in settings.secrets


def test_secrets_omits_empties():
    """An empty secret would scrub every empty string in every log line."""
    settings = proxy_settings(SOCKS)

    assert "" not in settings.secrets


def test_redacted_hides_the_password():
    redacted = proxy_settings(AUTHED).proxy.redacted

    assert "hunter2" not in redacted
    assert "alice" in redacted
    assert "proxy.example.com" in redacted
    assert "1080" in redacted


def test_redacted_hides_a_passwordless_auth_slot():
    redacted = proxy_settings(SOCKS).proxy.redacted

    assert "127.0.0.1" in redacted
    assert "***" in redacted


def test_redacted_summary_never_contains_the_password():
    settings = proxy_settings(AUTHED)

    assert "hunter2" not in str(settings.redacted_summary())
    assert settings.redacted_summary()["proxy_url"] == settings.proxy.redacted


def test_repr_does_not_leak():
    assert "hunter2" not in repr(proxy_settings(AUTHED).proxy)


def test_proxy_password_is_scrubbed_from_logs(capsys):
    settings = proxy_settings(AUTHED, log_level="INFO")

    configure_logging(settings)
    try:
        logging.getLogger("snitch.probe").info("connecting to %s", AUTHED)
        captured = capsys.readouterr()
    finally:
        logging.getLogger().handlers.clear()

    assert "hunter2" not in captured.out
    assert "***redacted***" in captured.out


def test_proxy_password_is_scrubbed_from_tracebacks(capsys):
    settings = proxy_settings(AUTHED, log_level="INFO")

    configure_logging(settings)
    try:
        try:
            raise OSError(f"cannot reach {AUTHED}")
        except OSError:
            logging.getLogger("snitch.probe").exception("proxy failed")
        captured = capsys.readouterr()
    finally:
        logging.getLogger().handlers.clear()

    assert "hunter2" not in captured.out
    assert "***redacted***" in captured.out


def test_scrub_covers_the_percent_encoded_spelling(capsys):
    """A raw PROXY_URL logged anywhere shows the encoded password."""
    url = "socks5://alice:p%40ss@1.2.3.4:1080"
    settings = proxy_settings(url, log_level="INFO")

    configure_logging(settings)
    try:
        logging.getLogger("snitch.probe").info("url=%s", url)
        captured = capsys.readouterr()
    finally:
        logging.getLogger().handlers.clear()

    assert "p%40ss" not in captured.out
    assert "***redacted***" in captured.out


# ===========================================================================
# bot wiring
# ===========================================================================
def test_bot_without_a_proxy_uses_a_plain_session():
    from snitch.bot import create_bot

    bot = create_bot(proxy_settings(""))

    assert getattr(bot.session, "proxy", None) is None


def test_bot_with_a_proxy_installs_a_socks_connector():
    from aiohttp_socks import ProxyConnector, ProxyType

    from snitch.bot import create_bot

    bot = create_bot(proxy_settings(SOCKS))

    assert bot.session._connector_type is ProxyConnector
    init = bot.session._connector_init
    assert init["proxy_type"] is ProxyType.SOCKS5
    assert init["host"] == "127.0.0.1"
    assert init["port"] == 1080


def test_proxy_connector_resolves_dns_remotely():
    """rdns=True means api.telegram.org is never looked up by the local resolver.

    This is the whole point of routing through a proxy on a restricted network:
    a DNS hijack would otherwise break the connection before the proxy is used.
    """
    from snitch.bot import create_bot

    bot = create_bot(proxy_settings(SOCKS))

    assert bot.session._connector_init["rdns"] is True


def test_proxy_credentials_reach_the_connector():
    from snitch.bot import create_bot

    bot = create_bot(proxy_settings(AUTHED))

    init = bot.session._connector_init
    assert init["username"] == "alice"
    assert init["password"] == "hunter2"


# ===========================================================================
# preflight behaviour with a proxy
# ===========================================================================
def test_network_error_is_treated_as_transient():
    """A dead proxy must not be mistaken for a permanent config error."""
    assert preflight.is_transient(TelegramNetworkError(method=None, message="Cannot connect"))


async def test_unreachable_proxy_does_not_claim_the_token_is_invalid():
    bot = PreflightBot(
        get_me_error=TelegramNetworkError(method=None, message="Cannot connect to host")
    )

    with pytest.raises(PreflightError) as excinfo:
        await preflight.check_token(bot, proxy_settings())  # type: ignore[arg-type]

    message = str(excinfo.value)
    assert "cannot reach the Telegram API" in message
    assert "BOT_TOKEN looks invalid" not in message
    assert excinfo.value.permanent is False


async def test_unreachable_proxy_hint_names_the_proxy_but_not_its_password():
    bot = PreflightBot(
        get_me_error=TelegramNetworkError(method=None, message="Cannot connect to host")
    )

    with pytest.raises(PreflightError) as excinfo:
        await preflight.check_token(bot, proxy_settings(AUTHED))  # type: ignore[arg-type]

    message = str(excinfo.value)
    assert "proxy.example.com" in message
    assert "hunter2" not in message
    assert "host.docker.internal" in message


async def test_no_proxy_network_error_suggests_setting_one():
    bot = PreflightBot(
        get_me_error=TelegramNetworkError(method=None, message="Cannot connect to host")
    )

    with pytest.raises(PreflightError) as excinfo:
        await preflight.check_token(bot, proxy_settings(""))  # type: ignore[arg-type]

    assert "PROXY_URL" in str(excinfo.value)


async def test_rejected_credentials_are_permanent_not_transient():
    """A 407-style auth failure will not fix itself."""
    bot = PreflightBot(get_me_error=api_error("Bad Request: Unauthorized"))

    with pytest.raises(PreflightError) as excinfo:
        await preflight.check_token(bot, proxy_settings(AUTHED))  # type: ignore[arg-type]

    assert excinfo.value.permanent is True
    assert "BOT_TOKEN looks invalid" in str(excinfo.value)


def test_proxy_config_is_truthy_only_when_set():
    assert bool(ProxyConfig(SOCKS)) is True
    assert bool(ProxyConfig("")) is False


def test_settings_repr_hides_the_proxy_url():
    """A pydantic repr lists raw field values, and a Settings can end up in a
    traceback. The password must not be in it."""
    assert "hunter2" not in repr(proxy_settings(AUTHED))


def test_settings_str_hides_the_proxy_url():
    assert "hunter2" not in str(proxy_settings(AUTHED))


def test_settings_repr_still_shows_the_token_as_masked():
    """bot_token is a SecretStr, so it renders masked even in a repr."""
    assert "TEST_TOKEN" not in repr(proxy_settings(AUTHED))
