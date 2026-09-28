"""Configuration parsing and the startup guards that depend on it."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from snitch.config import MAX_MUTE_HOURS, NoticeMode, Settings, normalize_username
from tests.conftest import CHAT_ID, make_settings


# ===========================================================================
# usernames
# ===========================================================================
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("@alice", "alice"),
        ("Alice", "alice"),
        ("https://t.me/alice", "alice"),
        ("http://t.me/alice", "alice"),
        ("t.me/alice", "alice"),
        ("tg://alice", "alice"),
        ("alice?start=1", "alice"),
        ("  @alice  ", "alice"),
    ],
)
def test_username_normalisation(raw, expected):
    assert normalize_username(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "a", "ab", "@", "has space", "way_too_long" * 5])
def test_invalid_usernames_rejected(raw):
    """Telegram usernames are 5-32 chars of [A-Za-z0-9_]; 'ab' is too short."""
    assert normalize_username(raw) is None


# ===========================================================================
# restricted users
# ===========================================================================
def test_restricted_users_accept_ids_and_usernames():
    settings = make_settings(restricted_users=[111, "@carol", 222])

    assert settings.restricted_users == [111, "@carol", 222]


def test_restricted_users_parse_from_csv_string():
    settings = Settings(
        _env_file=None,
        bot_token="1:x",
        chat_id=CHAT_ID,
        restricted_users="111, @carol ,222",
    )

    assert settings.restricted_users == [111, "@carol", 222]


def test_restricted_users_are_deduplicated():
    settings = make_settings(restricted_users=[111, 111, "@alice", "@ALICE"])

    assert settings.restricted_users == [111, "@alice"]


def test_restricted_users_reject_garbage():
    with pytest.raises(ValidationError, match="neither a numeric user id"):
        Settings(
            _env_file=None,
            bot_token="1:x",
            chat_id=CHAT_ID,
            restricted_users="111, not a user",
        )


def test_empty_restricted_users_default_to_empty_list():
    settings = Settings(_env_file=None, bot_token="1:x", chat_id=CHAT_ID)

    assert settings.restricted_users == []


# ===========================================================================
# whitelist topic ids
# ===========================================================================
def test_whitelist_topics_parse_from_csv():
    settings = make_settings(whitelist_topic_ids=["42, 7,general"])

    assert settings.whitelist_thread_ids == frozenset({42, 7})
    assert settings.whitelist_general is True


def test_whitelist_topic_zero_means_general():
    """'0' is a digit, but it is the documented alias for the General topic."""
    settings = make_settings(whitelist_topic_ids=["0"])

    assert settings.whitelist_thread_ids == frozenset()
    assert settings.whitelist_general is True


def test_whitelist_topics_are_deduplicated_and_normalised():
    settings = make_settings(whitelist_topic_ids=["042", "42", "GENERAL", "general"])

    assert settings.whitelist_thread_ids == frozenset({42})
    assert settings.whitelist_general is True


def test_whitelist_topic_rejects_a_non_numeric_value():
    with pytest.raises(ValidationError, match="not a topic id"):
        make_settings(whitelist_topic_ids=["my topic"])


def test_whitelist_topic_accepts_a_negative_number():
    """Negative ids are not real topics, but the parser must not silently drop one."""
    assert make_settings(whitelist_topic_ids=["-5"]).whitelist_thread_ids == frozenset({-5})


# ===========================================================================
# mute bounds
# ===========================================================================
def test_mute_hours_defaults_to_24():
    assert make_settings().mute_hours == 24


@pytest.mark.parametrize("hours", [1, 12, 24, 168, MAX_MUTE_HOURS])
def test_valid_mute_hours_accepted(hours):
    assert make_settings(mute_hours=hours).mute_hours == hours


@pytest.mark.parametrize("hours", [0, -1, MAX_MUTE_HOURS + 1, 100000])
def test_mute_hours_outside_the_safe_range_rejected(hours):
    """Beyond 366 days Telegram silently turns the restriction into a permanent ban."""
    with pytest.raises(ValidationError):
        make_settings(mute_hours=hours)


def test_mute_is_off_by_default():
    """The mute is chat-wide, so it must never be enabled implicitly."""
    assert make_settings().mute_enabled is False


# ===========================================================================
# misc validation
# ===========================================================================
def test_delete_is_on_by_default():
    assert make_settings().delete_message is True


def test_all_detectors_on_by_default():
    settings = make_settings()

    assert settings.detection_enabled is True
    assert settings.detect_replies is True
    assert settings.detect_mentions is True
    assert settings.detect_bare_usernames is True


def test_detection_enabled_reflects_the_switches():
    settings = make_settings(
        detect_replies=False, detect_mentions=False, detect_bare_usernames=False
    )

    assert settings.detection_enabled is False


@pytest.mark.parametrize("level", ["INFO", "info", "DEBUG", "WARNING"])
def test_log_level_case_insensitive(level):
    assert make_settings(log_level=level).log_level == level.upper()


def test_log_level_validated():
    with pytest.raises(ValidationError, match="LOG_LEVEL"):
        make_settings(log_level="CHATTY")


def test_admin_ids_parse_from_csv():
    assert make_settings(admin_ids=["1,2, 2"]).admin_ids == [1, 2]


def test_admin_ids_reject_garbage():
    with pytest.raises(ValidationError, match="not a numeric user id"):
        make_settings(admin_ids=["1, @alice"])


def test_notice_mode_enum():
    assert make_settings(notice_mode="dm").notice_mode is NoticeMode.DM


def test_notice_mode_rejects_garbage():
    with pytest.raises(ValidationError):
        make_settings(notice_mode="shout")


def test_missing_token_is_rejected():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, chat_id=CHAT_ID)


def test_empty_token_is_rejected():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, bot_token="   ", chat_id=CHAT_ID)


def test_cooldown_bounds():
    assert make_settings(mute_cooldown_seconds=0).mute_cooldown_seconds == 0.0
    with pytest.raises(ValidationError):
        make_settings(mute_cooldown_seconds=99999)


def test_redacted_summary_hides_the_token():
    """The startup banner must never be able to leak the token."""
    summary = make_settings().redacted_summary()

    assert summary["bot_token"] == "***redacted***"
    assert "TEST_TOKEN" not in str(summary)
