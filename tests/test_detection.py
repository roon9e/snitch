"""The rule engine: who counts as talking to whom, and where the rule applies."""

from __future__ import annotations

import pytest

from snitch.detection import NO_DETECTION, TargetKind, detect, is_whitelisted
from tests.conftest import (
    ALICE_ID,
    BOB_ID,
    STRANGER_ID,
    make_directory,
    make_mention_entity_from_text,
    make_mention_text_mention,
    make_message,
    make_settings,
    make_user,
)


# ===========================================================================
# replies
# ===========================================================================
def test_reply_to_restricted_user_is_a_violation(alice, bob):
    message = make_message(alice, text="sure", reply_to_sender=bob)

    result = detect(message, make_settings(), make_directory())

    assert result
    assert result.user_ids == {BOB_ID}
    assert result.targets[0].kind is TargetKind.REPLY


def test_reply_to_stranger_is_not_a_violation(alice, stranger):
    message = make_message(alice, text="sure", reply_to_sender=stranger)

    assert detect(message, make_settings(), make_directory()) is NO_DETECTION


def test_reply_without_a_sender_is_not_a_violation(alice):
    """A reply to a deleted user's message has no author to attribute it to."""
    orphan = make_message(None, text="gone", message_id=99)
    message = make_message(alice, text="?", reply_to=orphan)

    assert not detect(message, make_settings(), make_directory())


def test_external_reply_across_topics_is_a_violation(alice, bob):
    """Replies that cross forum topics land in external_reply, not reply_to_message."""
    message = make_message(alice, text="answering across topics", external_reply_sender=bob)

    result = detect(message, make_settings(), make_directory())

    assert result.user_ids == {BOB_ID}
    assert result.targets[0].kind is TargetKind.EXTERNAL_REPLY


def test_external_reply_to_stranger_is_not_a_violation(alice, stranger):
    message = make_message(alice, text="hi", external_reply_sender=stranger)

    assert not detect(message, make_settings(), make_directory())


# ===========================================================================
# mentions
# ===========================================================================
def test_mention_entity_is_a_violation(alice):
    # "hey @alice" -> the mention entity starts at offset 4 and is 6 chars long
    message = make_message(
        alice,
        text="hey @alice",
        entities=[make_mention_entity_from_text("hey @alice", "@alice", ALICE_ID)],
    )

    result = detect(message, make_settings(), make_directory())

    assert result.user_ids == {ALICE_ID}
    assert result.targets[0].kind is TargetKind.MENTION


def test_text_mention_entity_is_a_violation(alice, bob):
    message = make_message(
        alice,
        text="hey Bob",
        entities=[make_mention_text_mention(bob, 4, 3)],
    )

    result = detect(message, make_settings(), make_directory())

    assert result.user_ids == {BOB_ID}
    assert result.targets[0].kind is TargetKind.TEXT_MENTION


def test_mention_of_a_stranger_is_not_a_violation(alice, stranger):
    message = make_message(
        alice,
        text=f"hey @{stranger.username}",
        entities=[
            make_mention_entity_from_text(
                f"hey @{stranger.username}", f"@{stranger.username}", STRANGER_ID
            )
        ],
    )

    assert not detect(message, make_settings(), make_directory())


def test_mention_in_a_caption_is_a_violation(alice):
    """Entities can be attached to a caption, not just to text."""
    message = make_message(
        alice,
        caption="for @alice",
        caption_entities=[make_mention_entity_from_text("for @alice", "@alice", ALICE_ID)],
    )

    assert detect(message, make_settings(), make_directory()).user_ids == {ALICE_ID}


def test_mention_detection_can_be_disabled(alice):
    message = make_message(
        alice,
        text="hey @alice",
        entities=[make_mention_entity_from_text("hey @alice", "@alice", ALICE_ID)],
    )
    settings = make_settings(detect_mentions=False, detect_bare_usernames=False)

    assert not detect(message, settings, make_directory())


# ===========================================================================
# bare usernames
# ===========================================================================
@pytest.mark.parametrize(
    "text",
    [
        "hey alice",
        "hey @alice",
        "ALICE are you there",
        "ask alice about it",
        "alice: no",
    ],
)
def test_bare_username_text_is_a_violation(text):
    message = make_message(make_user(ALICE_ID, "alice"), text=text)

    result = detect(message, make_settings(), make_directory())

    assert result.user_ids == {ALICE_ID}
    assert result.targets[0].kind is TargetKind.BARE_USERNAME


@pytest.mark.parametrize(
    "text",
    [
        "alicebob is a different handle",  # no word boundary
        "malice in wonderland",  # substring, not a word
        "how are you",
    ],
)
def test_unrelated_text_is_not_a_violation(text):
    message = make_message(make_user(ALICE_ID, "alice"), text=text)

    assert not detect(message, make_settings(), make_directory())


def test_bare_username_can_be_disabled():
    message = make_message(make_user(ALICE_ID, "alice"), text="hey alice")
    settings = make_settings(detect_bare_usernames=False)

    assert not detect(message, settings, make_directory())


def test_bare_username_needs_a_username():
    """A restricted user with no public username cannot be caught by text scan."""
    directory = make_directory(entries=((ALICE_ID, None),))
    message = make_message(make_user(ALICE_ID, "alice"), text="hey alice")

    assert not detect(message, make_settings(), directory)


# ===========================================================================
# dedup: one message, one target, one punishment
# ===========================================================================
def test_a_single_mention_is_reported_once(alice):
    """A real @mention is seen by both the entity detector and the text scan.

    They must collapse into one target, otherwise a user who mentions someone
    once would look like two separate offences.
    """
    text = "hey @alice"
    message = make_message(
        alice,
        text=text,
        entities=[make_mention_entity_from_text(text, "@alice", ALICE_ID)],
    )

    result = detect(message, make_settings(), make_directory())

    assert len(result.targets) == 1


def test_both_restricted_users_targeted_reports_both(alice):
    text = "@alice @bob"
    message = make_message(
        alice,
        text=text,
        entities=[
            make_mention_entity_from_text(text, "@alice", ALICE_ID),
            make_mention_entity_from_text(text, "@bob", BOB_ID),
        ],
    )

    assert detect(message, make_settings(), make_directory()).user_ids == {ALICE_ID, BOB_ID}


# ===========================================================================
# the whitelist
# ===========================================================================
def test_whitelisted_topic_bypasses_the_rule():
    message = make_message(
        make_user(ALICE_ID, "alice"),
        text="hey @bob",
        thread_id=42,
    )

    assert is_whitelisted(message, make_settings())


def test_non_whitelisted_topic_does_not_bypass():
    message = make_message(
        make_user(ALICE_ID, "alice"),
        text="hey @bob",
        thread_id=7,
    )

    assert not is_whitelisted(message, make_settings())


def test_general_topic_is_whitelisted_by_name_only_when_configured():
    """General-topic messages carry no message_thread_id at all."""
    in_general = make_message(make_user(ALICE_ID, "alice"), text="hey @bob")
    assert in_general.message_thread_id is None

    assert not is_whitelisted(in_general, make_settings())
    assert is_whitelisted(in_general, make_settings(whitelist_topic_ids=["42", "general"]))


def test_topic_zero_means_general():
    message = make_message(make_user(ALICE_ID, "alice"), text="hey @bob")

    assert is_whitelisted(message, make_settings(whitelist_topic_ids=["0"]))


def test_no_whitelist_configured_blocks_nothing():
    message = make_message(make_user(ALICE_ID, "alice"), text="hey @bob", thread_id=42)

    assert not is_whitelisted(message, make_settings(whitelist_topic_ids=[]))


# ===========================================================================
# global switches and degenerate inputs
# ===========================================================================
def test_all_detectors_disabled_means_no_violations(alice, bob):
    settings = make_settings(
        detect_replies=False,
        detect_mentions=False,
        detect_bare_usernames=False,
    )
    message = make_message(alice, text="hey @bob", reply_to_sender=bob)

    assert not detect(message, settings, make_directory())


def test_empty_directory_never_triggers():
    """Nothing resolves (e.g. all entries left the group) - the rule is inert."""
    message = make_message(
        make_user(ALICE_ID, "alice"),
        text="hey @bob",
        reply_to_sender=make_user(BOB_ID, "bob"),
    )

    assert not detect(message, make_settings(), make_directory(entries=()))


def test_message_with_no_text_at_all_is_not_a_violation(alice):
    assert not detect(make_message(alice), make_settings(), make_directory())


def test_detection_summary_is_readable(alice, bob):
    message = make_message(alice, text="hi", reply_to_sender=bob)

    summary = detect(message, make_settings(), make_directory()).summary()

    assert "reply" in summary
    assert str(BOB_ID) in summary
