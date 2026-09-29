"""The word blacklist: a file-based rule with no on/off switch.

The rule is active exactly when the file exists, which is the property most
worth pinning: there is no setting to forget, and no way to have the config say
one thing and the file another.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from snitch.wordlist import REGEX_PREFIX, WordList, fold


def write_list(path: Path, body: str) -> WordList:
    path.write_text(body, encoding="utf-8")
    wordlist = WordList(path, min_reload_interval=0.0)
    wordlist.reload()
    return wordlist


#: Written as escapes on purpose. These tests exist precisely because two
#: characters *look* identical, so a literal in the source would make the test
#: unreadable and unreviewable - and a reviewer could not tell it had been
#: typed as the confusable one at all.
CYRILLIC_O = "\u043e"
FULLWIDTH_BAD = "\uff42\uff41\uff44"  # fullwidth b, a, d


# ===========================================================================
# whole words
# ===========================================================================


def test_a_word_is_matched(tmp_path):
    wordlist = write_list(tmp_path / "w.txt", "forbidden\n")

    assert [hit.entry for hit in wordlist.match("say forbidden things")] == ["forbidden"]


def test_matching_ignores_case(tmp_path):
    wordlist = write_list(tmp_path / "w.txt", "Forbidden\n")

    assert wordlist.match("FORBIDDEN")
    assert wordlist.match("forbidden")
    assert wordlist.match("FoRbIdDeN")


def test_a_substring_is_not_a_match(tmp_path):
    """The whole point of whole-word matching.

    Substring matching turns 'ass' into a minefield: 'class', 'assess', 'bass',
    'pass' all contain it. A filter that cries wolf gets switched off in a day.
    """
    wordlist = write_list(tmp_path / "w.txt", "ass\n")

    assert wordlist.match("class") == []
    assert wordlist.match("assess the situation") == []
    assert wordlist.match("bass guitar") == []
    assert wordlist.match("pass") == []


def test_punctuation_around_the_word_still_matches(tmp_path):
    """`\\b` would fail on a word followed by punctuation in some cases; the
    lookaround used here does not."""
    wordlist = write_list(tmp_path / "w.txt", "bad\n")

    for text in ("bad.", "(bad)", "bad!", "a bad,", "-bad-"):
        assert wordlist.match(text), text


def test_a_multi_word_phrase_matches_as_a_phrase(tmp_path):
    wordlist = write_list(tmp_path / "w.txt", "buy now\n")

    assert wordlist.match("please buy now thanks")
    assert wordlist.match("buy  now") == [], "internal spacing must not be fudged"
    assert wordlist.match("buy something now") == []


def test_the_entry_is_regex_escaped_not_interpreted(tmp_path):
    """A literal 'c++' must match 'c++', not the regex 'c++'."""
    wordlist = write_list(tmp_path / "w.txt", "c++\n")

    assert wordlist.match("i love c++")
    assert wordlist.match("i love ccc") == []


def test_every_match_is_reported_not_just_the_first(tmp_path):
    """Knowing a message used three banned words is worth more in the audit."""
    wordlist = write_list(tmp_path / "w.txt", "alpha\nbeta\ngamma\n")

    assert [hit.entry for hit in wordlist.match("alpha and beta")] == ["alpha", "beta"]


def test_the_reported_text_is_the_authors_own(tmp_path):
    """Matched text comes from the message, not the folded comparison form, so an
    operator reading the log sees what was actually written."""
    wordlist = write_list(tmp_path / "w.txt", "forbidden\n")

    hit = wordlist.match("you FORBIDDEN behaviour")[0]

    assert hit.matched == "FORBIDDEN", "the original casing must survive"


# ===========================================================================
# lookalikes
# ===========================================================================


def test_cyrillic_lookalikes_do_not_bypass_the_list(tmp_path):
    """Typing CYRILLIC SMALL LETTER O (U+043E) instead of Latin 'o' is the
    cheapest bypass in a Russian group, and it costs one keypress."""
    wordlist = write_list(tmp_path / "w.txt", "porn\n")

    assert wordlist.match(f"p{CYRILLIC_O}rn"), "Cyrillic o must not slip through"
    assert wordlist.match(f"p{CYRILLIC_O.upper()}RN"), "nor capitalised"


def test_folding_does_not_break_a_cyrillic_entry(tmp_path):
    """Folding applies to both sides, so a Cyrillic word in the list still
    matches Cyrillic text - folding is not a Latin-only filter."""
    wordlist = write_list(tmp_path / "w.txt", "привет\n")

    assert wordlist.match("привет")
    assert wordlist.match("скажи привет")


def test_fullwidth_forms_are_normalised(tmp_path):
    wordlist = write_list(tmp_path / "w.txt", "bad\n")

    assert wordlist.match(FULLWIDTH_BAD), "fullwidth must not bypass"


def test_fold_is_idempotent():
    once = fold(f"p{CYRILLIC_O}rn")

    assert fold(once) == once


# ===========================================================================
# regular expressions
# ===========================================================================


def test_a_regex_line_is_a_regex(tmp_path):
    wordlist = write_list(tmp_path / "w.txt", f"{REGEX_PREFIX}b[au]zz\\w*\n")

    assert wordlist.match("buzz off")
    assert wordlist.match("bazzinga")
    assert wordlist.match("bezzel") == []


def test_a_regex_line_is_case_insensitive(tmp_path):
    wordlist = write_list(tmp_path / "w.txt", f"{REGEX_PREFIX}spam+\n")

    assert wordlist.match("SPAMMM")


def test_a_regex_can_span_characters_a_word_cannot(tmp_path):
    """The reason `re:` exists: "viagra" spelled with a space inside it."""
    wordlist = write_list(tmp_path / "w.txt", f"{REGEX_PREFIX}v\\s*i\\s*agra\\w*\n")

    assert wordlist.match("v iagra")
    assert wordlist.match("viagra")
    assert wordlist.match("v  i  agra")


def test_a_broken_regex_is_skipped_not_fatal(tmp_path, caplog):
    """One typo must not take the whole filter down - that would turn a small
    mistake into a silent total loss of enforcement."""
    with caplog.at_level(logging.WARNING):
        wordlist = write_list(tmp_path / "w.txt", "good\nre:[unclosed\nalso_good\n")

    assert [hit.entry for hit in wordlist.match("good")] == ["good"]
    assert [hit.entry for hit in wordlist.match("also_good")] == ["also_good"]
    assert wordlist.skipped == 1
    assert any("bad regex" in r.message for r in caplog.records)


def test_an_empty_regex_is_skipped(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        wordlist = write_list(tmp_path / "w.txt", "re:\n")

    assert wordlist.size == 0
    assert wordlist.skipped == 1


def test_comments_and_blanks_are_ignored(tmp_path):
    wordlist = write_list(
        tmp_path / "w.txt",
        "# a comment\n\n   \nreal\n   # indented comment\n",
    )

    assert wordlist.size == 1
    assert wordlist.entries() == ("real",)


def test_whitespace_around_an_entry_is_trimmed(tmp_path):
    wordlist = write_list(tmp_path / "w.txt", "   spaced   \n")

    assert wordlist.entries() == ("spaced",)
    assert wordlist.match("a spaced thing")


# ===========================================================================
# reloading
# ===========================================================================


def test_a_missing_file_is_not_an_error(tmp_path):
    """The normal state before you write one."""
    wordlist = WordList(tmp_path / "absent.txt", min_reload_interval=0.0)

    wordlist.reload()

    assert wordlist.size == 0
    assert wordlist.error is None
    assert wordlist.match("anything") == []


def test_reload_reports_whether_the_entry_set_changed(tmp_path):
    """The return value drives the "reloaded" log line, so it must mean
    "something actually changed" and not merely "a read happened"."""
    path = tmp_path / "w.txt"
    wordlist = WordList(path, min_reload_interval=0.0)

    assert wordlist.reload() is False, "missing -> missing: nothing changed"

    write_list(path, "word\n")
    assert wordlist.reload() is True, "missing -> one entry"

    assert wordlist.reload() is False, "unchanged file: nothing changed"

    path.unlink()
    assert wordlist.reload() is True, "one entry -> missing is a real change"


def test_a_new_file_is_picked_up_without_a_restart(tmp_path):
    """The reason this is a file and not an env var."""
    path = tmp_path / "w.txt"
    wordlist = WordList(path, min_reload_interval=0.0)
    wordlist.reload()
    assert wordlist.match("later") == []

    write_list(path, "later\n")

    assert wordlist.refresh() is True
    assert wordlist.size == 1
    assert wordlist.match("later")


def test_editing_the_file_reloads_it(tmp_path):
    path = tmp_path / "w.txt"
    wordlist = write_list(path, "first\n")
    assert wordlist.match("second") == []

    write_list(path, "second\n")
    wordlist.refresh()

    assert wordlist.match("second")
    assert wordlist.match("first") == []


def test_deleting_the_file_deactivates_the_rule_loudly(tmp_path, caplog):
    """Going inactive is the dangerous direction, so it is announced."""
    path = tmp_path / "w.txt"
    wordlist = write_list(path, "word\n")

    path.unlink()
    with caplog.at_level(logging.INFO):
        assert wordlist.reload() is True

    assert wordlist.size == 0
    assert any("no longer exists" in r.message for r in caplog.records)


def test_refresh_is_rate_limited(tmp_path):
    """Called per message: a busy group must not stat() on every one."""
    path = tmp_path / "w.txt"
    wordlist = WordList(path, min_reload_interval=60.0)
    wordlist.reload()
    assert wordlist.match("changed") == []

    write_list(path, "changed\n")
    wordlist._last_check = 0.0  # exercising the throttle directly

    assert wordlist.refresh(now=1.0) is False, "inside the interval: no reload"
    assert wordlist.match("changed") == []
    assert wordlist.refresh(now=99.0) is True, "past the interval: reloaded"
    assert wordlist.match("changed")


def test_the_throttle_does_not_delay_the_very_first_check(tmp_path):
    """A file written a moment after startup must still be picked up promptly;
    a throttle that starts armed would swallow the first edit."""
    path = tmp_path / "w.txt"
    write_list(path, "seed\n")
    wordlist = WordList(path, min_reload_interval=60.0)
    wordlist.reload()

    write_list(path, "seed\nfresh\n")
    wordlist._last_check = 0.0

    assert wordlist.refresh(now=0.0 + 61.0) is True
    assert wordlist.match("fresh")


def test_refresh_on_an_unchanged_file_does_nothing(tmp_path):
    wordlist = write_list(tmp_path / "w.txt", "word\n")

    assert wordlist.refresh(now=1000.0) is False


def test_unreadable_file_reports_but_keeps_the_previous_list(tmp_path, monkeypatch):
    """Losing your filter because of a transient IO error would be worse than
    the error itself."""
    wordlist = write_list(tmp_path / "w.txt", "word\n")

    def boom(_self: Path, *_args: object, **_kwargs: object) -> str:
        raise OSError("device went away")

    monkeypatch.setattr(Path, "read_text", boom)
    assert wordlist.reload() is False

    assert wordlist.size == 1, "the working list survives"
    assert wordlist.error is not None
    assert wordlist.match("word")


# ===========================================================================
# state for /blacklist
# ===========================================================================


def test_state_is_reportable(tmp_path):
    wordlist = write_list(tmp_path / "w.txt", "one\ntwo\n")

    assert wordlist.path == tmp_path / "w.txt"
    assert wordlist.size == 2
    assert wordlist.entries() == ("one", "two")
    assert wordlist.loaded_at is not None


def test_a_freshly_constructed_list_reports_nothing_loaded(tmp_path):
    wordlist = WordList(tmp_path / "w.txt")

    assert wordlist.size == 0
    assert wordlist.entries() == ()
    assert wordlist.loaded_at is None


@pytest.mark.parametrize("body", ["", "\n\n", "# only a comment\n"])
def test_a_file_with_nothing_usable_yields_no_entries(tmp_path, body):
    wordlist = write_list(tmp_path / "w.txt", body)

    assert wordlist.size == 0
