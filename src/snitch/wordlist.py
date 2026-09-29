"""A word blacklist loaded from a file, rather than from ``.env``.

Two things make this different from the detector in :mod:`snitch.detection`:

* **It is a file, and it reloads.** A word list is the kind of thing an operator
  edits while watching a group. Requiring a restart to add one word makes the
  feature useless in practice, so the file is re-read when it changes.
* **It folds lookalikes.** A Latin blacklist is trivially bypassed in a Russian
  group by typing CYRILLIC SMALL LETTER A (U+0430) instead of Latin ``a``. Both
  the pattern and the message text are folded the same way before matching, so
  the bypass closes without the blacklist having to be written twice. This is a
  mitigation, not a guarantee - Unicode is a large space.

Matching rules, one per line:

* blank lines and ``#`` comments are ignored
* ``re:<pattern>`` is a regular expression, matched case-insensitively
* anything else is a whole word or phrase, matched case-insensitively, so
  ``class`` does not match ``ass`` and ``bass`` does not match ``ass``

Only whole words match by default. Substring matching turns any entry into a
minefield (``cat`` matches ``concatenate``), and a word filter that cries wolf
gets switched off within a day.
"""

from __future__ import annotations

import logging
import re
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

#: Lines beginning with this are regular expressions, not literal words.
REGEX_PREFIX = "re:"

#: Comments and blank lines.
_COMMENT = "#"

#: Cyrillic characters that render identically to a Latin letter. Folding them
#: to their Latin twin is what makes "porn" and the Cyrillic-o spelling the same
#: word as far as this filter is concerned.
#:
#: Written as escapes with the letter named in ASCII, deliberately. A literal
#: Cyrillic "o" here is indistinguishable from the Latin "o" to a reader and to
#: a linter, and the whole point of the table is that those two are *not* the
#: same character.
_HOMOGLYPHS = str.maketrans(
    {
        "\u0430": "a",  # CYRILLIC SMALL LETTER A
        "\u0432": "b",  # CYRILLIC SMALL LETTER VE
        "\u0435": "e",  # CYRILLIC SMALL LETTER IE
        "\u0451": "e",  # CYRILLIC SMALL LETTER YO
        "\u043a": "k",  # CYRILLIC SMALL LETTER KA
        "\u043c": "m",  # CYRILLIC SMALL LETTER EM
        "\u043d": "h",  # CYRILLIC SMALL LETTER EN
        "\u043e": "o",  # CYRILLIC SMALL LETTER O
        "\u0440": "p",  # CYRILLIC SMALL LETTER ER
        "\u0441": "c",  # CYRILLIC SMALL LETTER ES
        "\u0442": "t",  # CYRILLIC SMALL LETTER TE
        "\u0443": "y",  # CYRILLIC SMALL LETTER U
        "\u0445": "x",  # CYRILLIC SMALL LETTER HA
        "\u0456": "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
        "\u0455": "s",  # CYRILLIC SMALL LETTER DZE
        "\u0458": "j",  # CYRILLIC SMALL LETTER JE
    }
)

#: Never look at the file more often than this. A busy group must not turn a
#: keyword filter into a stat() per message.
DEFAULT_MIN_RELOAD_INTERVAL = 5.0

#: Cap on how much of the file is read, so a runaway file cannot exhaust memory.
MAX_BYTES = 1_000_000


@dataclass(frozen=True, slots=True)
class WordHit:
    """One matched entry: what was configured, and what actually appeared."""

    entry: str
    matched: str

    def describe(self) -> str:
        """Log-friendly label. The matched text comes from the original message,
        not the folded form, so an operator reads their own words back."""
        return f"{self.entry!r} (matched {self.matched!r})"


@dataclass(frozen=True, slots=True)
class _Entry:
    """One compiled blacklist line."""

    raw: str
    regex: re.Pattern[str] | None = None
    literal: re.Pattern[str] | None = None

    def find(self, folded: str, original: str) -> WordHit | None:
        """First match in ``folded``, reported against ``original``.

        Both are the same text, folded and unfolded; spans therefore line up
        and the reported substring is the author's own text.
        """
        if self.regex is not None:
            match = self.regex.search(folded) or self.regex.search(
                unicodedata.normalize("NFKC", original).casefold()
            )
            return WordHit(self.raw, _slice(original, match)) if match else None
        assert self.literal is not None
        match = self.literal.search(folded)
        return WordHit(self.raw, _slice(original, match)) if match else None


def _slice(original: str, match: re.Match[str] | None) -> str:
    if match is None:  # pragma: no cover - defensive
        return ""
    return original[match.start() : match.end()]


def fold(text: str) -> str:
    """Normalise text for comparison: NFKC, casefolded, lookalikes mapped.

    Applied to patterns and messages alike, so a Cyrillic word in the list
    still matches Cyrillic text - folding is not a Latin-only filter.
    """
    return unicodedata.normalize("NFKC", text).casefold().translate(_HOMOGLYPHS)


class WordList:
    """A reloadable set of banned words and patterns.

    Loading never raises. A missing file means "no words", a malformed line is
    skipped with a warning, and the previously loaded entries survive a failed
    reload - losing your filter because of one typo would be worse than the
    typo.
    """

    def __init__(
        self,
        path: Path,
        min_reload_interval: float = DEFAULT_MIN_RELOAD_INTERVAL,
    ) -> None:
        self._path = path
        self._interval = min_reload_interval
        self._entries: tuple[_Entry, ...] = ()
        self._stamp: tuple[int, int] | None = None
        self._last_check = 0.0
        self._error: str | None = None
        self._loaded_at: float | None = None
        self._skipped = 0

    # ------------------------------------------------------------------
    @property
    def path(self) -> Path:
        """Where the list is read from."""
        return self._path

    @property
    def size(self) -> int:
        """How many entries are active."""
        return len(self._entries)

    @property
    def error(self) -> str | None:
        """The last load problem, if any. Survives until the next good load."""
        return self._error

    @property
    def skipped(self) -> int:
        """Lines that were dropped because they would not compile."""
        return self._skipped

    @property
    def loaded_at(self) -> float | None:
        """Monotonic timestamp of the last successful load."""
        return self._loaded_at

    def entries(self) -> tuple[str, ...]:
        """The configured entries, for ``/blacklist``."""
        return tuple(entry.raw for entry in self._entries)

    # ------------------------------------------------------------------
    def reload(self) -> bool:
        """Re-read the file. Returns whether the active entries changed."""
        before = len(self._entries)
        try:
            raw = self._path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            # A missing file is the normal state before you write one, so it is
            # not an error - but dropping a list that used to exist is worth
            # saying out loud, because the rule just went inactive.
            if before:
                logger.info("word list %s no longer exists; the word rule is inactive", self._path)
            self._entries = ()
            self._error = None
            self._stamp = None
            self._loaded_at = time.monotonic()
            return before > 0
        except OSError as exc:
            message = f"cannot read {self._path}: {exc}"
            if message != self._error:
                logger.warning("word list unavailable: %s", message)
            self._error = message
            return False

        if len(raw.encode("utf-8", errors="replace")) > MAX_BYTES:  # pragma: no cover
            logger.warning(
                "word list %s is larger than %d bytes; refusing to load it",
                self._path,
                MAX_BYTES,
            )
            self._error = "file too large"
            return False

        entries, skipped = self._compile(raw)
        # Compared by configured text, not by compiled pattern: two compiles of
        # the same pattern are different objects, so comparing entries would
        # report a change on every single read.
        changed = tuple(entry.raw for entry in entries) != tuple(
            entry.raw for entry in self._entries
        )
        self._entries = entries
        self._skipped = skipped
        self._stamp = self._current_stamp()
        self._loaded_at = time.monotonic()
        if skipped:
            # Not an error: the rest of the file is live and working. But the
            # operator must know a third of their list is doing nothing.
            logger.warning(
                "word list %s: %d of %d lines skipped as unusable",
                self._path,
                skipped,
                skipped + len(entries),
            )
        self._error = None
        return changed

    def refresh(self, now: float | None = None) -> bool:
        """Reload if the file changed, rate limited.

        Called per message, so the rate limit is the point: the check is a
        ``stat``, but a busy group should not make it per message.
        """
        moment = now if now is not None else time.monotonic()
        if moment - self._last_check < self._interval:
            return False
        self._last_check = moment
        stamp = self._current_stamp()
        if stamp is None:
            # Missing file: only a periodic full load can notice it appearing.
            return self.reload()
        if stamp == self._stamp:
            return False
        before = len(self._entries)
        self.reload()
        if len(self._entries) != before:
            logger.info(
                "word list reloaded: %d entries active (%d unusable lines ignored)",
                len(self._entries),
                self._skipped,
            )
        return True

    # ------------------------------------------------------------------
    def match(self, text: str | None) -> list[WordHit]:
        """Every entry found in ``text``, in list order.

        Returns all of them, not just the first: knowing a message used three
        banned words is worth more in the audit trail than knowing one.
        """
        if not text or not self._entries:
            return []
        folded = fold(text)
        hits = []
        for entry in self._entries:
            hit = entry.find(folded, text)
            if hit is not None:
                hits.append(hit)
        return hits

    # ------------------------------------------------------------------
    def _current_stamp(self) -> tuple[int, int] | None:
        """(mtime, size), which together identify the file's content cheaply."""
        try:
            info = self._path.stat()
        except OSError:
            return None
        return (info.st_mtime_ns, info.st_size)

    @staticmethod
    def _compile(raw: str) -> tuple[tuple[_Entry, ...], int]:
        entries: list[_Entry] = []
        skipped = 0
        for number, line in enumerate(raw.splitlines(), start=1):
            text = line.strip()
            if not text or text.startswith(_COMMENT):
                continue
            if text.lower().startswith(REGEX_PREFIX):
                pattern = text[len(REGEX_PREFIX) :].strip()
                if not pattern:
                    logger.warning("word list line %d: empty regex", number)
                    skipped += 1
                    continue
                try:
                    entries.append(_Entry(raw=text, regex=re.compile(pattern, re.IGNORECASE)))
                except re.error as exc:
                    # Skipped, not fatal: one typo must not disable the filter.
                    logger.warning("word list line %d: bad regex %r (%s)", number, pattern, exc)
                    skipped += 1
                continue
            entries.append(
                _Entry(
                    raw=text,
                    literal=re.compile(rf"(?<!\w){re.escape(fold(text))}(?!\w)"),
                )
            )
        return tuple(entries), skipped
