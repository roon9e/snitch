"""Append-only JSONL audit log.

Telegram keeps the mute expiry on its side (``until_date``), so the bot needs no
database to run. What it does want is a durable record of who was caught, when,
and why - which is what this writes. One JSON object per line, flushed on every
write, so a hard kill loses at most the last line.
"""

from __future__ import annotations

import errno
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

FILENAME = "violations.jsonl"


def _current_uid() -> int | None:
    """The uid this process runs as, or None where the concept does not exist."""
    getter = getattr(os, "getuid", None)
    return getter() if getter is not None else None


def _current_gid() -> int | None:
    """The gid this process runs as, or None where the concept does not exist."""
    getter = getattr(os, "getgid", None)
    return getter() if getter is not None else None


def _owner_of(path: Path) -> int | None:
    """The uid that owns ``path``, or None if it cannot be determined."""
    try:
        return getattr(path.stat(), "st_uid", None)
    except OSError:
        return None


def _owner_sentence(path: Path) -> str:
    """Name both uids, which is the whole diagnosis in one line.

    "Permission denied" on its own is unactionable: an operator cannot tell
    whether they need to chown the file, the directory, or neither.
    """
    uid = _current_uid()
    owner = _owner_of(path)
    if uid is None or owner is None or owner == uid:
        return ""
    return f" The file is owned by uid {owner}, but the bot runs as uid {uid}."


def _remedy(data_dir: Path, exc: OSError) -> str:
    """The command that fixes this, or an explanation of why there is none.

    Only offered for the genuinely recoverable case: a bind mount owned by
    someone else on the host. Anything else would be a guess.
    """
    if getattr(exc, "errno", None) not in {errno.EACCES, errno.EPERM}:
        return ""
    uid, gid = _current_uid(), _current_gid()
    if uid is None or gid is None:
        return ""
    # The data dir itself, never its parent: chowning the parent recursively
    # would reach the virtualenv and the application itself. And the path
    # printed is the *container* path - on the host it is whatever was mapped
    # onto it, which is why the named volume is offered as the better answer.
    return (
        f" This is a permissions problem on the host. Either use the named Docker "
        f"volume in docker-compose.yml (no fix needed), or run on the host: "
        f"`chown -R {uid}:{gid} <host dir mapped to {data_dir}>`, then restart."
    )


def _hint(path: Path, exc: OSError) -> dict[str, object]:
    """Structured context for log shipping, so this is alertable and not just readable."""
    return {
        "event": "audit_unavailable",
        "path": str(path),
        "errno": getattr(exc, "errno", None),
        "uid": _current_uid(),
        "owner_uid": _owner_of(path),
    }


class AuditLog:
    """Writes violation records to ``DATA_DIR/violations.jsonl``."""

    def __init__(self, data_dir: Path) -> None:
        self._path = data_dir / FILENAME
        self._enabled = self._prepare(data_dir)

    @property
    def path(self) -> Path:
        """Location of the audit log file."""
        return self._path

    @property
    def enabled(self) -> bool:
        """Whether records are being written (false if the dir is unusable)."""
        return self._enabled

    def _prepare(self, data_dir: Path) -> bool:
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning(
                "audit log disabled: cannot create %s (%s)%s",
                data_dir,
                exc,
                _remedy(data_dir, exc),
                extra=_hint(data_dir, exc),
            )
            return False

        # Probe the exact operation record() performs, on the exact file it
        # writes to. Touching a fresh file in the directory is not equivalent:
        # the usual container failure is a perfectly writable directory that
        # already contains a violations.jsonl owned by a different uid, and
        # appending to *that* is denied even though the directory is fine.
        problem = self._append_failure()
        if problem is not None:
            logger.warning(
                "audit log disabled: cannot append to %s (%s)%s%s "
                "The audit log is off for the rest of this run; snitch still "
                "deletes and mutes, but the record of it is not being kept.",
                self._path,
                problem,
                _owner_sentence(self._path),
                _remedy(data_dir, problem),
                extra=_hint(self._path, problem),
            )
            return False
        return True

    def _append_failure(self) -> OSError | None:
        """Try the append that ``record`` will do. Returns the error, if any.

        Opening in append mode is the whole test: it succeeds when writing is
        allowed, and raises exactly the ``OSError`` the operator will otherwise
        only meet hours later, on the first violation.
        """
        try:
            with self._path.open("a", encoding="utf-8"):
                pass
        except OSError as exc:
            return exc
        return None

    def record(self, **fields: Any) -> None:
        """Append one violation record. Never raises."""
        if not self._enabled:
            return
        payload = {"ts": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"), **fields}
        line = json.dumps(payload, default=str, ensure_ascii=False)
        try:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(f"{line}\n")
        except OSError as exc:
            # Reached only if permissions change while running; the startup
            # probe already covers the case where they were wrong from the start.
            logger.warning(
                "could not append to audit log %s (%s)%s",
                self._path,
                exc,
                _remedy(self._path.parent, exc),
                extra=_hint(self._path, exc),
            )

    def tail(self, limit: int = 20) -> list[str]:
        """Last ``limit`` raw lines, newest last. Used by the /status command."""
        if not self._enabled or not self._path.exists():
            return []
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                return [line.strip() for line in handle.readlines() if line.strip()][-limit:]
        except OSError as exc:  # pragma: no cover - defensive
            logger.warning("could not read audit log %s (%s)", self._path, exc)
            return []
