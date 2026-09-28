"""Append-only JSONL audit log.

Telegram keeps the mute expiry on its side (``until_date``), so the bot needs no
database to run. What it does want is a durable record of who was caught, when,
and why - which is what this writes. One JSON object per line, flushed on every
write, so a hard kill loses at most the last line.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

FILENAME = "violations.jsonl"


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
            logger.warning("audit log disabled: cannot create %s (%s)", data_dir, exc)
            return False
        return True

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
            logger.warning("could not append to audit log %s (%s)", self._path, exc)

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
