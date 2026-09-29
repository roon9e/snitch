"""Audit log writability: failing at startup, loudly, instead of silently later.

The bug this suite exists for: snitch logged

    could not append to audit log /app/data/violations.jsonl ([Errno 13] ...)

and that was the *first* anyone heard of it - on the first real violation, hours
into a run, as a single unactionable line. ``Permission denied`` does not tell an
operator whether to chown the file, the directory, or neither.

The nastier part is that the two are not equivalent. A bind mount commonly gives
you a perfectly writable directory that already contains a ``violations.jsonl``
owned by a different uid. Any "can I write here?" probe that creates its own
scratch file passes, and the append still fails.
"""

from __future__ import annotations

import errno
import json
import logging
import os
from pathlib import Path
from typing import Any

import pytest

from snitch.services import audit as audit_module
from snitch.services.audit import FILENAME, AuditLog

# ===========================================================================
# helpers: simulating "the directory is fine, the file is not"
# ===========================================================================


def _append_denier(path: Path, code: int) -> Any:
    """A ``Path.open`` replacement that refuses to append to ``path``.

    Interception rather than chmod, because the situation being modelled is a
    *container* uid mismatch, which no host chmod reproduces faithfully (and
    which Windows does not reproduce at all).
    """
    real_open = Path.open

    def guarded(self: Path, *args: Any, **kwargs: Any) -> Any:
        mode = args[0] if args else kwargs.get("mode", "r")
        if self == path and mode == "a":
            raise OSError(code, os.strerror(code), str(self))
        return real_open(self, *args, **kwargs)

    return guarded


def deny_append_to(path: Path, monkeypatch: pytest.MonkeyPatch, code: int = errno.EACCES) -> None:
    """Make appending to ``path`` fail while everything else keeps working."""
    monkeypatch.setattr(Path, "open", _append_denier(path, code))


def warnings(caplog: pytest.LogCaptureFixture, needle: str) -> list[str]:
    return [r.message for r in caplog.records if needle in r.message]


# ===========================================================================
# the healthy case must not regress
# ===========================================================================


def test_a_writable_directory_enables_the_log(tmp_path):
    assert AuditLog(tmp_path).enabled is True


def test_the_file_is_created_by_the_startup_probe(tmp_path):
    """The probe performs a real append, so the log exists from startup."""
    audit = AuditLog(tmp_path)

    assert audit.path == tmp_path / FILENAME
    assert audit.path.exists()


def test_the_probe_does_not_truncate_existing_history(tmp_path):
    """The probe must never destroy the records it exists to protect.

    It opens in append mode precisely so that a startup check cannot truncate
    the violation history to zero.
    """
    audit = AuditLog(tmp_path)
    audit.record(event="violation", user_id=111)
    audit.record(event="violation", user_id=222)

    AuditLog(tmp_path)  # restart: probe runs again over a populated file

    assert len(AuditLog(tmp_path).tail(limit=50)) == 2


def test_records_still_round_trip(tmp_path):
    audit = AuditLog(tmp_path)
    audit.record(event="violation", user_id=111, deleted=True)

    assert json.loads(audit.tail()[0])["user_id"] == 111


# ===========================================================================
# the bug: writable directory, unwritable file
# ===========================================================================


def test_an_unappendable_file_disables_the_log_at_startup(tmp_path, monkeypatch, caplog):
    """Not hours later on the first violation - at startup, with a reason."""
    deny_append_to(tmp_path / FILENAME, monkeypatch)

    with caplog.at_level(logging.WARNING):
        audit = AuditLog(tmp_path)

    assert audit.enabled is False
    assert warnings(caplog, "cannot append to")


def test_the_failure_names_the_actual_file_not_the_directory(tmp_path, monkeypatch, caplog):
    """chowning the directory would not have helped; the message must not imply it would."""
    deny_append_to(tmp_path / FILENAME, monkeypatch)

    with caplog.at_level(logging.WARNING):
        AuditLog(tmp_path)

    message = warnings(caplog, "cannot append to")[0]
    assert str(tmp_path / FILENAME) in message


def test_a_permission_error_suggests_the_chown_command(tmp_path, monkeypatch, caplog):
    # uid/gid are stubbed because the remedy is POSIX-only by design; on Windows
    # it is correctly withheld, which a separate test pins down.
    monkeypatch.setattr(audit_module, "_current_uid", lambda: 10001)
    monkeypatch.setattr(audit_module, "_current_gid", lambda: 10001)
    deny_append_to(tmp_path / FILENAME, monkeypatch)

    with caplog.at_level(logging.WARNING):
        AuditLog(tmp_path)

    message = warnings(caplog, "cannot append to")[0]
    assert "chown -R 10001:10001" in message
    assert "named Docker volume" in message


def test_the_chown_targets_the_data_dir_not_its_parent(tmp_path, monkeypatch, caplog):
    """Regression: the remedy once printed `/app` instead of `/app/data`.

    A recursive chown of the parent would take the venv and the app with it.
    """
    monkeypatch.setattr(audit_module, "_current_uid", lambda: 10001)
    monkeypatch.setattr(audit_module, "_current_gid", lambda: 10001)
    deny_append_to(tmp_path / FILENAME, monkeypatch)

    with caplog.at_level(logging.WARNING):
        AuditLog(tmp_path)

    message = warnings(caplog, "cannot append to")[0]
    assert f"mapped to {tmp_path}" in message
    assert f"chown -R 10001:10001 {tmp_path.parent} " not in message


def test_no_chown_advice_where_the_concept_does_not_exist(tmp_path, monkeypatch, caplog):
    """On a platform without uids, `chown` advice would be nonsense."""
    monkeypatch.setattr(audit_module, "_current_uid", lambda: None)
    deny_append_to(tmp_path / FILENAME, monkeypatch)

    with caplog.at_level(logging.WARNING):
        AuditLog(tmp_path)
    # Matched on the remedy's own wording: pytest's tmp_path can contain
    # arbitrary substrings, including "chown".
    message = warnings(caplog, "cannot append to")[0]
    assert "chown -R" not in message
    assert "named Docker volume" not in message


def test_a_non_permission_error_gets_no_guessed_remedy(tmp_path, monkeypatch, caplog):
    """Offering `chown` for a full disk or a read-only mount is a red herring."""
    deny_append_to(tmp_path / FILENAME, monkeypatch, code=errno.ENOSPC)

    with caplog.at_level(logging.WARNING):
        AuditLog(tmp_path)

    message = warnings(caplog, "cannot append to")[0]
    assert "chown" not in message
    assert "No space left on device" in message or "oserror" in message.lower()


def test_the_warning_says_the_record_is_not_being_kept(tmp_path, monkeypatch, caplog):
    """The operator must know deleting and muting still work - this is not fatal."""
    deny_append_to(tmp_path / FILENAME, monkeypatch)

    with caplog.at_level(logging.WARNING):
        AuditLog(tmp_path)

    assert "not being kept" in warnings(caplog, "cannot append to")[0]


def test_recording_after_a_startup_failure_is_silent_and_harmless(tmp_path, monkeypatch):
    """record() is called from the moderation path; it must never raise."""
    deny_append_to(tmp_path / FILENAME, monkeypatch)
    audit = AuditLog(tmp_path)

    audit.record(event="violation", user_id=111)  # must not raise
    audit.record(event="violation", user_id=111, message_id=5)

    assert audit.tail() == []


# ===========================================================================
# the ownership sentence
# ===========================================================================


def test_the_warning_names_both_uids_when_they_differ(tmp_path, monkeypatch, caplog):
    """'Permission denied' alone is unactionable without knowing who owns what.

    Ownership is stubbed at ``_owner_of`` because a container uid mismatch is
    the situation being modelled and cannot be reproduced with host permissions.
    """
    monkeypatch.setattr(audit_module, "_current_uid", lambda: 10001)
    monkeypatch.setattr(audit_module, "_owner_of", lambda _path: 0)
    monkeypatch.setattr(
        Path,
        "open",
        _append_denier(tmp_path / FILENAME, errno.EACCES),
    )

    with caplog.at_level(logging.WARNING):
        AuditLog(tmp_path)

    message = warnings(caplog, "cannot append to")[0]
    assert "owned by uid 0" in message
    assert "runs as uid 10001" in message


def test_the_optional_clauses_are_separated_by_spaces(tmp_path, monkeypatch, caplog):
    """These sentences are concatenated; without a separator they run together
    into '...jsonl')The audit log is off', which reads as garbled output."""
    monkeypatch.setattr(audit_module, "_current_uid", lambda: 10001)
    monkeypatch.setattr(audit_module, "_current_gid", lambda: 10001)
    deny_append_to(tmp_path / FILENAME, monkeypatch)

    with caplog.at_level(logging.WARNING):
        AuditLog(tmp_path)

    message = warnings(caplog, "cannot append to")[0]
    assert ")The" not in message
    assert "uid 10001.The" not in message
    assert ". This" in message or ".The" not in message


def test_no_ownership_speech_when_uids_match(tmp_path, monkeypatch, caplog):
    """Same owner means the cause is the mount, not ownership; do not imply otherwise."""
    deny_append_to(tmp_path / FILENAME, monkeypatch)

    with caplog.at_level(logging.WARNING):
        AuditLog(tmp_path)

    assert "owned by uid" not in warnings(caplog, "cannot append to")[0]


# ===========================================================================
# structured context, for log shipping
# ===========================================================================


def test_the_failure_is_machine_readable_not_just_readable(tmp_path, monkeypatch, caplog):
    deny_append_to(tmp_path / FILENAME, monkeypatch)

    with caplog.at_level(logging.WARNING):
        AuditLog(tmp_path)

    record = next(r for r in caplog.records if "cannot append to" in r.message)
    assert getattr(record, "event", None) == "audit_unavailable"
    assert getattr(record, "errno", None) == errno.EACCES
    assert record.path == str(tmp_path / FILENAME)


def test_the_problem_is_reported_once_not_on_every_violation(tmp_path, monkeypatch, caplog):
    """A broken log must not become log spam that buries the original warning."""
    deny_append_to(tmp_path / FILENAME, monkeypatch)

    with caplog.at_level(logging.WARNING):
        audit = AuditLog(tmp_path)
        for _ in range(50):
            audit.record(event="violation")

    assert len(warnings(caplog, "cannot append")) == 1


# ===========================================================================
# the other failure: the directory itself
# ===========================================================================


def test_an_uncreatable_directory_still_disables_the_log(tmp_path, caplog):
    """mkdir failure was already handled; keep it."""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")

    with caplog.at_level(logging.WARNING):
        audit = AuditLog(blocker / "nested")

    assert audit.enabled is False
    assert warnings(caplog, "cannot create")


# ===========================================================================
# permissions changing *while* running
# ===========================================================================


def test_permissions_lost_mid_run_are_reported_with_the_remedy(tmp_path, monkeypatch, caplog):
    """The original symptom: an append fails long after startup.

    Covered separately from the startup probe because it is the same warning an
    operator actually met - and it must not be the bare "[Errno 13] Permission
    denied" that gave no clue what to do.
    """
    monkeypatch.setattr(audit_module, "_current_uid", lambda: 10001)
    monkeypatch.setattr(audit_module, "_current_gid", lambda: 10001)
    audit = AuditLog(tmp_path)  # healthy
    assert audit.enabled is True

    deny_append_to(tmp_path / FILENAME, monkeypatch)  # then the volume is remounted

    with caplog.at_level(logging.WARNING):
        audit.record(event="violation", user_id=111)  # must not raise

    message = warnings(caplog, "could not append to")[0]
    assert "chown -R 10001:10001" in message
    assert "named Docker volume" in message
    assert f"mapped to {tmp_path}" in message


def test_a_mid_run_failure_does_not_disable_the_log(tmp_path, monkeypatch):
    """A transient write failure must not permanently mute the audit trail; the
    next violation should be recorded once the volume is back."""
    audit = AuditLog(tmp_path)
    deny_append_to(tmp_path / FILENAME, monkeypatch)
    audit.record(event="violation", user_id=111)  # fails
    monkeypatch.undo()

    audit.record(event="violation", user_id=222)

    assert json.loads(audit.tail()[-1])["user_id"] == 222
