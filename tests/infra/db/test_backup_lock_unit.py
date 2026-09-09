"""Unit tests for `infra.db.backup.lock` -- proving `backup_lock()`
actually prevents concurrent acquisition (via a real second process, not
just a second call in the same process -- an in-process second `open()`
would not exercise the OS-level lock this module exists to provide), and
that it releases cleanly on both normal exit and an exception.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest
from infra.db.backup.lock import BackupLockError, backup_lock

_HOLD_LOCK_SCRIPT = """
import sys
import time
from pathlib import Path
sys.path.insert(0, {repo_root!r})
from infra.db.backup.lock import backup_lock

with backup_lock(Path({lock_path!r})):
    print("LOCKED", flush=True)
    time.sleep({hold_seconds})
"""


def test_lock_is_released_after_normal_exit(tmp_path: Path) -> None:
    lock_path = tmp_path / "backup.lock"
    with backup_lock(lock_path):
        pass
    with backup_lock(lock_path):  # must succeed -- the first lock was released
        pass


def test_lock_is_released_after_an_exception(tmp_path: Path) -> None:
    lock_path = tmp_path / "backup.lock"
    with pytest.raises(RuntimeError, match="boom"):
        with backup_lock(lock_path):
            raise RuntimeError("boom")
    with backup_lock(lock_path):  # must succeed -- released even though the body raised
        pass


def test_lock_creates_missing_parent_directory(tmp_path: Path) -> None:
    lock_path = tmp_path / "nested" / "dir" / "backup.lock"
    with backup_lock(lock_path):
        pass
    assert lock_path.parent.is_dir()


def test_concurrent_acquisition_by_a_second_process_is_rejected(tmp_path: Path) -> None:
    """A real second OS process holds the lock while this process attempts
    a second acquisition -- proves the lock is an OS-level primitive, not
    merely an in-process guard a second caller in the same interpreter
    could trivially bypass."""
    repo_root = str(Path(__file__).resolve().parents[3])
    lock_path = tmp_path / "backup.lock"
    script = _HOLD_LOCK_SCRIPT.format(repo_root=repo_root, lock_path=str(lock_path), hold_seconds=3)

    holder = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        line = ""
        while time.monotonic() < deadline:
            line = holder.stdout.readline() if holder.stdout else ""
            if "LOCKED" in line:
                break
        assert "LOCKED" in line, "holder process never reported acquiring the lock"

        with pytest.raises(BackupLockError):
            with backup_lock(lock_path):
                pass
    finally:
        holder.wait(timeout=10)

    # Once the holder has exited, the lock must be acquirable again.
    with backup_lock(lock_path):
        pass
