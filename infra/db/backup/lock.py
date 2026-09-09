"""P2.4 -- concurrent-backup-execution prevention.

`infra.db.backup`'s production pipeline (`orchestrator.py`) is invoked by
a host-level scheduler (`docs/BACKUP-RESTORE.md`'s systemd timer, or
cron) -- a single process, on a single VPS (this repository's one
accepted deployment target, `docs/ADR/0010-deployment-target.md`), that
never holds a database connection for the pipeline's full duration (dump,
encrypt, upload, and retention can each take a meaningfully long time,
and the dump/restore steps themselves connect and disconnect via separate
`docker exec` invocations -- there is no single long-lived Postgres
session to attach a `pg_advisory_lock` to across the whole pipeline).

The right-sized mechanism for "prevent two overlapping runs of the same
host-level scheduled process" is therefore an OS-level advisory file lock
(`fcntl.flock`, POSIX -- this repository's production target is Linux
only) -- not a PID file (this checkpoint's own "do not use a fragile
PID-file-only lock"): a PID file can go stale (the recorded process died
without cleaning up, and a new process with the same PID is now
running -- classic PID-file bug) and requires the *next* run to notice
and repair that; an `flock` held by a file descriptor is released
automatically by the kernel the instant the holding process exits for
*any* reason, including a crash or `SIGKILL`, with no separate staleness
check ever required. `LOCK_EX | LOCK_NB` (non-blocking exclusive): a
second run that finds the lock already held fails immediately rather
than queueing behind the first (this checkpoint's own "if another backup
is running: do not run concurrently" -- queueing would just move the
same problem later, e.g. two runs starting minutes apart under real
production duration).
"""

from __future__ import annotations

import contextlib
import sys
from collections.abc import Iterator
from pathlib import Path


class BackupLockError(RuntimeError):
    """Raised when the backup lock is already held by another process."""


@contextlib.contextmanager
def backup_lock(lock_path: Path) -> Iterator[None]:
    """Hold an exclusive, non-blocking lock on `lock_path` for the
    duration of the `with` block. Raises `BackupLockError` immediately if
    another process already holds it -- never blocks. `lock_path`'s
    parent directory is created if missing; the lock file itself is never
    deleted (its mere existence carries no meaning -- only *holding an
    flock on it* does, so a stale zero-byte file left over from a past,
    cleanly-exited run is harmless and expected, exactly why this is not
    a PID-file scheme)."""
    if sys.platform == "win32":  # pragma: no cover -- production target is Linux only (ADR-0010)
        import msvcrt

        lock_path.parent.mkdir(parents=True, exist_ok=True)
        if not lock_path.exists():
            lock_path.write_bytes(b"\0")  # msvcrt.locking needs >=1 byte to lock a region
        handle = lock_path.open("r+b")
        try:
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise BackupLockError(
                    f"backup lock {lock_path.name!r} is already held by another process."
                ) from exc
            try:
                yield
            finally:
                handle.seek(0)
                with contextlib.suppress(OSError):
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            handle.close()
        return

    import fcntl  # POSIX only -- see module docstring

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise BackupLockError(
                f"backup lock {lock_path.name!r} is already held by another process -- "
                "a backup is already running."
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()
