"""Retry after a started marker with real worker processes
(`docs/architecture/OUTBOX-RETRY-AFTER-MARKER-DESIGN.md`, section 13; the
harness of `test_outbox_started_marker_crash_integration.py`).

Each test claims an event and starts a separate Python process that runs the
real `_run_outbox_event` job with a probe consumer and markers on:

- (a) killed after the consumer raised its attestation and before the outcome
  committed: the row is still marked, the reclaim dead-letters it
  `CrashAfterStart:`, no retry, no duplicate;
- (b) killed after the outcome committed: the event is pending, unmarked; the
  retry runs once and completes;
- (c) killed during the retry's own request: `CrashAfterStart:` for the new
  claim;
- (d) the stale worker resumes after the reclaim decided the event: its
  attestation changes nothing.

Marked `integration`. Every row created is removed afterwards.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.outbox.dispatch as dispatch
import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING
from saas_os.core.outbox import (
    CRASH_AFTER_START_ERROR,
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    OutboxDispatchConfig,
    OutboxEvent,
    append_event,
    claim_due_events,
)
from saas_os.core.tenancy import create_tenant, list_open_tenant_ids
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PROBE = "probe.external_effect"
_CONFIG = OutboxDispatchConfig(
    max_attempts=3, retry_jitter_ratio=0, lease_seconds=360, external_effect_markers=True
)

# The worker process. argv: mode tenant event claim. Modes:
#   attest_before_commit  the consumer attests "not sent"; the process stops
#                         inside the outcome write, before its COMMIT
#   attest_after_commit   the same, stopping right after the outcome committed
#   send_and_hang         marks, then stops where the request would be on the wire
#   attest_after_go       marks, waits for "GO" on stdin, then attests; the
#                         process returns normally (the stale worker)
#   deliver               marks and returns: the retry's successful delivery
_WORKER = r"""
import asyncio, sys, time, uuid
from contextlib import contextmanager

import saas_os.core.rbac  # noqa: F401
import saas_os.api.outbox_dispatcher as dispatcher
import saas_os.core.outbox.dispatch as dispatch
from saas_os.core.outbox import ConfirmedNotSentError
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload

mode, tenant, event, claim = sys.argv[1:5]


class NotSent(ConfirmedNotSentError):
    pass


def ready_and_hang():
    print("READY", flush=True)
    time.sleep(600)


real_scope = dispatch.tenant_session_scope
real_record = dispatcher.record_confirmed_not_sent


@contextmanager
def scope_paused_before_commit(tenant_id):
    with real_scope(tenant_id) as session:
        yield session
        ready_and_hang()  # the outcome UPDATE ran; its COMMIT has not


def record_paused_before_commit(*args, **kwargs):
    dispatch.tenant_session_scope = scope_paused_before_commit
    return real_record(*args, **kwargs)


def record_then_hang(*args, **kwargs):
    result = real_record(*args, **kwargs)
    ready_and_hang()  # the outcome is committed
    return result


if mode == "attest_before_commit":
    dispatcher.record_confirmed_not_sent = record_paused_before_commit
elif mode == "attest_after_commit":
    dispatcher.record_confirmed_not_sent = record_then_hang


async def consumer(context, payload):
    if mode == "deliver":
        with context.external_effect():
            return
    if mode == "send_and_hang":
        with context.external_effect():
            ready_and_hang()
    if mode == "attest_after_go":
        with context.external_effect():
            print("READY", flush=True)
            assert sys.stdin.readline().strip() == "GO"
            raise NotSent("connect_failed")
    with context.external_effect():
        raise NotSent("connect_failed")


dispatcher.outbox_event_handlers = lambda: {"probe.external_effect": consumer}
asyncio.run(
    dispatcher._run_outbox_event(
        TenantJobContext(tenant_id=uuid.UUID(tenant)),
        TenantJobPayload(
            tenant_id=tenant, data={"outbox_event_id": event, "claim_token": claim}
        ),
    )
)
print("RETURNED", flush=True)
"""


@pytest.fixture(autouse=True)
def _require_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT external_started_claim FROM core.outbox_events LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable/migrated to 0420025c3b4b: {exc}")
    finally:
        probe.dispose()


def _admin(sql: str, params: Mapping[str, object]) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            session.execute(text(sql), params)
    finally:
        engine.dispose()


@pytest.fixture
def tenant(monkeypatch: pytest.MonkeyPatch) -> Iterator[uuid.UUID]:
    tenant_id = create_tenant(f"outbox-rt18-crash-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id
    monkeypatch.setattr(
        dispatch,
        "list_open_tenant_ids",
        lambda: [t for t in list_open_tenant_ids() if t == tenant_id],
    )
    try:
        yield tenant_id
    finally:
        params = {"t": str(tenant_id)}
        _admin("DELETE FROM core.outbox_events WHERE tenant_id = :t", params)
        _admin(
            "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t", params
        )
        _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
        _admin("DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t", params)
        _admin("DELETE FROM core.tenants WHERE id = :t", params)


def _row(tenant_id: uuid.UUID, event_id: uuid.UUID) -> OutboxEvent:
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(select(OutboxEvent).where(OutboxEvent.id == event_id)).scalar_one()
        session.expunge(row)
        return row


def _claimed_event(tenant_id: uuid.UUID) -> dispatch.ClaimedEvent:
    with tenant_session_scope(tenant_id) as session:
        append_event(
            session,
            tenant_id=tenant_id,
            event_type=_PROBE,
            aggregate_type="probe",
            aggregate_id="1",
            payload={"n": 1},
        )
    (claim,) = claim_due_events(
        config=_CONFIG, now=datetime.now(UTC) + timedelta(seconds=1), rng=lambda: 0.0
    )
    return claim


def _later_claim(hours: float, tries: int = 40) -> list[dispatch.ClaimedEvent]:
    """Reclaim `hours` from now. A killed worker's backend may hold its row
    lock for a moment after the kill; `SKIP LOCKED` then skips the row, so
    try again briefly."""
    for _ in range(tries):
        claims = claim_due_events(
            config=_CONFIG, now=datetime.now(UTC) + timedelta(hours=hours), rng=lambda: 0.0
        )
        if claims:
            return claims
        time.sleep(0.25)
    return []


class _Worker:
    """One worker process: started, waited for READY, then killed or
    released; `stdout` is what it printed."""

    def __init__(self, mode: str, claim: dispatch.ClaimedEvent) -> None:
        env = {
            **os.environ,
            "OUTBOX_EXTERNAL_EFFECT_MARKERS": "true",
            "OUTBOX_LEASE_SECONDS": "360",
            "OUTBOX_RETRY_JITTER_RATIO": "0",
            "OUTBOX_RETRY_BASE_SECONDS": "30",
            "PYTHONUNBUFFERED": "1",
        }
        self.proc = subprocess.Popen(  # noqa: S603 -- the test's own interpreter and script
            [
                sys.executable,
                "-c",
                _WORKER,
                mode,
                str(claim.tenant_id),
                str(claim.id),
                str(claim.claim_token),
            ],
            cwd=_REPO_ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.lines: queue.Queue[str] = queue.Queue()
        self.seen: list[str] = []
        self.errors: list[str] = []
        assert self.proc.stdout is not None and self.proc.stderr is not None
        stdout, stderr = self.proc.stdout, self.proc.stderr
        self._readers = [
            threading.Thread(
                target=lambda: [self.lines.put(x.strip()) for x in stdout], daemon=True
            ),
            threading.Thread(target=lambda: self.errors.extend(stderr), daemon=True),
        ]
        for reader in self._readers:
            reader.start()
        self.mode = mode

    def wait_for(self, marker: str, timeout: float = 120) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=0.5)
            except queue.Empty:
                if self.proc.poll() is not None:
                    break
                continue
            self.seen.append(line)
            if line == marker:
                return
        raise AssertionError(
            f"worker never printed {marker!r} in {self.mode!r}: {self.seen} "
            f"{''.join(self.errors)[-2000:]}"
        )

    def kill(self) -> int:
        self.proc.kill()
        code = self.proc.wait(timeout=30)
        self.finish()
        return code

    def finish(self) -> None:
        for reader in self._readers:
            reader.join(timeout=10)

    def send(self, line: str) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()


def _run_to_ready_and_kill(mode: str, claim: dispatch.ClaimedEvent) -> _Worker:
    worker = _Worker(mode, claim)
    try:
        worker.wait_for("READY")
        assert worker.proc.poll() is None, "the worker exited by itself"
    finally:
        assert worker.kill() != 0
    assert "RETURNED" not in worker.seen
    return worker


def _run_to_completion(mode: str, claim: dispatch.ClaimedEvent) -> _Worker:
    worker = _Worker(mode, claim)
    try:
        worker.wait_for("RETURNED")
        assert worker.proc.wait(timeout=60) == 0
    finally:
        if worker.proc.poll() is None:
            worker.kill()
        worker.finish()
    return worker


def test_a_worker_killed_after_the_attestation_before_its_outcome_committed_is_crash_after_start(
    tenant: uuid.UUID,
) -> None:
    """(a) The attestation was raised but never recorded: PostgreSQL rolls the
    uncommitted outcome back with the dead connection, the row is still
    marked, and the safe reading is the ambiguous one."""
    claim = _claimed_event(tenant)

    _run_to_ready_and_kill("attest_before_commit", claim)

    marked = _row(tenant, claim.id)
    assert marked.status == OUTBOX_STATUS_PENDING
    assert marked.claim_token == claim.claim_token
    assert marked.external_started_claim == claim.claim_token
    assert _later_claim(1, 4) == []  # dead-lettered, not claimed again
    row = _row(tenant, claim.id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error == CRASH_AFTER_START_ERROR
    assert row.external_started_claim == claim.claim_token
    assert row.attempts == 1  # no second attempt, no duplicate


def test_a_worker_killed_after_the_outcome_committed_leaves_a_retry_that_runs_once(
    tenant: uuid.UUID,
) -> None:
    """(b)"""
    claim = _claimed_event(tenant)

    _run_to_ready_and_kill("attest_after_commit", claim)

    recorded = _row(tenant, claim.id)
    assert recorded.status == OUTBOX_STATUS_PENDING
    assert recorded.claim_token is None
    assert (recorded.external_started_at, recorded.external_started_claim) == (None, None)
    assert recorded.attempts == 1
    (retry,) = _later_claim(1)
    assert (retry.id, retry.attempts) == (claim.id, 2)

    worker = _run_to_completion("deliver", retry)

    assert worker.seen[-1] == "RETURNED"
    row = _row(tenant, claim.id)
    assert (row.status, row.attempts) == (OUTBOX_STATUS_PUBLISHED, 2)
    assert (row.external_started_at, row.external_started_claim) == (None, None)
    assert _later_claim(3, 4) == []  # nothing left to run again


def test_a_worker_killed_during_the_retrys_own_request_is_crash_after_start(
    tenant: uuid.UUID,
) -> None:
    """(c) A crash after the outcome is unmarked, so the retry's own marker
    decides a crash during its request: ambiguous for the new claim."""
    claim = _claimed_event(tenant)
    _run_to_ready_and_kill("attest_after_commit", claim)
    (retry,) = _later_claim(1)

    _run_to_ready_and_kill("send_and_hang", retry)

    marked = _row(tenant, claim.id)
    assert marked.external_started_claim == retry.claim_token
    assert _later_claim(3, 4) == []
    row = _row(tenant, claim.id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error == CRASH_AFTER_START_ERROR
    assert (row.attempts, row.external_started_claim) == (2, retry.claim_token)


def test_a_stale_worker_resuming_after_the_reclaim_changes_nothing(tenant: uuid.UUID) -> None:
    """(d) The worker marked, stalled past its lease, and the reclaim
    dead-lettered `CrashAfterStart:`. When it resumes and attests, its claim
    is no longer the row's: the outcome matches no row."""
    claim = _claimed_event(tenant)
    worker = _Worker("attest_after_go", claim)
    try:
        worker.wait_for("READY")
        assert _row(tenant, claim.id).external_started_claim == claim.claim_token
        assert _later_claim(1, 4) == []  # reclaimed by lease expiry: dead-lettered
        decided = _row(tenant, claim.id)
        assert decided.status == OUTBOX_STATUS_DEAD_LETTERED
        assert decided.last_error == CRASH_AFTER_START_ERROR

        worker.send("GO")
        worker.wait_for("RETURNED")
        assert worker.proc.wait(timeout=60) == 0
    finally:
        if worker.proc.poll() is None:
            worker.kill()
        worker.finish()

    row = _row(tenant, claim.id)
    assert (row.status, row.last_error, row.attempts) == (
        OUTBOX_STATUS_DEAD_LETTERED,
        CRASH_AFTER_START_ERROR,
        1,
    )
    assert row.external_started_claim == claim.claim_token
    assert row.next_attempt_at == decided.next_attempt_at
