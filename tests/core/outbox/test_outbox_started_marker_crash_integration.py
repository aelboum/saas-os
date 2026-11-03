"""Crash recovery D4 with real worker processes (design pull request #195,
section 5; `docs/architecture/OUTBOX-STARTED-MARKER.md`).

Each test claims an event, then starts a separate Python process that runs
the real `_run_outbox_event` job with a probe consumer and markers on
(`OUTBOX_EXTERNAL_EFFECT_MARKERS=true`). When the process reports that it
has reached the crash point it is killed (`Popen.kill()`: SIGKILL on POSIX,
`TerminateProcess` on Windows), so nothing is committed or closed cleanly.
The lease then expires (an explicit later `now`) and the event is reclaimed:

- killed before the marker: nothing was sent; retried;
- killed while the marker `UPDATE` was uncommitted: PostgreSQL rolls it
  back with the dead connection; retried as "never started";
- killed after the marker committed (the request "in flight"): ambiguous;
  dead-lettered `CrashAfterStart:` with the marker kept.

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
from typing import Any

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
    max_attempts=3, retry_jitter_ratio=0, lease_seconds=300, external_effect_markers=True
)

# The worker process: the real job, a probe consumer that stops at the
# crash point named by argv[1] and reports READY.
_WORKER = r"""
import asyncio, sys, time, uuid
from contextlib import contextmanager

import saas_os.core.rbac  # noqa: F401
import saas_os.api.outbox_dispatcher as dispatcher
import saas_os.core.outbox.dispatch as dispatch
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload

mode, tenant, event, claim = sys.argv[1:5]
armed = []


def ready_and_hang():
    print("READY", flush=True)
    time.sleep(600)


real_scope = dispatch.tenant_session_scope


@contextmanager
def scope_paused_before_commit(tenant_id):
    with real_scope(tenant_id) as session:
        yield session
        if armed:
            ready_and_hang()  # the marker UPDATE ran; its COMMIT has not


if mode == "uncommitted":
    dispatch.tenant_session_scope = scope_paused_before_commit


async def consumer(context, payload):
    if mode == "before":
        ready_and_hang()
    armed.append(True)
    with context.external_effect():
        ready_and_hang()  # the request would be on the wire here


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
    tenant_id = create_tenant(f"outbox-d4-crash-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id
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


def _run_and_kill(mode: str, claim: dispatch.ClaimedEvent) -> dict[str, Any]:
    """Start the worker process, wait for READY, kill it, return what it
    printed and its exit status."""
    env = {
        **os.environ,
        "OUTBOX_EXTERNAL_EFFECT_MARKERS": "true",
        "OUTBOX_LEASE_SECONDS": "300",
        "PYTHONUNBUFFERED": "1",
    }
    proc = subprocess.Popen(  # noqa: S603 -- the test's own interpreter and script
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
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lines: queue.Queue[str] = queue.Queue()
    errors: list[str] = []
    assert proc.stdout is not None and proc.stderr is not None
    stdout, stderr = proc.stdout, proc.stderr

    def _drain_out() -> None:
        for line in stdout:
            lines.put(line.strip())

    def _drain_err() -> None:
        errors.extend(stderr)

    readers = [threading.Thread(target=f, daemon=True) for f in (_drain_out, _drain_err)]
    for reader in readers:
        reader.start()
    try:
        deadline = time.monotonic() + 120
        seen: list[str] = []
        while time.monotonic() < deadline:
            try:
                line = lines.get(timeout=0.5)
            except queue.Empty:
                if proc.poll() is not None:
                    break
                continue
            seen.append(line)
            if line == "READY":
                break
        assert "READY" in seen, f"worker never reached {mode!r}: {seen} {''.join(errors)[-2000:]}"
        assert proc.poll() is None, "the worker exited by itself"
    finally:
        proc.kill()
        returncode = proc.wait(timeout=30)
        for reader in readers:
            reader.join(timeout=10)
    return {"returncode": returncode, "stdout": seen, "stderr": "".join(errors)}


def _reclaim_until_settled(at: datetime, attempts: int = 40) -> list[dispatch.ClaimedEvent]:
    """Reclaim at `at`. A killed worker's backend may hold its row lock
    for a moment after the kill (until PostgreSQL notices the closed
    connection); `SKIP LOCKED` then skips the row, so try again briefly."""
    for _ in range(attempts):
        claims = claim_due_events(config=_CONFIG, now=at, rng=lambda: 0.0)
        if claims:
            return claims
        time.sleep(0.25)
    return []


def test_a_worker_killed_before_the_marker_leaves_the_event_to_be_retried(
    tenant: uuid.UUID,
) -> None:
    claim = _claimed_event(tenant)

    result = _run_and_kill("before", claim)

    assert result["returncode"] != 0 and "RETURNED" not in result["stdout"]
    assert _row(tenant, claim.id).external_started_claim is None
    (retry,) = _reclaim_until_settled(datetime.now(UTC) + timedelta(seconds=601))
    assert (retry.id, retry.attempts) == (claim.id, 2)
    row = _row(tenant, claim.id)
    assert row.status == OUTBOX_STATUS_PENDING
    assert row.last_error is not None and row.last_error.startswith("LeaseExpired")


def test_a_worker_killed_with_its_marker_uncommitted_leaves_the_event_to_be_retried(
    tenant: uuid.UUID,
) -> None:
    claim = _claimed_event(tenant)

    result = _run_and_kill("uncommitted", claim)

    assert result["returncode"] != 0 and "RETURNED" not in result["stdout"]
    (retry,) = _reclaim_until_settled(datetime.now(UTC) + timedelta(seconds=601))
    assert (retry.id, retry.attempts) == (claim.id, 2)
    row = _row(tenant, claim.id)
    assert row.status == OUTBOX_STATUS_PENDING
    assert (row.external_started_at, row.external_started_claim) == (None, None)


def test_a_worker_killed_after_its_marker_committed_is_dead_lettered_crash_after_start(
    tenant: uuid.UUID,
) -> None:
    claim = _claimed_event(tenant)

    result = _run_and_kill("after", claim)

    assert result["returncode"] != 0 and "RETURNED" not in result["stdout"]
    marked = _row(tenant, claim.id)
    assert marked.external_started_claim == claim.claim_token  # survived the crash
    assert marked.external_started_at is not None

    assert _reclaim_until_settled(datetime.now(UTC) + timedelta(seconds=601), attempts=4) == []

    row = _row(tenant, claim.id)
    assert row.status == OUTBOX_STATUS_DEAD_LETTERED
    assert row.last_error == CRASH_AFTER_START_ERROR
    assert row.claim_token is None
    assert row.external_started_claim == claim.claim_token
    assert row.external_started_at == marked.external_started_at
