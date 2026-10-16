"""ADR-0053 -- audit digests against a real PostgreSQL.

Rows are written with the migrations role at fixed times in 1990, so the
windows under test hold only this file's rows. Changes are then made the
way a holder of that role could make them -- `UPDATE`, `DELETE` and
`INSERT` straight into the audit tables -- and the verifier, running as the
application role, must find each one in the right window and tenant.

`core.audit_digests` is global state: the job test clears it first (the
digest job's cursor is the newest row) and the fixture removes what the
tests wrote.

Marked `integration`.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
import saas_os.core.rbac.models  # noqa: F401  (delegation/support-access FK targets)
from lifecycle_callers import PROVISIONING
from saas_os.core.audit_digest import (
    LOG_EVENT,
    AuditDigest,
    AuditDigestConfig,
    LoggedRecord,
    Verification,
    build_record,
    canonical_json,
    compute_windows,
    digest_settled_windows,
    record_digest,
    records_from_log_lines,
    verify_records,
)
from saas_os.core.audit_digest.service import _store
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db import select
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import tenant_session_scope
from saas_os.infra.observability.logging import JsonFormatter

pytestmark = pytest.mark.integration

WINDOW = timedelta(hours=1)
T0 = datetime(1990, 1, 1, tzinfo=UTC)
_BEFORE_1991 = datetime(1991, 1, 1, tzinfo=UTC)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="microseconds")


def _admin(statement: str, **params: object) -> list[tuple[object, ...]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(statement), params)
            return [tuple(row) for row in result.all()] if result.returns_rows else []
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _require_migrated_database() -> None:
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.audit_digests LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    finally:
        engine.dispose()


@dataclass(frozen=True)
class _Seed:
    t1: uuid.UUID
    t2: uuid.UUID
    t1_first: uuid.UUID  # window 0
    t1_second: uuid.UUID  # window 1
    t2_first: uuid.UUID  # window 0
    platform: uuid.UUID  # window 0


def _insert_audit(tenant: uuid.UUID, at: datetime) -> uuid.UUID:
    row_id = uuid.uuid4()
    _admin(
        "INSERT INTO core.audit_log (id, tenant_id, actor_type, action, resource_type, "
        "resource_id, outcome, metadata, created_at) VALUES (:id, :t, 'system', 'test.digest', "
        "'test_resource', :r, 'success', CAST(:m AS json), :at)",
        id=str(row_id),
        t=str(tenant),
        r=str(row_id),
        m=json.dumps({"z": 1, "a": [1, 2]}),
        at=at,
    )
    return row_id


def _insert_platform(at: datetime) -> uuid.UUID:
    row_id = uuid.uuid4()
    _admin(
        "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
        "target_type, target_id, outcome, created_at) VALUES (:id, 'system', 'provisioning', "
        "'test.digest', 'test_target', :tid, 'success', :at)",
        id=str(row_id),
        tid=str(row_id),
        at=at,
    )
    return row_id


@pytest.fixture
def seed() -> Iterator[_Seed]:
    t1 = create_tenant(f"digest-a-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id
    t2 = create_tenant(f"digest-b-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id
    try:
        yield _Seed(
            t1=t1,
            t2=t2,
            t1_first=_insert_audit(t1, T0 + timedelta(minutes=10)),
            t1_second=_insert_audit(t1, T0 + timedelta(minutes=70)),
            t2_first=_insert_audit(t2, T0 + timedelta(minutes=20)),
            platform=_insert_platform(T0 + timedelta(minutes=30)),
        )
    finally:
        tenants = [str(t1), str(t2)]
        _admin(
            "DELETE FROM core.audit_log WHERE tenant_id::text = ANY(:t) "
            "OR acting_as_tenant_id::text = ANY(:t)",
            t=tenants,
        )
        _admin(
            "DELETE FROM core.platform_audit_log WHERE created_at < :c "
            "OR target_tenant_id::text = ANY(:t)",
            c=_BEFORE_1991,
            t=tenants,
        )
        _admin("DELETE FROM core.audit_digests WHERE window_start < :c", c=_BEFORE_1991)
        _admin("DELETE FROM core.tenants WHERE id::text = ANY(:t)", t=tenants)


def _chain(starts: list[datetime]) -> list[LoggedRecord]:
    logged: list[LoggedRecord] = []
    previous = None
    for window in compute_windows(starts, WINDOW):
        record = build_record(window, previous)
        previous = record_digest(record)
        logged.append(LoggedRecord(record, previous))
    return logged


def _kinds(result: Verification) -> list[tuple[str, str | None, str]]:
    return [(f.kind, f.window_start, f.detail.split(":")[0]) for f in result.findings]


def test_windows_hold_each_tenants_rows_and_the_platform_rows(seed: _Seed) -> None:
    first, second = compute_windows([T0, T0 + WINDOW], WINDOW)
    assert {t: s.rows for t, s in first.tenants.items()} == {str(seed.t1): 1, str(seed.t2): 1}
    assert {t: s.rows for t, s in second.tenants.items()} == {str(seed.t1): 1}
    assert (first.platform.rows, second.platform.rows) == (1, 0)
    # Deterministic: recomputing gives the same digests.
    assert compute_windows([T0, T0 + WINDOW], WINDOW) == [first, second]


def test_verify_passes_untouched_and_finds_each_change(seed: _Seed) -> None:
    w0, w1 = _iso(T0), _iso(T0 + WINDOW)
    logged = _chain([T0, T0 + WINDOW])
    clean = verify_records(logged)
    assert clean.ok, clean.findings
    assert (clean.windows, clean.covered_from, clean.covered_until) == (
        2,
        w0,
        _iso(T0 + 2 * WINDOW),
    )

    # A changed row: found in its window and tenant only.
    _admin("UPDATE core.audit_log SET action = 'test.forged' WHERE id = :i", i=str(seed.t1_first))
    assert _kinds(verify_records(logged)) == [("audit_log_changed", w0, f"tenant {seed.t1}")]
    _admin("UPDATE core.audit_log SET action = 'test.digest' WHERE id = :i", i=str(seed.t1_first))
    assert verify_records(logged).ok

    # A changed timestamp moves a row into another window: both are found.
    _admin(
        "UPDATE core.audit_log SET created_at = :at WHERE id = :i",
        at=T0 + timedelta(minutes=80),
        i=str(seed.t2_first),
    )
    assert _kinds(verify_records(logged)) == [
        ("audit_log_changed", w0, f"tenant {seed.t2}"),
        ("audit_log_changed", w1, f"tenant {seed.t2}"),
    ]
    _admin(
        "UPDATE core.audit_log SET created_at = :at WHERE id = :i",
        at=T0 + timedelta(minutes=20),
        i=str(seed.t2_first),
    )
    assert verify_records(logged).ok

    # A deleted platform row.
    _admin("DELETE FROM core.platform_audit_log WHERE id = :i", i=str(seed.platform))
    deleted = verify_records(logged)
    assert [(f.kind, f.window_start) for f in deleted.findings] == [
        ("platform_audit_log_changed", w0)
    ]

    # An inserted row.
    _insert_audit(seed.t2, T0 + timedelta(minutes=90))
    assert ("audit_log_changed", w1, f"tenant {seed.t2}") in _kinds(verify_records(logged))


def test_altered_or_missing_records_are_findings(seed: _Seed) -> None:
    logged = _chain([T0, T0 + WINDOW, T0 + 2 * WINDOW])
    # A record changed in the store: its log line's digest no longer matches.
    forged = dict(logged[0].record)
    forged["platform_audit_log"] = {"rows": 0, "sha256": "0" * 64}
    altered = verify_records([LoggedRecord(forged, logged[0].stated_digest), *logged[1:]])
    assert "record_altered" in [f.kind for f in altered.findings]
    # A record removed from the store: a gap and a broken chain.
    missing = verify_records([logged[0], logged[2]])
    assert [f.kind for f in missing.findings] == ["gap", "chain_broken"]


def test_the_job_logs_chains_and_stores_settled_windows(
    seed: _Seed, caplog: pytest.LogCaptureFixture
) -> None:
    # The job resumes after the newest stored window; start from none, so it
    # starts at the oldest audit row: this file's, in 1990.
    _admin("DELETE FROM core.audit_digests")
    caplog.set_level(logging.INFO, logger="saas_os.core.audit_digest.service")
    config = AuditDigestConfig(window_seconds=3600, settle_seconds=60, max_windows_per_run=2)

    first = digest_settled_windows(config)
    assert [r["window_start"] for r in first.records] == [_iso(T0), _iso(T0 + WINDOW)]
    assert first.records[0]["previous"] is None
    assert first.records[1]["previous"] == first.digests[0]

    second = digest_settled_windows(config)
    assert second.records[0]["window_start"] == _iso(T0 + 2 * WINDOW)
    assert second.records[0]["previous"] == first.digests[1]

    # The log lines, formatted as the worker formats them, are the evidence:
    # exactly the stored records, and they verify.
    lines = [
        JsonFormatter().format(entry) for entry in caplog.records if entry.getMessage() == LOG_EVENT
    ]
    exported = records_from_log_lines(lines)
    assert [logged.record for logged in exported] == first.records + second.records
    assert verify_records(exported).ok

    stored = _admin("SELECT digest, record FROM core.audit_digests ORDER BY window_start")
    assert [row[0] for row in stored] == first.digests + second.digests
    assert [row[1] for row in stored] == [
        canonical_json(record) for record in first.records + second.records
    ]

    # A window another worker stored first is not stored again.
    (window,) = compute_windows([T0], WINDOW)
    assert _store(window, first.records[0], first.digests[0]) is False

    # The table is unreachable from a tenant-scoped transaction.
    with tenant_session_scope(seed.t1) as session:
        assert session.execute(select(AuditDigest.window_start)).all() == []
