"""Deleting expired permission grant ledger rows: the manual migrations-role
procedure of owner decision B of 2026-11-02. PostgreSQL.

`expire_permission_grant_ledger_rows` connects only with
`MIGRATIONS_DATABASE_URL` (the privileged role in this environment), names
a person who must hold `platform.security_retention:report`, re-checks
eligibility and holds under lock, deletes only after the operator confirmed
the exact count and digest of a prior report, and writes its platform audit
rows in the deletion's transaction. The runtime role keeps no `DELETE`.

A tenant's rows are made old enough by moving its one purge row back three
years with the privileged role (the purge itself is the real one).
The platform audit table is never truncated here: it holds the purge
evidence. Cleanup: `Ledger` deletes the test's ledger rows, holds and permission;
`Scene` and `PlatformWorld` the rest.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from phase_c_helpers import TENANT_PURGE, Scene
from platform_helpers import Gate, PlatformWorld, run_first_then_second
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError
from test_permission_grant_ledger_retention_integration import REASON, Ledger

from saas_os.core.authority import ServiceAccountCaller, UserCaller
from saas_os.core.permission_grants import (
    InvalidLedgerRetentionRequestError,
    LedgerExpiryConfirmationMismatchError,
    RetentionStatus,
    place_permission_grant_ledger_hold,
    release_permission_grant_ledger_hold,
)
from saas_os.core.permission_grants.expiry import expire_permission_grant_ledger_rows
from saas_os.core.platform_authority import PlatformNotAuthorizedError, PlatformPermission
from saas_os.core.tenancy import TenantStatus
from saas_os.infra.db import (
    UnsafeDatabaseRoleError,
    get_database_config,
    get_migrations_database_config,
    tenant_session_scope,
)

pytestmark = pytest.mark.integration

P = PlatformPermission
EXPIRE = "platform.permission_grant_ledger.expired_delete"


@pytest.fixture
def ledger(scene: Scene, platform: PlatformWorld) -> Iterator[Ledger]:
    built = Ledger(scene, platform)
    try:
        yield built
    finally:
        built.cleanup()


def _age(ledger: Ledger, tenant: uuid.UUID, years: int = 3) -> None:
    """Move the tenant's purge row back `years` years (privileged role)."""
    ledger.platform.execute(
        "UPDATE core.platform_audit_log SET created_at = created_at - make_interval(years => :y) "
        "WHERE action = 'platform.tenant.purge_transition' AND target_tenant_id = :t "
        "AND metadata->>'to_status' = 'purged'",
        {"y": years, "t": tenant},
    )


def _expired(ledger: Ledger, migrations: int = 1) -> uuid.UUID:
    tenant = ledger.tenant(migrations=migrations)
    ledger.purge(tenant)
    _age(ledger, tenant)
    return tenant


def _expire(ledger: Ledger, *tenants: uuid.UUID, caller: object = None, **kwargs: object):  # type: ignore[no-untyped-def]
    return expire_permission_grant_ledger_rows(
        caller=caller if caller is not None else ledger.reporter,
        reason="TICKET-9: retention expiry",
        tenant_ids=list(tenants),
        **kwargs,  # type: ignore[arg-type]
    )


# --- the procedure ----------------------------------------------------------------------


def test_a_confirmed_run_deletes_exactly_the_eligible_rows_with_its_audit_rows(
    ledger: Ledger, scene: Scene, platform: PlatformWorld
) -> None:
    eligible_a = _expired(ledger, migrations=2)
    eligible_b = _expired(ledger)
    held = _expired(ledger)
    place_permission_grant_ledger_hold(
        held, reference="LEGAL-1", caller=ledger.holder, reason=REASON
    )
    recent = ledger.tenant()
    ledger.purge(recent)  # purged now: two years still running
    unknown = ledger.tenant()
    scene.set_status(unknown, TenantStatus.PURGED)  # no purge evidence
    ambiguous = _expired(ledger)
    platform.execute(
        "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
        "target_type, target_id, target_tenant_id, outcome, metadata, created_at) VALUES "
        "(:i, 'system', 'tenant_purge', 'platform.tenant.purge_transition', 'tenant', :s, :t, "
        "'success', CAST(:m AS json), now() - interval '10 years')",
        {
            "i": uuid.uuid4(),
            "s": str(ambiguous),
            "t": ambiguous,
            "m": '{"from_status": "purging", "to_status": "purged"}',
        },
    )
    still_open = ledger.tenant()
    everyone = (eligible_a, eligible_b, held, recent, unknown, ambiguous, still_open)

    # 1. The audited report, made with the runtime role.
    report = ledger.report(*everyone)
    statuses = {t.tenant_id: t.status for t in report.tenants}
    assert statuses == {
        eligible_a: RetentionStatus.ELIGIBLE,
        eligible_b: RetentionStatus.ELIGIBLE,
        held: RetentionStatus.LEGAL_HOLD,
        recent: RetentionStatus.RETENTION_RUNNING,
        unknown: RetentionStatus.PURGE_TIME_UNKNOWN,
        ambiguous: RetentionStatus.PURGE_TIME_AMBIGUOUS,
        still_open: RetentionStatus.NOT_PURGED,
    }
    assert report.eligible_ledger_rows == 3

    # 2. The procedure's own dry run agrees and writes nothing.
    audit_before = platform.audit_count()
    dry = _expire(ledger, *everyone)
    assert (dry.applied, dry.run_id) == (False, None)
    assert (dry.eligible_ledger_rows, dry.eligible_digest) == (3, report.eligible_digest)
    assert {t.tenant_id for t in dry.eligible} == {eligible_a, eligible_b}
    assert dry.not_eligible == {
        "legal_hold": 1,
        "retention_running": 1,
        "purge_time_unknown": 1,
        "purge_time_ambiguous": 1,
        "not_purged": 1,
    }
    assert platform.audit_count() == audit_before
    assert [ledger.rows(t) for t in everyone] == [2, 1, 1, 1, 1, 1, 1]

    # 3. The deletion, confirmed with the report's count and digest.
    done = _expire(
        ledger,
        *everyone,
        apply=True,
        confirm_rows=report.eligible_ledger_rows,
        confirm_digest=report.eligible_digest,
    )
    assert done.applied is True and done.run_id is not None
    assert [ledger.rows(t) for t in everyone] == [0, 0, 1, 1, 1, 1, 1]

    # 4. The evidence: one run row (its id is the run id) and one row per
    # tenant, all by the reporter, all in the deletion's transaction.
    rows = platform.execute(
        "SELECT id, actor_user_id, target_tenant_id, outcome, reason, metadata, created_at "
        "FROM core.platform_audit_log WHERE action = :a ORDER BY target_tenant_id NULLS FIRST",
        {"a": EXPIRE},
    )
    assert len(rows) == 3
    run = rows[0]
    assert run[0] == done.run_id and run[2] is None
    assert run[5]["phase"] == "run" and run[5]["deleted_ledger_rows"] == 3
    assert run[5]["eligible_digest"] == report.eligible_digest and run[5]["tenants"] == 2
    per_tenant = {row[2]: row[5] for row in rows[1:]}
    assert set(per_tenant) == {eligible_a, eligible_b}
    assert per_tenant[eligible_a]["deleted_ledger_rows"] == 2
    assert {m["run_id"] for m in per_tenant.values()} == {str(done.run_id)}
    assert {row[1] for row in rows} == {ledger.reporter.user_id}
    assert {row[3] for row in rows} == {"success"}
    assert {row[4] for row in rows} == {"TICKET-9: retention expiry"}
    assert len({row[6] for row in rows}) == 1  # one transaction: one now()
    assert ledger.resource not in str(rows) and "admin" not in str(rows)

    # 5. Nothing is eligible any more: the same confirmation is refused.
    with pytest.raises(LedgerExpiryConfirmationMismatchError):
        _expire(
            ledger,
            *everyone,
            apply=True,
            confirm_rows=3,
            confirm_digest=report.eligible_digest,
        )
    assert [ledger.rows(t) for t in everyone] == [0, 0, 1, 1, 1, 1, 1]


def test_a_wrong_or_stale_confirmation_deletes_nothing(
    ledger: Ledger, platform: PlatformWorld
) -> None:
    tenant = _expired(ledger, migrations=2)
    report = ledger.report(tenant)
    assert report.eligible_ledger_rows == 2
    for rows, digest in ((1, report.eligible_digest), (2, "0" * 64)):
        with pytest.raises(LedgerExpiryConfirmationMismatchError):
            _expire(ledger, tenant, apply=True, confirm_rows=rows, confirm_digest=digest)
    # A hold placed after the report: re-checked under lock, nothing goes.
    hold = place_permission_grant_ledger_hold(
        tenant, reference="LEGAL-LATE", caller=ledger.holder, reason=REASON
    )
    with pytest.raises(LedgerExpiryConfirmationMismatchError):
        _expire(
            ledger,
            tenant,
            apply=True,
            confirm_rows=2,
            confirm_digest=report.eligible_digest,
        )
    assert ledger.rows(tenant) == 2
    denied = platform.audit(EXPIRE, "denied")
    assert [row["reason"] for row in denied] == ["confirmation_mismatch"] * 3
    assert platform.audit(EXPIRE, "success") == []
    # Released, the same confirmation is valid again.
    release_permission_grant_ledger_hold(hold.hold_id, caller=ledger.holder, reason=REASON)
    _expire(ledger, tenant, apply=True, confirm_rows=2, confirm_digest=report.eligible_digest)
    assert ledger.rows(tenant) == 0


def test_apply_without_a_confirmation_is_refused_before_any_read(ledger: Ledger) -> None:
    tenant = _expired(ledger)
    for kwargs in (
        {"apply": True},
        {"apply": True, "confirm_rows": 1},
        {"apply": True, "confirm_rows": 0, "confirm_digest": "0" * 64},
        {"apply": True, "confirm_rows": 1, "confirm_digest": "XYZ"},
        {"confirm_rows": 1, "confirm_digest": "0" * 64},  # a confirmation without apply
    ):
        with pytest.raises(InvalidLedgerRetentionRequestError):
            _expire(ledger, tenant, **kwargs)
    assert ledger.rows(tenant) == 1


# --- who may run it ------------------------------------------------------------------


def test_only_an_operator_holding_the_report_permission_may_run_it(
    ledger: Ledger, platform: PlatformWorld
) -> None:
    tenant = _expired(ledger)
    report = ledger.report(tenant)
    confirm = {
        "apply": True,
        "confirm_rows": report.eligible_ledger_rows,
        "confirm_digest": report.eligible_digest,
    }
    refused = [
        platform.operator([])[0],  # enrolled, no permission
        ledger.operator,  # `platform.permission_grant:apply` only
        ledger.holder,  # `platform.security_retention_hold:manage` only
        platform.operator([P.TENANT_DELETE, P.AUDIT_READ])[0],  # a wrong permission
        UserCaller(platform.user()),  # not an operator
        ServiceAccountCaller(tenant, uuid.uuid4()),
        TENANT_PURGE,  # never part of a purge
    ]
    for caller in refused:
        for kwargs in ({}, confirm):
            with pytest.raises(PlatformNotAuthorizedError):
                _expire(ledger, tenant, caller=caller, **kwargs)
    assert ledger.rows(tenant) == 1
    assert platform.audit(EXPIRE, "success") == []
    denied = platform.audit(EXPIRE, "denied")
    # A person or a system purpose is recorded; a service account cannot be.
    assert len(denied) == 2 * 6
    assert {row["reason"] for row in denied} == {"not_authorized"}


def test_it_refuses_the_application_role_and_never_falls_back(
    ledger: Ledger, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = _expired(ledger)
    report = ledger.report(tenant)
    confirm = {
        "apply": True,
        "confirm_rows": report.eligible_ledger_rows,
        "confirm_digest": report.eligible_digest,
    }
    runtime_url = get_database_config().url
    migrations_url = get_migrations_database_config().url
    try:
        # MIGRATIONS_DATABASE_URL pointed at the application role.
        with monkeypatch.context() as m:
            m.setenv("MIGRATIONS_DATABASE_URL", runtime_url)
            get_migrations_database_config.cache_clear()
            with pytest.raises(UnsafeDatabaseRoleError, match="does not own"):
                _expire(ledger, tenant, **confirm)
        get_migrations_database_config.cache_clear()
        # The migrations role also configured as DATABASE_URL: refused too.
        with monkeypatch.context() as m:
            m.setenv("DATABASE_URL", migrations_url)
            get_database_config.cache_clear()
            with pytest.raises(UnsafeDatabaseRoleError, match="application role"):
                _expire(ledger, tenant, **confirm)
    finally:
        get_migrations_database_config.cache_clear()
        get_database_config.cache_clear()
    assert ledger.rows(tenant) == 1
    assert platform.audit(EXPIRE) == []


def test_the_runtime_role_still_cannot_delete_and_purge_never_does(
    ledger: Ledger,
) -> None:
    tenant = ledger.tenant(migrations=2)
    ledger.purge(tenant)  # the real purge: the rows stay next to the tombstone
    assert ledger.rows(tenant) == 2
    _age(ledger, tenant)
    with (
        pytest.raises(ProgrammingError, match="permission denied"),
        tenant_session_scope(tenant) as session,
    ):
        session.execute(text("DELETE FROM core.permission_grant_applications"))
    assert ledger.rows(tenant) == 2


# --- concurrency with a hold (two connections) -----------------------------------------


def _gate_before(monkeypatch: pytest.MonkeyPatch, module: object, name: str) -> Gate:
    """Stop the thread named "first" just before `module.name(session, ...)`
    runs, inside its transaction, every lock it took still held."""
    gate = Gate("first")
    real = getattr(module, name)

    def wrapped(session: object, *args: object, **kwargs: object) -> object:
        gate.checkpoint(session)
        return real(session, *args, **kwargs)

    monkeypatch.setattr(module, name, wrapped)
    return gate


def test_a_hold_placed_while_the_deletion_holds_the_tenant_waits_for_its_commit(
    ledger: Ledger, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deletion locks the tenant row first and the tenant is eligible at
    that moment: a concurrent hold placement waits on the same row lock,
    the deletion commits (the rows go), and the hold is placed afterwards."""
    import saas_os.core.permission_grants.expiry as expiry_module

    tenant = _expired(ledger, migrations=2)
    report = ledger.report(tenant)
    pause = _gate_before(monkeypatch, expiry_module, "_decide")  # after the tenant lock

    def delete() -> object:
        return _expire(
            ledger,
            tenant,
            apply=True,
            confirm_rows=report.eligible_ledger_rows,
            confirm_digest=report.eligible_digest,
        )

    def hold() -> object:
        return place_permission_grant_ledger_hold(
            tenant, reference="LEGAL-RACE", caller=ledger.holder, reason=REASON
        )

    first, second = run_first_then_second(admin, pause, delete, hold)
    assert "error" not in first and "error" not in second, (first, second)
    assert first["result"].applied is True and first["result"].eligible_ledger_rows == 2
    assert ledger.rows(tenant) == 0
    # The hold exists, placed after the deletion's transaction.
    deleted_at = ledger.platform.scalar(
        "SELECT created_at FROM core.platform_audit_log WHERE id = :i",
        {"i": first["result"].run_id},
    )
    assert second["result"].placed_at > deleted_at


def test_a_deletion_started_while_a_hold_is_being_placed_waits_and_deletes_nothing(
    ledger: Ledger, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hold transaction holds the tenant row lock (hold row flushed,
    not committed): the deletion waits on that lock, then re-decides with
    the hold committed, finds nothing eligible, refuses the confirmation
    and deletes nothing."""
    import saas_os.core.permission_grants.retention as retention_module

    tenant = _expired(ledger, migrations=2)
    report = ledger.report(tenant)
    assert report.eligible_ledger_rows == 2
    pause = _gate_before(monkeypatch, retention_module, "record_platform_event_in_transaction")

    def hold() -> object:
        return place_permission_grant_ledger_hold(
            tenant, reference="LEGAL-RACE", caller=ledger.holder, reason=REASON
        )

    def delete() -> object:
        return _expire(
            ledger,
            tenant,
            apply=True,
            confirm_rows=report.eligible_ledger_rows,
            confirm_digest=report.eligible_digest,
        )

    first, second = run_first_then_second(admin, pause, hold, delete)
    assert "error" not in first, first
    assert isinstance(second.get("error"), LedgerExpiryConfirmationMismatchError), second
    assert ledger.rows(tenant) == 2
    assert ledger.platform.audit(EXPIRE, "success") == []
    assert [row["reason"] for row in ledger.platform.audit(EXPIRE, "denied")] == [
        "confirmation_mismatch"
    ]
