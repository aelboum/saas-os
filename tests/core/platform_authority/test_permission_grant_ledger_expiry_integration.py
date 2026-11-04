"""Deleting expired permission grant ledger rows: the manual migrations-role
procedure of owner decision B of 2026-11-02. PostgreSQL.

Deletion is disabled (owner decision of 2026-11-02, separation of duties):
`test_deletion_is_disabled_and_refused_before_the_run_connects` pins that.
Since the owner decisions of 2026-11-03 a deletion needs an execution
authorisation made through the authenticated platform-admin API; the
declared-operator form below only reports, and its `apply` is refused even
with the gate switched on in-process (`deletion_enabled`). The deletion of
exactly the bound rows, its audit rows, stale confirmations and the races
with hold placement and release are tested through that authorised path in
`test_permission_grant_ledger_approval_integration.py`
(`test_the_full_path_binds_verifies_refuses_apply_and_with_the_gate_on_deletes_once`,
`test_a_request_binds_an_eligible_scope_with_its_count_and_digest`,
`test_execution_refuses_a_changed_scope`,
`test_a_hold_placed_while_the_execution_holds_the_tenant_waits_for_its_commit`,
`test_a_hold_placed_before_the_execution_takes_the_tenant_is_seen`,
`test_a_release_started_while_the_execution_holds_the_tenant_waits_for_it`).

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
from platform_helpers import PlatformWorld
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from test_permission_grant_ledger_retention_integration import REASON, Ledger

from saas_os.core.authority import ServiceAccountCaller, UserCaller
from saas_os.core.permission_grants import (
    InvalidLedgerRetentionRequestError,
    LedgerDeletionDisabledError,
    RetentionStatus,
    place_permission_grant_ledger_hold,
)
from saas_os.core.permission_grants import expiry as expiry_gate
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


@pytest.fixture
def deletion_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """In-process only: the shipped constant stays `False`."""
    monkeypatch.setattr(expiry_gate, "_DELETION_ENABLED", True)


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


def test_the_dry_run_reports_exactly_the_eligible_rows_and_the_declared_apply_is_refused(
    ledger: Ledger, scene: Scene, platform: PlatformWorld, deletion_enabled: None
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

    # 3. The declared form can never delete, even with the gate on: a
    # deletion needs an execution authorisation made through the API.
    with pytest.raises(InvalidLedgerRetentionRequestError, match="execution authorisation"):
        _expire(
            ledger,
            *everyone,
            apply=True,
            confirm_rows=report.eligible_ledger_rows,
            confirm_digest=report.eligible_digest,
        )
    assert [ledger.rows(t) for t in everyone] == [2, 1, 1, 1, 1, 1, 1]
    assert platform.audit(EXPIRE, "success") == []
    assert [row["reason"] for row in platform.audit(EXPIRE, "denied")] == ["invalid_request"]
    assert ledger.resource not in str(platform.audit(EXPIRE)) and "admin" not in str(
        platform.audit(EXPIRE)
    )


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


def test_deletion_is_disabled_and_refused_before_the_run_connects(
    ledger: Ledger, platform: PlatformWorld
) -> None:
    """Separation of duties: every operator id is declared, not
    authenticated, so a deletion cannot be verifiably approved by someone
    other than the person who released a hold. `apply` with a correct,
    current confirmation is refused with `deletion_disabled`; nothing is
    deleted; one `denied` row; the dry run still reports."""
    assert expiry_gate._DELETION_ENABLED is False  # pyright: ignore[reportPrivateUsage]
    tenant = _expired(ledger, migrations=2)
    report = _expire(ledger, tenant)
    assert report.eligible_ledger_rows == 2
    with pytest.raises(LedgerDeletionDisabledError):
        _expire(
            ledger,
            tenant,
            apply=True,
            confirm_rows=report.eligible_ledger_rows,
            confirm_digest=report.eligible_digest,
        )
    assert ledger.rows(tenant) == 2
    assert platform.audit(EXPIRE, "success") == []
    denied = platform.audit(EXPIRE, "denied")
    assert [(row["reason"], row["actor_user_id"]) for row in denied] == [
        ("deletion_disabled", ledger.reporter.user_id)
    ]
    # The hold manager, an owner-like operator, anyone: the same refusal.
    for caller in (ledger.holder, platform.operator(list(P))[0]):
        with pytest.raises(LedgerDeletionDisabledError):
            _expire(
                ledger,
                tenant,
                caller=caller,
                apply=True,
                confirm_rows=report.eligible_ledger_rows,
                confirm_digest=report.eligible_digest,
            )
    assert ledger.rows(tenant) == 2
    assert platform.audit(EXPIRE, "success") == []


# --- who may run it ------------------------------------------------------------------


def test_only_an_operator_holding_the_report_permission_may_run_it(
    ledger: Ledger, platform: PlatformWorld, deletion_enabled: None
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
        with pytest.raises(PlatformNotAuthorizedError):
            _expire(ledger, tenant, caller=caller)
        # The declared apply is refused before anything connects, whoever
        # is named: no declared operator ever deletes (2026-11-03).
        with pytest.raises(InvalidLedgerRetentionRequestError):
            _expire(ledger, tenant, caller=caller, **confirm)
    assert ledger.rows(tenant) == 1
    assert platform.audit(EXPIRE, "success") == []
    denied = platform.audit(EXPIRE, "denied")
    # A person or a system purpose is recorded; a service account cannot be.
    assert (
        sorted(row["reason"] for row in denied) == ["invalid_request"] * 6 + ["not_authorized"] * 6
    )


def test_it_refuses_the_application_role_and_never_falls_back(
    ledger: Ledger, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = _expired(ledger)
    # The dry run opens the migrations-role connection the deletion would.
    confirm: dict[str, object] = {}
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
