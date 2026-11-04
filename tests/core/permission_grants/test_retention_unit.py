"""Retention eligibility of the permission grant ledger (owner policy of
2026-11-02): the pure decision, without a database. The integration
counterpart is
`tests/core/platform_authority/test_permission_grant_ledger_retention_integration.py`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from saas_os.core.authority import SystemAuthority
from saas_os.core.permission_grants import (
    RETENTION_PERIOD_YEARS,
    InvalidLedgerRetentionRequestError,
    RetentionStatus,
    retention_eligibility,
    retention_expires_at,
)
from saas_os.core.platform_authority import purge_evidence
from saas_os.core.tenancy import TenantStatus

_T = datetime(2024, 3, 15, 12, 30, tzinfo=UTC)
_EXPIRES = datetime(2026, 3, 15, 12, 30, tzinfo=UTC)


def _decide(
    *,
    status: str | None = TenantStatus.PURGED.value,
    evidence: tuple[datetime, ...] = (_T,),
    holds: int = 0,
    now: datetime = _EXPIRES,
):  # type: ignore[no-untyped-def]
    return retention_eligibility(
        tenant_status=status, purge_evidence=evidence, active_holds=holds, now=now
    )


def test_the_period_is_two_years() -> None:
    assert RETENTION_PERIOD_YEARS == 2
    assert retention_expires_at(_T) == _EXPIRES


def test_exactly_two_years_after_the_purge_is_eligible() -> None:
    decision = _decide(now=_EXPIRES)
    assert decision.status is RetentionStatus.ELIGIBLE and decision.eligible
    assert decision.purged_at == _T and decision.expires_at == _EXPIRES


def test_one_microsecond_before_two_years_is_still_retained() -> None:
    decision = _decide(now=_EXPIRES - timedelta(microseconds=1))
    assert decision.status is RetentionStatus.RETENTION_RUNNING and not decision.eligible
    assert decision.expires_at == _EXPIRES


def test_after_two_years_is_eligible() -> None:
    assert _decide(now=_EXPIRES + timedelta(days=400)).eligible


def test_right_after_the_purge_is_retained() -> None:
    assert _decide(now=_T).status is RetentionStatus.RETENTION_RUNNING


def test_the_calendar_is_utc_whatever_the_purge_time_zone() -> None:
    """Review finding 3: a leap-day purge (UTC) read back in a session time
    zone east of UTC is already 1 March locally; local arithmetic would
    expire it a day early. The result is the UTC result, in UTC."""
    utc_purge = datetime(2028, 2, 29, 23, 30, tzinfo=UTC)
    utc_result = retention_expires_at(utc_purge)
    assert utc_result == datetime(2030, 3, 1, 23, 30, tzinfo=UTC)
    for hours in (1, 2, 9, 14, -5, -12):
        local = utc_purge.astimezone(timezone(timedelta(hours=hours)))
        expires = retention_expires_at(local)
        assert expires == utc_result and expires.utcoffset() == timedelta(0)
        assert not _decide(evidence=(local,), now=utc_result - timedelta(seconds=1)).eligible


def test_the_comparison_is_by_instant_not_by_wall_clock() -> None:
    plus_two = timezone(timedelta(hours=2))
    assert _decide(now=_EXPIRES.astimezone(plus_two)).eligible
    assert not _decide(now=(_EXPIRES - timedelta(seconds=1)).astimezone(plus_two)).eligible


def test_a_29_february_purge_expires_on_1_march_never_earlier() -> None:
    leap = datetime(2024, 2, 29, 8, 0, tzinfo=UTC)
    assert retention_expires_at(leap) == datetime(2026, 3, 1, 8, 0, tzinfo=UTC)
    assert not _decide(evidence=(leap,), now=datetime(2026, 2, 28, 23, 59, tzinfo=UTC)).eligible
    assert _decide(evidence=(leap,), now=datetime(2026, 3, 1, 8, 0, tzinfo=UTC)).eligible


@pytest.mark.parametrize(
    "status",
    [
        TenantStatus.PENDING,
        TenantStatus.ACTIVE,
        TenantStatus.SUSPENDED,
        TenantStatus.DELETED,
        TenantStatus.PURGING,
    ],
)
def test_a_tenant_that_is_not_purged_is_never_eligible(status: TenantStatus) -> None:
    """Even with old purge evidence (it cannot exist for these states, but
    the status decides first)."""
    decision = _decide(status=status.value, now=_EXPIRES + timedelta(days=3650))
    assert decision.status is RetentionStatus.NOT_PURGED
    assert decision.purged_at is None and decision.expires_at is None


def test_a_missing_tenant_row_is_never_eligible() -> None:
    decision = _decide(status=None, now=_EXPIRES + timedelta(days=3650))
    assert decision.status is RetentionStatus.TENANT_NOT_FOUND


def test_a_purged_tenant_without_purge_evidence_is_retained() -> None:
    """A purge recorded before the platform row existed: the time is not
    known, so the rows are kept (fail closed)."""
    decision = _decide(evidence=(), now=_EXPIRES + timedelta(days=3650))
    assert decision.status is RetentionStatus.PURGE_TIME_UNKNOWN


def test_two_pieces_of_purge_evidence_are_ambiguous_and_retained() -> None:
    """A second, earlier row (for instance one inserted by hand) cannot
    advance the expiry: two rows retain."""
    earlier = _T - timedelta(days=3650)
    decision = _decide(evidence=(earlier, _T), now=_EXPIRES + timedelta(days=1))
    assert decision.status is RetentionStatus.PURGE_TIME_AMBIGUOUS


def test_an_active_legal_hold_blocks_and_its_release_allows() -> None:
    late = _EXPIRES + timedelta(days=30)
    held = _decide(holds=1, now=late)
    assert held.status is RetentionStatus.LEGAL_HOLD and not held.eligible
    assert held.expires_at == _EXPIRES
    assert _decide(holds=2, now=late).status is RetentionStatus.LEGAL_HOLD
    assert _decide(holds=0, now=late).eligible


def test_a_legal_hold_is_reported_during_the_period_too() -> None:
    assert _decide(holds=1, now=_T).status is RetentionStatus.LEGAL_HOLD


@pytest.mark.parametrize(
    "kwargs",
    [
        {"now": datetime(2026, 3, 15, 12, 30)},  # no offset
        {"evidence": (datetime(2024, 3, 15),)},  # no offset
        {"holds": -1},
        {"holds": True},
        {"evidence": "2024-03-15"},
    ],
)
def test_malformed_input_is_refused(kwargs: dict[str, object]) -> None:
    with pytest.raises(InvalidLedgerRetentionRequestError):
        _decide(**kwargs)  # type: ignore[arg-type]


def test_the_purge_evidence_filter_names_the_purge_purpose() -> None:
    assert purge_evidence.TENANT_PURGE_AUTHORITY == SystemAuthority.TENANT_PURGE.value


# --- the eligible-row digest (owner decision B of 2026-11-02) ---------------------


def test_the_digest_names_exactly_the_eligible_rows_in_any_order() -> None:
    import hashlib
    import json
    import uuid

    from saas_os.core.permission_grants import eligible_ledger_digest

    a, b = uuid.UUID(int=1), uuid.UUID(int=2)
    r1, r2, r3 = uuid.UUID(int=11), uuid.UUID(int=12), uuid.UUID(int=13)
    digest = eligible_ledger_digest({a: [r2, r1], b: [r3]})
    assert digest == eligible_ledger_digest({b: (r3,), a: (r1, r2)})
    expected = json.dumps(
        [[str(a), [str(r1), str(r2)]], [str(b), [str(r3)]]], separators=(",", ":")
    )
    assert digest == hashlib.sha256(expected.encode("ascii")).hexdigest()
    # One row more or less, or a row moved to another tenant, changes it.
    assert digest != eligible_ledger_digest({a: [r1, r2], b: []})
    assert digest != eligible_ledger_digest({a: [r1], b: [r2, r3]})
    assert digest != eligible_ledger_digest({a: [r1, r2], b: [r3], uuid.UUID(int=3): []})
    assert len(digest) == 64 and eligible_ledger_digest({}) != digest
