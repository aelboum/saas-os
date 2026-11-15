"""Audit identity phase P2, hermetic: the exact two-year rule, the canonical
set digests (owner decision D8; proposal section 4.11), the `--apply` gate
(owner decision O9) and the command-line checks of the expiry command and the
place-only hold command (owner decision O8).

The rule's vectors are the decision record's worked values
(docs/architecture/AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md, "Two-year
expiry calculation").
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import uuid
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path

import pytest

import saas_os.core.audit_identity.expiry as expiry
from saas_os.core.audit_identity import (
    AuditIdentityExpiryDisabledError,
    InvalidAuditIdentityRequestError,
    hold_set_digest,
    reference_set_digest,
)
from saas_os.core.audit_identity.expiry import ExpiryConfirmation, expire_audit_identity_links
from saas_os.core.audit_identity.plan import (
    link_day_bound,
    record_expires_at,
    record_past_retention,
)
from saas_os.core.authority import UserCaller
from saas_os.ops import audit_identity_expiry as command
from saas_os.ops import operator_cli

_ROOT = Path(__file__).resolve().parents[3]


# --- the exact two-year rule ------------------------------------------------------------


@pytest.mark.parametrize(
    ("created_at", "expires_at"),
    [
        # 2028-02-29 12:00 UTC: 730 days.
        (datetime(2028, 2, 29, 12, tzinfo=UTC), datetime(2030, 2, 28, 12, tzinfo=UTC)),
        # 2028-02-28 12:00 UTC: 731 days, the same instant as the record above.
        (datetime(2028, 2, 28, 12, tzinfo=UTC), datetime(2030, 2, 28, 12, tzinfo=UTC)),
        # Across 29 February 2028: 731 days.
        (datetime(2027, 3, 1, tzinfo=UTC), datetime(2029, 3, 1, tzinfo=UTC)),
        # UTC first: 2028-02-29 00:30+01 is 2028-02-28 23:30 UTC.
        (
            datetime(2028, 2, 29, 0, 30, tzinfo=timezone(timedelta(hours=1))),
            datetime(2030, 2, 28, 23, 30, tzinfo=UTC),
        ),
        (
            datetime(2028, 12, 31, 23, 59, 59, 999999, tzinfo=UTC),
            datetime(2030, 12, 31, 23, 59, 59, 999999, tzinfo=UTC),
        ),
    ],
)
def test_the_exact_rule_matches_the_decision_records_vectors(
    created_at: datetime, expires_at: datetime
) -> None:
    assert record_expires_at(created_at) == expires_at
    assert record_expires_at(created_at).utcoffset() == timedelta(0)


def test_the_boundary_is_inclusive_and_carries_one_day_of_margin() -> None:
    created = datetime(2027, 6, 1, 8, tzinfo=UTC)
    boundary = datetime(2029, 6, 2, 8, tzinfo=UTC)  # E(r) + 1 day
    assert record_past_retention(created, boundary)
    assert not record_past_retention(created, boundary - timedelta(microseconds=1))


def test_a_time_without_an_offset_is_refused() -> None:
    with pytest.raises(InvalidAuditIdentityRequestError):
        record_expires_at(datetime(2028, 1, 1))  # noqa: DTZ001 -- the naive value under test


@pytest.mark.parametrize(
    ("day", "bound"),
    [
        (date(2026, 11, 14), datetime(2028, 11, 16, tzinfo=UTC)),
        # A leap day: 2028-02-29 + 2 years is 2030-02-28, then two days.
        (date(2028, 2, 29), datetime(2030, 3, 2, tzinfo=UTC)),
        # Not `(day + 1) + 2 years`: that would be 2030-02-28 00:00, earlier
        # than the expiry of a record made at 2028-02-28 23:00.
        (date(2028, 2, 28), datetime(2030, 3, 2, tzinfo=UTC)),
    ],
)
def test_the_day_bound_is_two_years_and_two_days(day: date, bound: datetime) -> None:
    assert link_day_bound(day) == bound


def test_no_record_of_a_day_expires_after_its_links_day_bound() -> None:
    """For the last instant of a day, the record's expiry plus the margin is
    at or before the link's day bound: the day bound never deletes a link
    whose records are still in retention."""
    for day in (date(2028, 2, 28), date(2028, 2, 29), date(2027, 12, 31), date(2026, 3, 1)):
        latest = datetime.combine(day, datetime.max.time(), tzinfo=UTC)
        assert record_expires_at(latest) + timedelta(days=1) <= link_day_bound(day)


# --- the canonical digests (D8) -----------------------------------------------------------

_A = "00000000-0000-4000-8000-000000000001"
_B = "ffffffff-0000-4000-8000-000000000002"


def _sha(message: str) -> str:
    return hashlib.sha256(message.encode("ascii")).hexdigest()


def test_the_empty_set_has_a_fixed_digest() -> None:
    assert reference_set_digest("platform", []) == _sha(
        "saas-os/audit-subject-ref-set/v1\nplatform\n0\n"
    )


def test_one_reference_and_byte_order() -> None:
    assert reference_set_digest("platform", [_A]) == _sha(
        f"saas-os/audit-subject-ref-set/v1\nplatform\n1\n{_A}\n"
    )
    expected = _sha(f"saas-os/audit-subject-ref-set/v1\nplatform\n2\n{_A}\n{_B}\n")
    assert reference_set_digest("platform", [_B, _A]) == expected
    assert reference_set_digest("platform", [uuid.UUID(_B), uuid.UUID(_A)]) == expected


def test_a_duplicate_or_a_non_canonical_reference_is_refused() -> None:
    for items in ([_A, _A], [_B.upper()], ["{" + _A + "}"], ["not-a-uuid"], [7]):
        with pytest.raises(InvalidAuditIdentityRequestError):
            reference_set_digest("platform", items)


def test_the_scope_and_the_kind_are_bound_into_the_message() -> None:
    tenant = "tenant:" + str(uuid.UUID(int=7))
    assert reference_set_digest("platform", [_A]) != reference_set_digest(tenant, [_A])
    assert reference_set_digest("platform", [_A]) != hold_set_digest("platform", [_A])
    assert hold_set_digest("platform", []) == _sha(
        "saas-os/audit-identity-hold-set/v1\nplatform\n0\n"
    )
    with pytest.raises(InvalidAuditIdentityRequestError):
        reference_set_digest("elsewhere", [_A])


# --- the --apply gate (O9) ----------------------------------------------------------------


def test_the_apply_gate_is_a_literal_false() -> None:
    tree = ast.parse(inspect.getsource(expiry))
    assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_APPLY_ENABLED" for t in node.targets)
    ]
    assert len(assignments) == 1
    value = assignments[0].value
    assert isinstance(value, ast.Constant) and value.value is False
    assert expiry._APPLY_ENABLED is False


def _confirmation(**changes: object) -> ExpiryConfirmation:
    values: dict[str, object] = {
        "rows": 0,
        "digest": "0" * 64,
        "holds": "0" * 64,
        "unlinks": 0,
        "markers": 0,
    }
    values.update(changes)
    return ExpiryConfirmation(**values)  # type: ignore[arg-type]


def test_apply_is_refused_before_any_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_connection(**_: object) -> object:
        raise AssertionError("connected")

    monkeypatch.setattr(expiry, "migrations_role_session_scope", no_connection)
    with pytest.raises(AuditIdentityExpiryDisabledError):
        expire_audit_identity_links(
            caller=UserCaller(uuid.uuid4()),
            reason="TICKET-9: expiry",
            apply=True,
            confirmation=_confirmation(),
        )


def test_no_setting_or_environment_variable_names_the_gate() -> None:
    source = inspect.getsource(expiry)
    assert "os.environ" not in source and "get_settings" not in source


def test_a_confirmation_goes_with_apply_only() -> None:
    with pytest.raises(InvalidAuditIdentityRequestError):
        expiry._validated_confirmation(False, _confirmation())
    with pytest.raises(InvalidAuditIdentityRequestError):
        expiry._validated_confirmation(True, None)
    with pytest.raises(InvalidAuditIdentityRequestError):
        expiry._validated_confirmation(True, _confirmation(rows=-1))
    with pytest.raises(InvalidAuditIdentityRequestError):
        expiry._validated_confirmation(True, _confirmation(digest="X" * 64))
    with pytest.raises(InvalidAuditIdentityRequestError):
        expiry._validated_confirmation(True, _confirmation(markers=True))


# --- the commands ---------------------------------------------------------------------------


def _run(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setenv("ENVIRONMENT", "test")
    return command.main(argv)


def test_the_expiry_command_refuses_partial_confirmations(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    operator = str(uuid.uuid4())
    partial = ["--operator", operator, "--reason", "T-1", "--apply", "--confirm-rows", "1"]
    assert _run(partial, monkeypatch) == 2
    without_apply = ["--operator", operator, "--reason", "T-1", "--confirm-rows", "1"]
    assert _run(without_apply, monkeypatch) == 2
    assert "invalid input" in capsys.readouterr().err


def test_the_expiry_commands_apply_exits_one_without_connecting(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def no_connection(**_: object) -> object:
        raise AssertionError("connected")

    monkeypatch.setattr(expiry, "migrations_role_session_scope", no_connection)
    argv = [
        "--operator",
        str(uuid.uuid4()),
        "--reason",
        "T-1",
        "--apply",
        "--confirm-rows",
        "0",
        "--confirm-digest",
        "0" * 64,
        "--confirm-holds",
        "0" * 64,
        "--confirm-unlinks",
        "0",
        "--confirm-markers",
        "0",
    ]
    assert _run(argv, monkeypatch) == 1
    assert capsys.readouterr().err.strip() == "failed: AuditIdentityExpiryDisabledError"


def _release_paths(commands: set[str], source: str) -> list[str]:
    """Command names, other than the place command, that touch audit identity
    holds, plus any reference to the release function."""
    found = [
        name for name in commands if "audit-identity" in name and name != "hold-audit-identity"
    ]
    if "release_audit_identity_hold" in source:
        found.append("release_audit_identity_hold")
    return found


def test_the_operator_command_can_place_a_hold_but_has_no_release_path() -> None:
    """Owner decision O8: a command may only place a hold."""
    commands = set(operator_cli._COMMANDS)
    assert "hold-audit-identity" in commands
    source = (_ROOT / "saas_os" / "ops" / "operator_cli.py").read_text(encoding="utf-8")
    assert _release_paths(commands, source) == []


def test_the_no_release_scan_catches_a_release_path() -> None:
    """Negative control: the same scan over a command set and a source that
    add a release path."""
    assert _release_paths({"hold-audit-identity", "release-audit-identity"}, "") == [
        "release-audit-identity"
    ]
    assert _release_paths(
        {"hold-audit-identity"},
        "from saas_os.core.audit_identity import release_audit_identity_hold\n",
    ) == ["release_audit_identity_hold"]
