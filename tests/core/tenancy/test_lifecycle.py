"""Tenant lifecycle state-machine tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.1, docs/MULTI-TENANCY.md section 6). Pure unit tests -- no
database needed, `validate_transition` is plain Python.
"""

from __future__ import annotations

import itertools

import pytest
from core.tenancy.errors import InvalidTenantTransitionError
from core.tenancy.lifecycle import (
    CLOSED_STATUSES,
    TenantStatus,
    is_closed,
    validate_transition,
)

_Transition = tuple[TenantStatus, TenantStatus]

_ALLOWED: set[_Transition] = {
    (TenantStatus.PENDING, TenantStatus.ACTIVE),
    (TenantStatus.PENDING, TenantStatus.DELETED),
    (TenantStatus.ACTIVE, TenantStatus.SUSPENDED),
    (TenantStatus.ACTIVE, TenantStatus.DELETED),
    (TenantStatus.SUSPENDED, TenantStatus.ACTIVE),
    (TenantStatus.SUSPENDED, TenantStatus.DELETED),
    # PRIV-03 Phase P2: PURGING sits between DELETED and PURGED.
    (TenantStatus.DELETED, TenantStatus.PURGING),
    (TenantStatus.PURGING, TenantStatus.PURGED),
}


def _sort_key(pair: _Transition) -> tuple[str, str]:
    return (pair[0].value, pair[1].value)


@pytest.mark.parametrize("current,target", sorted(_ALLOWED, key=_sort_key))
def test_allowed_transitions_do_not_raise(current: TenantStatus, target: TenantStatus) -> None:
    validate_transition(current, target)  # must not raise


_DISALLOWED: list[_Transition] = sorted(
    ((c, t) for c, t in itertools.product(TenantStatus, TenantStatus) if (c, t) not in _ALLOWED),
    key=_sort_key,
)


@pytest.mark.parametrize("current,target", _DISALLOWED)
def test_every_other_pair_is_rejected(current: TenantStatus, target: TenantStatus) -> None:
    """Exhaustive: every (current, target) pair not explicitly allowed --
    including same-state no-ops, backward moves, and skipping states
    (e.g. pending -> purged directly) -- is rejected. This is what makes
    the state machine's rejection non-vacuous: it is not just "some
    invalid transitions fail," every unlisted pair does.
    """
    with pytest.raises(InvalidTenantTransitionError) as excinfo:
        validate_transition(current, target)
    assert excinfo.value.current_status == current
    assert excinfo.value.target_status == target


def test_purged_is_terminal() -> None:
    for target in TenantStatus:
        with pytest.raises(InvalidTenantTransitionError):
            validate_transition(TenantStatus.PURGED, target)


def test_pending_cannot_be_reached_from_anywhere() -> None:
    for current in TenantStatus:
        if current is TenantStatus.PENDING:
            continue
        with pytest.raises(InvalidTenantTransitionError):
            validate_transition(current, TenantStatus.PENDING)


def test_error_message_names_both_states_not_a_stack_trace_only() -> None:
    with pytest.raises(InvalidTenantTransitionError) as excinfo:
        validate_transition(TenantStatus.PENDING, TenantStatus.PURGED)
    message = str(excinfo.value)
    assert "pending" in message
    assert "purged" in message


# --- PRIV-03 Phase P2: PURGING / PURGED lifecycle ---------------------------
#
# The exhaustive `test_every_other_pair_is_rejected` above already covers
# every rejection below; these named tests exist so each approved invariant
# is individually visible by name, not only as one row of a product.


def test_deleted_to_purging_is_allowed() -> None:
    validate_transition(TenantStatus.DELETED, TenantStatus.PURGING)


def test_purging_to_purged_is_allowed() -> None:
    validate_transition(TenantStatus.PURGING, TenantStatus.PURGED)


def test_deleted_cannot_skip_straight_to_purged() -> None:
    """A tenant must pass through PURGING; DELETED -> PURGED is no longer
    on the graph."""
    with pytest.raises(InvalidTenantTransitionError):
        validate_transition(TenantStatus.DELETED, TenantStatus.PURGED)


@pytest.mark.parametrize("target", [TenantStatus.ACTIVE, TenantStatus.SUSPENDED])
def test_purging_cannot_reopen(target: TenantStatus) -> None:
    with pytest.raises(InvalidTenantTransitionError):
        validate_transition(TenantStatus.PURGING, target)


@pytest.mark.parametrize(
    "target", [TenantStatus.ACTIVE, TenantStatus.SUSPENDED, TenantStatus.DELETED]
)
def test_purged_is_terminal_by_name(target: TenantStatus) -> None:
    with pytest.raises(InvalidTenantTransitionError):
        validate_transition(TenantStatus.PURGED, target)


@pytest.mark.parametrize("source", [TenantStatus.ACTIVE, TenantStatus.SUSPENDED])
def test_purging_is_only_reachable_from_deleted(source: TenantStatus) -> None:
    """A tenant must reach DELETED before entering PURGING -- no shortcut
    from an operational state."""
    with pytest.raises(InvalidTenantTransitionError):
        validate_transition(source, TenantStatus.PURGING)


def test_pre_p2_transitions_are_unchanged() -> None:
    """Every transition that existed before P2 is still allowed, byte for
    byte -- P2 only inserted PURGING between DELETED and PURGED."""
    for current, target in {
        (TenantStatus.PENDING, TenantStatus.ACTIVE),
        (TenantStatus.PENDING, TenantStatus.DELETED),
        (TenantStatus.ACTIVE, TenantStatus.SUSPENDED),
        (TenantStatus.ACTIVE, TenantStatus.DELETED),
        (TenantStatus.SUSPENDED, TenantStatus.ACTIVE),
        (TenantStatus.SUSPENDED, TenantStatus.DELETED),
    }:
        validate_transition(current, target)


def test_closed_statuses_are_exactly_deleted_purging_purged() -> None:
    assert CLOSED_STATUSES == frozenset(
        {TenantStatus.DELETED, TenantStatus.PURGING, TenantStatus.PURGED}
    )


@pytest.mark.parametrize("status", list(TenantStatus))
def test_is_closed_matches_closed_statuses(status: TenantStatus) -> None:
    assert is_closed(status) is (status in CLOSED_STATUSES)


def test_open_statuses_are_exactly_pending_active_suspended() -> None:
    """The fence must not accidentally mean `!= PURGED`: DELETED and PURGING
    are closed too, and every other status is open."""
    assert {s for s in TenantStatus if not is_closed(s)} == {
        TenantStatus.PENDING,
        TenantStatus.ACTIVE,
        TenantStatus.SUSPENDED,
    }
