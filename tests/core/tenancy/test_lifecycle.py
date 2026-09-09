"""Tenant lifecycle state-machine tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.1, docs/MULTI-TENANCY.md section 6). Pure unit tests -- no
database needed, `validate_transition` is plain Python.
"""

from __future__ import annotations

import itertools

import pytest
from core.tenancy.errors import InvalidTenantTransitionError
from core.tenancy.lifecycle import TenantStatus, validate_transition

_Transition = tuple[TenantStatus, TenantStatus]

_ALLOWED: set[_Transition] = {
    (TenantStatus.PENDING, TenantStatus.ACTIVE),
    (TenantStatus.PENDING, TenantStatus.DELETED),
    (TenantStatus.ACTIVE, TenantStatus.SUSPENDED),
    (TenantStatus.ACTIVE, TenantStatus.DELETED),
    (TenantStatus.SUSPENDED, TenantStatus.ACTIVE),
    (TenantStatus.SUSPENDED, TenantStatus.DELETED),
    (TenantStatus.DELETED, TenantStatus.PURGED),
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
