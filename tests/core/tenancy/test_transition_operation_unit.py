"""The edge selection of `transition_tenant_status`
(docs/ADR/0045-installation-scoped-platform-authority.md section 5b).

The platform operation a transition is authorized as is selected from the
`(from, to)` pair. The selection names every edge of the lifecycle graph
and has no default: a pair it does not list is refused. Before this was
pinned, any unmatched target fell through to the purge operation, which
`SystemCaller(TENANT_PURGE)` is authorized for.
"""

from __future__ import annotations

import uuid
from itertools import product
from typing import Any

import pytest

from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.platform_authority import InvalidPlatformRequestError, operations
from saas_os.core.tenancy import service
from saas_os.core.tenancy.errors import InvalidTenantTransitionError
from saas_os.core.tenancy.lifecycle import _ALLOWED_TRANSITIONS, TenantStatus

_EDGES = {
    (current, target) for current, targets in _ALLOWED_TRANSITIONS.items() for target in targets
}
_PURGE_EDGES = {
    (TenantStatus.DELETED, TenantStatus.PURGING),
    (TenantStatus.PURGING, TenantStatus.PURGED),
}


@pytest.mark.parametrize(("current", "target"), sorted(_EDGES))
def test_every_edge_of_the_graph_has_a_declared_operation(
    current: TenantStatus, target: TenantStatus
) -> None:
    operation, _ = service._transition_operation(current, target)
    assert operation in operations.PLATFORM_OPERATIONS
    # Only the two purge edges are judged as the purge operation.
    assert (operation == operations.TENANT_PURGE_TRANSITION) == ((current, target) in _PURGE_EDGES)


@pytest.mark.parametrize(
    ("current", "target"),
    sorted(set(product(TenantStatus, TenantStatus)) - _EDGES),
)
def test_a_pair_that_is_not_an_edge_has_no_operation(
    current: TenantStatus, target: TenantStatus
) -> None:
    with pytest.raises(InvalidTenantTransitionError):
        service._transition_operation(current, target)


@pytest.mark.parametrize("target", ["active", "purging", "purged", "archived", None, 1])
def test_a_target_that_is_not_a_status_has_no_operation(target: Any) -> None:
    # "purging" equals `TenantStatus.PURGING` as a string and is still refused.
    with pytest.raises(TypeError):
        service._transition_operation(TenantStatus.DELETED, target)
    with pytest.raises(TypeError):
        service._transition_operation(target, TenantStatus.PURGING)


@pytest.mark.parametrize("target", ["active", "purging", "purged", None])
def test_transition_refuses_a_target_that_is_not_a_status_before_any_read(
    target: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_transaction(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a transaction was opened")

    monkeypatch.setattr(service, "session_scope", no_transaction)
    with pytest.raises(InvalidPlatformRequestError):
        service.transition_tenant_status(
            uuid.uuid4(), target, caller=SystemCaller(SystemAuthority.TENANT_PURGE)
        )


# --- the operations a target status can select (the preliminary gate) ---------------


def test_the_candidates_of_a_target_are_exactly_the_operations_of_the_edges_into_it() -> None:
    from saas_os.core.tenancy.service import _candidate_operations, _lifecycle_edges

    edges = _lifecycle_edges()
    for target in TenantStatus:
        into = {operation for (_, to), (operation, _) in edges.items() if to is target}
        candidates = _candidate_operations(target)
        assert len(set(candidates)) == len(candidates)  # no duplicates
        assert set(candidates) == into
        # No edge leads to PENDING, and to nothing else: no candidate, and
        # `transition_tenant_status` refuses the request before reading.
        assert (candidates == ()) is (target is TenantStatus.PENDING)


def test_only_an_active_target_is_ambiguous_and_its_first_candidate_is_activation() -> None:
    from saas_os.core.tenancy.service import _candidate_operations

    assert _candidate_operations(TenantStatus.ACTIVE) == ("tenant.activate", "tenant.reactivate")
    assert _candidate_operations(TenantStatus.SUSPENDED) == ("tenant.suspend",)
    assert _candidate_operations(TenantStatus.DELETED) == ("tenant.delete",)
    assert _candidate_operations(TenantStatus.PURGING) == ("tenant.purge_transition",)
    assert _candidate_operations(TenantStatus.PURGED) == ("tenant.purge_transition",)


def test_every_edge_selects_one_of_its_targets_candidates() -> None:
    """What makes deciding before the status is read sound for a
    single-candidate target: the operation selected under lock is the
    candidate."""
    from saas_os.core.tenancy.service import (
        _candidate_operations,
        _lifecycle_edges,
        _transition_operation,
    )

    for current, target in _lifecycle_edges():
        assert isinstance(current, TenantStatus) and isinstance(target, TenantStatus)
        assert _transition_operation(current, target)[0] in _candidate_operations(target)


@pytest.mark.parametrize("target", ["active", None, 1])
def test_a_candidate_target_that_is_not_a_status_is_a_type_error(target: object) -> None:
    from saas_os.core.tenancy.service import _candidate_operations

    with pytest.raises(TypeError):
        _candidate_operations(target)  # type: ignore[arg-type]
