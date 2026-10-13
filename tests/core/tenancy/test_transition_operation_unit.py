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
