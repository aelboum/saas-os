"""The declared platform operation table and the system-purpose matrix
(ADR-0045 sections 5a and 5b) -- hermetic.

The table in code is compared, row by row, with a literal copy of the
ADR's operation inventory written in this file. A change to either is a
visible diff in two places.

The purpose matrix is asserted cell by cell: every `SystemAuthority`
against every operation. One extra purpose added to any row fails here.
"""

from __future__ import annotations

import pytest

from saas_os.core.authority import SystemAuthority
from saas_os.core.platform_authority import PLATFORM_OPERATIONS, PlatformPermission

_PROV = SystemAuthority.PROVISIONING
_PURGE = SystemAuthority.TENANT_PURGE
_BOOT = SystemAuthority.PLATFORM_BOOTSTRAP

# ADR-0045 section 5b: key -> (permission, accepted system purposes, audit action).
_INVENTORY: dict[str, tuple[str | None, frozenset[SystemAuthority], str]] = {
    "tenant.read": ("platform.tenant:read", frozenset(), "platform.tenant.read"),
    "user.read": ("platform.user:read", frozenset(), "platform.user.read"),
    "operator.read": ("platform.operator:read", frozenset(), "platform.operator.read"),
    "audit.read": ("platform.audit:read", frozenset(), "platform.audit.read"),
    "billing.read": ("platform.billing:read", frozenset(), "platform.billing.read"),
    "feature_flag.read": (
        "platform.feature_flag:read",
        frozenset(),
        "platform.feature_flag.read",
    ),
    "ai_config.read": ("platform.ai_config:read", frozenset(), "platform.ai_config.read"),
    "ai_usage.read": ("platform.ai_usage:read", frozenset(), "platform.ai_usage.read"),
    "tenant.create_root": ("platform.tenant:create", frozenset({_PROV}), "platform.tenant.create"),
    "tenant.create_child": (
        "platform.tenant:create",
        frozenset({_PROV}),
        "platform.tenant.create",
    ),
    "tenant.activate": ("platform.tenant:create", frozenset({_PROV}), "platform.tenant.activate"),
    "tenant.suspend": ("platform.tenant:suspend", frozenset(), "platform.tenant.suspend"),
    "tenant.reactivate": ("platform.tenant:reactivate", frozenset(), "platform.tenant.reactivate"),
    "tenant.move": ("platform.tenant:move", frozenset(), "platform.tenant.move"),
    "tenant.delete": ("platform.tenant:delete", frozenset(), "platform.tenant.delete"),
    "tenant.purge_transition": (None, frozenset({_PURGE}), "platform.tenant.purge_transition"),
    "user.deactivate": ("platform.user:deactivate", frozenset(), "platform.user.deactivate"),
    "user.reactivate": ("platform.user:reactivate", frozenset(), "platform.user.reactivate"),
    "session.revoke": ("platform.session:revoke", frozenset(), "platform.session.revoke"),
    "api_key.revoke": ("platform.api_key:revoke", frozenset(), "platform.api_key.revoke"),
    "feature_flag.define": (
        "platform.feature_flag:define",
        frozenset({_PROV}),
        "platform.feature_flag.define",
    ),
    "feature_flag.override": (
        "platform.feature_flag:override",
        frozenset(),
        "platform.feature_flag.override",
    ),
    # ADR-0054 AI-C: the AI configuration mutations.
    "ai_provider.configure": (
        "platform.ai_provider:manage",
        frozenset(),
        "platform.ai_provider.configure",
    ),
    "ai_endpoint_trust.configure": (
        "platform.ai_endpoint_trust:manage",
        frozenset(),
        "platform.ai_endpoint_trust.configure",
    ),
    "ai_policy.configure": (
        "platform.ai_policy:manage",
        frozenset(),
        "platform.ai_policy.configure",
    ),
    # ADR-0045 amendment of 2026-10-31: replay of dead-lettered outbox events.
    "outbox.replay": ("platform.outbox:replay", frozenset(), "platform.outbox.replay"),
    "operator.enroll": (
        "platform.authority:manage",
        frozenset({_BOOT}),
        "platform.operator.enroll",
    ),
    "operator.suspend": (
        "platform.authority:manage",
        frozenset({_BOOT}),
        "platform.operator.suspend",
    ),
    "operator.reactivate": (
        "platform.authority:manage",
        frozenset(),
        "platform.operator.reactivate",
    ),
    "operator.revoke": ("platform.authority:manage", frozenset(), "platform.operator.revoke"),
    "grant.create": ("platform.authority:manage", frozenset({_BOOT}), "platform.grant.create"),
    "grant.revoke": ("platform.authority:manage", frozenset(), "platform.grant.revoke"),
}


def test_the_table_is_exactly_the_reviewed_inventory() -> None:
    assert len(_INVENTORY) == 32
    actual = {
        key: (
            row.permission.value if row.permission is not None else None,
            row.system_authorities,
            row.audit_action,
        )
        for key, row in PLATFORM_OPERATIONS.items()
    }
    assert actual == _INVENTORY
    assert all(row.key == key for key, row in PLATFORM_OPERATIONS.items())


def test_every_permission_appears_and_none_outside_the_vocabulary() -> None:
    used = {row.permission for row in PLATFORM_OPERATIONS.values() if row.permission is not None}
    assert used == set(PlatformPermission)


def test_audit_actions_are_platform_namespaced_and_distinct_except_tenant_create() -> None:
    actions = [row.audit_action for row in PLATFORM_OPERATIONS.values()]
    assert all(action.startswith("platform.") for action in actions)
    # `tenant.create_root` and `tenant.create_child` share one action by design.
    assert len(set(actions)) == len(actions) - 1
    assert actions.count("platform.tenant.create") == 2


@pytest.mark.parametrize("purpose", list(SystemAuthority))
@pytest.mark.parametrize("operation", sorted(_INVENTORY))
def test_purpose_matrix_cell(operation: str, purpose: SystemAuthority) -> None:
    """Each purpose is accepted by exactly the operations the reviewed
    inventory names, and by no other."""
    expected = purpose in _INVENTORY[operation][1]
    assert (purpose in PLATFORM_OPERATIONS[operation].system_authorities) is expected


def test_billing_operations_purpose_reaches_no_platform_operation() -> None:
    assert not any(
        SystemAuthority.BILLING_OPERATIONS in row.system_authorities
        for row in PLATFORM_OPERATIONS.values()
    )


def test_platform_bootstrap_reaches_exactly_enroll_grant_and_suspend() -> None:
    reached = {key for key, row in PLATFORM_OPERATIONS.items() if _BOOT in row.system_authorities}
    assert reached == {"operator.enroll", "operator.suspend", "grant.create"}


def test_provisioning_reaches_no_authority_user_session_key_or_oversight_operation() -> None:
    """Provisioning is tenant creation, first activation and flag
    definition. It can never suspend, reactivate, move or delete a tenant,
    touch a user, a session or an API key, override a flag, manage
    platform authority, read oversight data, or purge."""
    reached = {key for key, row in PLATFORM_OPERATIONS.items() if _PROV in row.system_authorities}
    assert reached == {
        "tenant.create_root",
        "tenant.create_child",
        "tenant.activate",
        "feature_flag.define",
    }


def test_tenant_purge_reaches_exactly_the_purge_transitions() -> None:
    reached = {key for key, row in PLATFORM_OPERATIONS.items() if _PURGE in row.system_authorities}
    assert reached == {"tenant.purge_transition"}


def test_only_the_purge_transition_has_no_permission() -> None:
    """An operation with no permission is one no person may perform."""
    assert [key for key, row in PLATFORM_OPERATIONS.items() if row.permission is None] == [
        "tenant.purge_transition"
    ]


def test_the_table_is_read_only() -> None:
    with pytest.raises(TypeError):
        PLATFORM_OPERATIONS["x"] = PLATFORM_OPERATIONS["grant.create"]  # type: ignore[index]


# --- refusal labels that are not operations ------------------------------------------


def test_the_non_operation_refusal_labels_are_exactly_the_reviewed_four() -> None:
    """A closed set, written out here as it is in the code: a fifth label
    is a visible diff in two places."""
    from saas_os.core.platform_authority import NON_OPERATION_REFUSALS

    assert {key: row.audit_action for key, row in NON_OPERATION_REFUSALS.items()} == {
        "user.erase": "platform.user.erase",
        "tenant.transition": None,
        "platform.bootstrap": None,
        "platform.recover": None,
    }
    assert all(key == row.label for key, row in NON_OPERATION_REFUSALS.items())


def test_no_label_is_both_an_operation_and_a_non_operation() -> None:
    from saas_os.core.platform_authority import NON_OPERATION_REFUSALS

    assert not NON_OPERATION_REFUSALS.keys() & PLATFORM_OPERATIONS.keys()


def test_user_erasure_is_not_a_platform_operation() -> None:
    """ADR-0045 sections 4 and 7: there is no permission for erasure and
    nobody is authorized for it through the table. Its refusal label
    exists so that the refusal can be recorded, not so that it can be
    granted."""
    from saas_os.core.platform_authority import UnknownPlatformOperationError, platform_operation

    assert "user.erase" not in PLATFORM_OPERATIONS
    assert not any(
        row.audit_action == "platform.user.erase" for row in PLATFORM_OPERATIONS.values()
    )
    assert not any("erase" in permission.value for permission in PlatformPermission)
    with pytest.raises(UnknownPlatformOperationError):
        platform_operation("user.erase")


def test_a_non_operation_action_never_collides_with_an_operation_or_an_attempt_action() -> None:
    from saas_os.core.platform_authority import NON_OPERATION_REFUSALS, oversight_attempt_action

    taken = {row.audit_action for row in PLATFORM_OPERATIONS.values()}
    taken |= {oversight_attempt_action(key) for key in PLATFORM_OPERATIONS}
    own = [row.audit_action for row in NON_OPERATION_REFUSALS.values() if row.audit_action]
    assert len(set(own)) == len(own) and not taken & set(own)


def test_is_refusal_label_accepts_both_mappings_and_nothing_else() -> None:
    from saas_os.core.platform_authority import NON_OPERATION_REFUSALS, is_refusal_label

    assert all(is_refusal_label(key) for key in PLATFORM_OPERATIONS)
    assert all(is_refusal_label(key) for key in NON_OPERATION_REFUSALS)
    for other in ("user.purge", "tenant.transition ", "", None, 3, b"user.erase"):
        assert not is_refusal_label(other)


def test_the_non_operation_mapping_is_read_only() -> None:
    from saas_os.core.platform_authority import NON_OPERATION_REFUSALS

    with pytest.raises(TypeError):
        NON_OPERATION_REFUSALS["x"] = NON_OPERATION_REFUSALS["user.erase"]  # type: ignore[index]
