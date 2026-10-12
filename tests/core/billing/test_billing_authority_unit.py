"""Phase 5.3 step 1 -- billing authority convergence, without a database
(docs/ADR/0031-foundation-authority-and-evidence.md, "Amendment
(2026-10-02)").

- Every billing permission is classified as exactly one of read or
  mutation, and support access is excluded from exactly the mutations.
- The billing caller model: typed callers, the single accepted system
  purpose, and the deprecated compatibility callers mapping onto them.
- Static shape of every billing mutation entry point: the caller is
  checked first, and each final transaction authorizes and audits inside
  the same `tenant_session_scope()` block.
"""

from __future__ import annotations

import ast
import inspect
import uuid
from pathlib import Path
from typing import Any

import pytest

from saas_os.core.authority import ServiceAccountCaller, SystemAuthority, SystemCaller, UserCaller
from saas_os.core.billing import authorization, commercial, parties
from saas_os.core.billing.authorization import (
    BILLING_PERMISSIONS,
    BILLING_SYSTEM_AUTHORITY,
    BillingActor,
    authorize_billing,
    require_billing_caller,
    trusted_system,
)
from saas_os.core.billing.errors import BillingActorRequiredError, BillingNotAuthorizedError
from saas_os.core.rbac.authorization import (
    _SUPPORT_ACCESS_EXCLUDED_ACTIONS,
    BILLING_MUTATION_ACTIONS,
)

_SESSION: Any = object()


# --- Read / mutation classification ------------------------------------------------


def test_every_billing_permission_is_exactly_a_read_or_a_mutation() -> None:
    permissions = set(BILLING_PERMISSIONS)
    reads = {p for p in permissions if p[1] == "read"}
    assert BILLING_MUTATION_ACTIONS <= permissions
    assert reads.isdisjoint(BILLING_MUTATION_ACTIONS)
    assert reads | BILLING_MUTATION_ACTIONS == permissions


def test_support_access_is_excluded_from_exactly_the_billing_mutations() -> None:
    assert _SUPPORT_ACCESS_EXCLUDED_ACTIONS == BILLING_MUTATION_ACTIONS
    assert BILLING_MUTATION_ACTIONS == {
        ("billing.subscription", "create"),
        ("billing.subscription", "change"),
        ("billing.subscription", "cancel"),
        ("billing.subscription", "reactivate"),
        ("billing.account", "charge"),
        ("billing.account", "manage"),
        ("billing.catalog", "manage"),
        ("billing.merchant", "manage"),
    }
    assert not any(action == "read" for _, action in _SUPPORT_ACCESS_EXCLUDED_ACTIONS)


# --- Caller model ---------------------------------------------------------------------


def _forbid_can(monkeypatch: pytest.MonkeyPatch) -> None:
    def _must_not_be_called(**_: object) -> bool:
        raise AssertionError("can() must not be evaluated")

    monkeypatch.setattr(authorization, "can", _must_not_be_called)
    monkeypatch.setattr(authorization, "register_permission", lambda *_, **__: None)


def test_billing_system_authority_is_the_typed_billing_purpose() -> None:
    assert BILLING_SYSTEM_AUTHORITY is SystemAuthority.BILLING_OPERATIONS
    assert SystemAuthority.BILLING_OPERATIONS.value == "billing_operations"


def test_the_billing_system_purpose_skips_can(monkeypatch: pytest.MonkeyPatch) -> None:
    _forbid_can(monkeypatch)
    caller = SystemCaller(SystemAuthority.BILLING_OPERATIONS)
    authorized = authorize_billing(
        caller, [(uuid.uuid4(), "billing.account", "charge")], operation="op", session=_SESSION
    )
    assert authorized.caller is caller and authorized.audit_note == {}


@pytest.mark.parametrize("purpose", [SystemAuthority.PROVISIONING, SystemAuthority.TENANT_PURGE])
def test_any_other_system_purpose_is_denied(
    monkeypatch: pytest.MonkeyPatch, purpose: SystemAuthority
) -> None:
    _forbid_can(monkeypatch)
    with pytest.raises(BillingNotAuthorizedError):
        authorize_billing(SystemCaller(purpose), [], operation="op", session=_SESSION)


def test_a_system_purpose_cannot_be_given_as_text() -> None:
    with pytest.raises(TypeError):
        SystemCaller("billing_operations")  # type: ignore[arg-type]


def test_service_account_callers_are_not_accepted() -> None:
    with pytest.raises(BillingActorRequiredError):
        require_billing_caller(ServiceAccountCaller(uuid.uuid4(), uuid.uuid4()))


def test_user_caller_is_evaluated_by_can_in_the_given_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[object] = []

    def _fake_can(*, session: object, **_: object) -> bool:
        seen.append(session)
        return True

    monkeypatch.setattr(authorization, "can", _fake_can)
    monkeypatch.setattr(authorization, "register_permission", lambda *_, **__: None)
    caller = UserCaller(uuid.uuid4())
    checks = [(uuid.uuid4(), "billing.subscription", "cancel")]
    assert authorize_billing(caller, checks, operation="op", session=_SESSION).caller is caller
    assert seen == [_SESSION]


def test_billing_actor_maps_to_exactly_its_user_caller() -> None:
    user_id = uuid.uuid4()
    authorized = require_billing_caller(BillingActor.user(user_id))
    assert authorized.caller == UserCaller(user_id) and authorized.audit_note == {}


@pytest.mark.parametrize(
    "reason", ["provisioning", "tenant_purge", "admin", "SystemAuthority.PROVISIONING"]
)
def test_a_trusted_system_reason_never_selects_an_authority(reason: str) -> None:
    with pytest.warns(DeprecationWarning):
        caller = trusted_system(reason)
    authorized = require_billing_caller(caller)
    assert authorized.caller == SystemCaller(SystemAuthority.BILLING_OPERATIONS)
    assert authorized.audit_note == {"trusted_system_reason": reason}


# --- Static shape of every billing mutation entry point -------------------------------

_ENTRY_POINTS: dict[object, tuple[str, ...]] = {
    parties: (
        "create_merchant_account",
        "set_merchant_account_status",
        "get_or_create_billing_account",
    ),
    commercial: (
        "_create_commercial_subscription",
        "reconcile_subscription_status",
        "cancel_commercial_subscription",
        "reconcile_legacy_subscription",
    ),
}
# The transactions that persist a billing mutation: each must authorize and
# audit inside one `tenant_session_scope()` block.
_FINAL_TRANSACTIONS: dict[object, tuple[str, ...]] = {
    parties: (
        "create_merchant_account",
        "set_merchant_account_status",
        "get_or_create_billing_account",
    ),
    commercial: (
        "_insert_pending",
        "_apply_provider_state",
        "cancel_commercial_subscription",
        "reconcile_legacy_subscription",
    ),
}


def _function(module: object, name: str) -> ast.FunctionDef:
    tree = ast.parse(Path(inspect.getsourcefile(module)).read_text(encoding="utf-8"))  # type: ignore[arg-type]
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


def _calls(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for call in ast.walk(node):
        if isinstance(call, ast.Call):
            func = call.func
            names.add(func.id if isinstance(func, ast.Name) else getattr(func, "attr", ""))
    return names


def _params(entry_points: dict[object, tuple[str, ...]]) -> list[tuple[object, str]]:
    return [(module, name) for module, names in entry_points.items() for name in names]


@pytest.mark.parametrize(
    ("module", "name"), _params(_ENTRY_POINTS), ids=[n for _, n in _params(_ENTRY_POINTS)]
)
def test_every_billing_mutation_checks_its_caller_before_anything_else(
    module: object, name: str
) -> None:
    body = [
        stmt
        for stmt in _function(module, name).body
        if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))
    ]
    # Pure input validation may come first; the first call that can reach
    # the database is never before the caller check.
    first_caller_check = next(
        i for i, stmt in enumerate(body) if "require_billing_caller" in _calls(stmt)
    )
    for stmt in body[:first_caller_check]:
        assert _calls(stmt) <= {"_validate_text", "_validate_merchant_status"}, name


@pytest.mark.parametrize(
    ("module", "name"),
    _params(_FINAL_TRANSACTIONS),
    ids=[n for _, n in _params(_FINAL_TRANSACTIONS)],
)
def test_every_final_transaction_authorizes_and_audits_in_one_session(
    module: object, name: str
) -> None:
    blocks = [
        node
        for node in ast.walk(_function(module, name))
        if isinstance(node, ast.With)
        and any(
            isinstance(item.context_expr, ast.Call)
            and getattr(item.context_expr.func, "id", None) == "tenant_session_scope"
            for item in node.items
        )
    ]
    # `_commercial_context()` is the commercial path's shared check: it
    # calls `authorize_billing` itself (pinned below).
    assert any(
        "record_billing_audit" in _calls(block)
        and _calls(block) & {"authorize_billing", "_commercial_context", "_cancellation_authority"}
        for block in blocks
    ), name


def test_the_cancellation_authority_authorizes_every_capacity() -> None:
    assert "authorize_billing" in _calls(_function(commercial, "_cancellation_authority"))


def test_the_commercial_context_authorizes_and_applies_catalog_eligibility() -> None:
    calls = _calls(_function(commercial, "_commercial_context"))
    assert {"authorize_billing", "evaluate_plan_eligibility", "lock_open_tenant"} <= calls


@pytest.mark.parametrize(
    ("module", "name"), _params(_ENTRY_POINTS), ids=[n for _, n in _params(_ENTRY_POINTS)]
)
def test_no_billing_mutation_audits_in_a_separate_transaction(module: object, name: str) -> None:
    calls = _calls(_function(module, name))
    if name == "_create_commercial_subscription":
        # The single documented exception: the payer-side record of a
        # sponsored subscription is a different tenant's evidence, written
        # after the service tenant's transaction (ADR-0029 keeps per-tenant
        # writes in separate transactions); making it outbox-durable is
        # deferred (the step 4 projection consumer writes no audit). The
        # service tenant's own entry is
        # written in `_insert_pending()`'s transaction.
        return
    assert "record_audit_event" not in calls, name
