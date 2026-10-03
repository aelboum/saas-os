"""Phase 5.3 step 2 -- Catalog v2 without a database: value sets match the
schema, plans are immutable through the code, every catalog mutation has
the step 1 shape, `list_plans()` is the predicate, and adoption refuses a
non-operator caller before touching anything."""

from __future__ import annotations

import ast
import inspect
import uuid
from pathlib import Path

import pytest
from core.authority import SystemAuthority, SystemCaller, UserCaller
from core.billing.catalog import PlanOfferStatus, PlanStatus, PlanVisibility
from core.billing.errors import BillingNotAuthorizedError, InvalidCatalogValueError
from core.billing.models import Plan, PlanOffer

import core.billing
from core.billing import catalog

_BILLING_DIR = Path(__file__).resolve().parents[3] / "core" / "billing"


def _check(table: object, name: str) -> str:
    return next(
        str(c.sqltext)  # type: ignore[attr-defined]
        for c in table.constraints  # type: ignore[attr-defined]
        if c.name == name
    )


def test_value_sets_match_the_database_constraints() -> None:
    plans, offers = Plan.__table__, PlanOffer.__table__
    for value in PlanVisibility:
        assert f"'{value.value}'" in _check(plans, "ck_billing_plans_visibility")
    for value in PlanStatus:
        assert f"'{value.value}'" in _check(plans, "ck_billing_plans_status")
    for value in PlanOfferStatus:
        assert f"'{value.value}'" in _check(offers, "ck_billing_plan_offers_status")
    assert {v.value for v in PlanVisibility} == {"public", "descendants", "private", "unlisted"}
    assert {v.value for v in PlanStatus} == {"active", "withdrawn"}


def _assignments(attr_names: set[str]) -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    for path in sorted(_BILLING_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for func in ast.walk(tree):
            if not isinstance(func, ast.FunctionDef):
                continue
            for node in ast.walk(func):
                if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if (
                            isinstance(target, ast.Attribute)
                            and target.attr in attr_names
                            and ast.unparse(target.value) != "self"  # an error's own field
                        ):
                            found.append((path.name, func.name, ast.unparse(target)))
    return found


def test_no_code_edits_a_plans_commercial_identity() -> None:
    """Plans are immutable through the API (ADR-0029 amendment): nothing
    assigns a plan's entitlements, key or provider price after creation."""
    assert _assignments({"entitlements", "key", "provider_price_id"}) == []


def test_only_adoption_assigns_a_plans_owner_and_merchant() -> None:
    plan_assignments = [
        (module, func, target)
        for module, func, target in _assignments({"owner_tenant_id", "merchant_account_id"})
        if target.startswith("plan.")
    ]
    assert plan_assignments == [
        ("catalog.py", "adopt_legacy_plan", "plan.owner_tenant_id"),
        ("catalog.py", "adopt_legacy_plan", "plan.merchant_account_id"),
    ]


def test_there_is_no_plan_edit_api() -> None:
    names = set(dir(core.billing)) | set(dir(catalog))
    assert not {n for n in names if "update_plan" in n or "edit_plan" in n or "set_plan_ent" in n}


_MUTATIONS = (
    "create_owned_plan",
    "set_plan_visibility",
    "withdraw_plan",
    "create_plan_offer",
    "revoke_plan_offer",
    "adopt_legacy_plan",
)


def _function(name: str) -> ast.FunctionDef:
    tree = ast.parse(Path(inspect.getsourcefile(catalog)).read_text(encoding="utf-8"))  # type: ignore[arg-type]
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


def _calls(node: ast.AST) -> set[str]:
    return {
        call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", "")
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
    }


@pytest.mark.parametrize("name", _MUTATIONS)
def test_every_catalog_mutation_authorizes_and_audits_in_its_transaction(name: str) -> None:
    func = _function(name)
    assert "require_billing_caller" in _calls(func)
    assert "record_audit_event" not in _calls(func)
    blocks = [
        node
        for node in ast.walk(func)
        if isinstance(node, ast.With)
        and any(
            isinstance(item.context_expr, ast.Call)
            and getattr(item.context_expr.func, "id", None) == "tenant_session_scope"
            for item in node.items
        )
    ]
    assert any({"authorize_billing", "record_billing_audit"} <= _calls(b) for b in blocks)


def test_list_plans_filters_through_the_single_predicate() -> None:
    assert "evaluate_plan_eligibility" in _calls(_function("list_plans"))


def test_adoption_refuses_a_non_operator_before_any_database_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _no_database(*_: object, **__: object) -> None:
        raise AssertionError("no transaction may be opened for a refused caller")

    monkeypatch.setattr(catalog, "tenant_session_scope", _no_database)
    for caller in (UserCaller(uuid.uuid4()), SystemCaller(SystemAuthority.PROVISIONING)):
        with pytest.raises(BillingNotAuthorizedError):
            catalog.adopt_legacy_plan(
                caller,
                uuid.uuid4(),
                owner_tenant_id=uuid.uuid4(),
                merchant_account_id=uuid.uuid4(),
            )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"key": ""},
        {"key": "x" * 101},
        {"name": " "},
        {"visibility": "secret"},
        {"entitlements": ["seats"]},
        {"provider_price_id": ""},
    ],
)
def test_invalid_catalog_input_is_refused_before_any_database_access(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, object]
) -> None:
    monkeypatch.setattr(catalog, "tenant_session_scope", lambda *_: pytest.fail("no DB access"))
    arguments: dict[str, object] = {
        "merchant_account_id": uuid.uuid4(),
        "key": "starter",
        "name": "Starter",
        **kwargs,
    }
    with pytest.raises(InvalidCatalogValueError):
        catalog.create_owned_plan(
            SystemCaller(SystemAuthority.BILLING_OPERATIONS),
            uuid.uuid4(),
            **arguments,  # type: ignore[arg-type]
        )
