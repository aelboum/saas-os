"""Phase 5.3 step 5 -- `inherits_billing` retirement and cancellation
capacity, without a database: no code can write a new `true`, the old
ungated setter is gone, the database rule exists, and the capacity
vocabulary is exactly the approved one."""

from __future__ import annotations

import ast
from pathlib import Path

from core.billing.commercial import CancellationCapacity

import core.tenancy

_REPO = Path(__file__).resolve().parents[3]
_SHIPPED = ("api", "core", "infra", "control-plane", "examples")


def _python_files() -> list[Path]:
    return [
        path
        for top in _SHIPPED
        for path in (_REPO / top).rglob("*.py")
        if "migrations" not in path.parts
    ]


def test_no_code_writes_a_new_billing_inheritance() -> None:
    offenders: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "inherits_billing":
                        if not (isinstance(node.value, ast.Constant) and node.value.value is False):
                            offenders.append(f"{path.relative_to(_REPO)}:{node.lineno}")
            if isinstance(node, ast.Call):
                func = node.func
                name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                for keyword in node.keywords:
                    if keyword.arg != "inherits_billing":
                        continue
                    literal_true = (
                        isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                    )
                    # A write: constructing a tenant, or an UPDATE's values.
                    writer = name in {"Tenant", "values", "update"} and not (
                        isinstance(keyword.value, ast.Constant) and keyword.value.value is False
                    )
                    if literal_true or writer:
                        offenders.append(f"{path.relative_to(_REPO)}:{keyword.value.lineno}")
    assert offenders == []


def test_the_ungated_tenancy_setter_is_gone() -> None:
    assert not hasattr(core.tenancy, "set_tenant_billing_inheritance")
    for path in _python_files():
        assert "set_tenant_billing_inheritance(" not in path.read_text(encoding="utf-8"), path


def test_the_database_enforces_the_forward_rule() -> None:
    migration = next((_REPO / "infra/db/migrations/versions").glob("aa43b942bf93_*.py"))
    source = migration.read_text(encoding="utf-8")
    assert "BEFORE INSERT OR UPDATE OF inherits_billing ON core.tenants" in source
    assert "NEW.inherits_billing AND (TG_OP = 'INSERT' OR NOT OLD.inherits_billing)" in source
    assert "SECURITY DEFINER" not in source.split('"""', 2)[2]


def test_cancellation_capacities_are_exactly_the_approved_parties() -> None:
    assert {c.value for c in CancellationCapacity} == {"service_tenant", "payer", "merchant"}
