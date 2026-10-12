"""Phase 5.3 step 4 -- seller/payer projection invariants, without a
database: every canonical subscription change announces itself in its own
transaction, only the announce helper moves the version, the event carries
only an id and a version, and the consumer can neither call a provider nor
write a canonical row."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from saas_os.core.billing import projections
from saas_os.core.billing.errors import MalformedProjectionEventError
from saas_os.core.outbox import PermanentEventError

_BILLING_DIR = Path(__file__).resolve().parents[3] / "saas_os" / "core" / "billing"


def _functions() -> list[tuple[str, ast.FunctionDef]]:
    found: list[tuple[str, ast.FunctionDef]] = []
    for path in sorted(_BILLING_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found.extend(
            (path.name, node) for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        )
    return found


def _calls(node: ast.AST) -> set[str]:
    return {
        call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", "")
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
    }


def _assigned_attributes(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for stmt in ast.walk(node):
        if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                if isinstance(target, ast.Attribute) and ast.unparse(target.value) != "self":
                    names.add(f"{ast.unparse(target.value)}.{target.attr}")
    return names


def _changes_a_subscription(module: str, func: ast.FunctionDef) -> bool:
    if "set_subscription_status" in _calls(func) and func.name != "set_subscription_status":
        return True
    if "Subscription" in _calls(func):  # constructs a row
        return True
    subscription_fields = {
        "plan_id",
        "payer_tenant_id",
        "billing_account_id",
        "merchant_account_id",
    }
    return any(
        name.split(".")[-1] in subscription_fields and not name.startswith("plan.")
        for name in _assigned_attributes(func)
    )


def test_every_canonical_change_announces_itself() -> None:
    changers = [(m, f) for m, f in _functions() if _changes_a_subscription(m, f)]
    assert {(m, f.name) for m, f in changers} >= {
        ("commercial.py", "_insert_pending"),
        ("commercial.py", "_apply_provider_state"),
        ("commercial.py", "cancel_commercial_subscription"),
        ("commercial.py", "reconcile_legacy_subscription"),
        ("service.py", "subscribe"),
        ("service.py", "upgrade_subscription"),
        ("service.py", "cancel_subscription"),
    }
    missing = [(m, f.name) for m, f in changers if "announce_subscription_change" not in _calls(f)]
    assert missing == []


def test_only_the_announce_helper_moves_the_version() -> None:
    movers = [
        (m, f.name)
        for m, f in _functions()
        if any(name.endswith(".version") for name in _assigned_attributes(f))
    ]
    assert movers == [("projections.py", "announce_subscription_change")]


def test_the_event_carries_only_an_identity_and_a_version() -> None:
    func = next(f for m, f in _functions() if f.name == "announce_subscription_change")
    payloads = [
        kw.value
        for call in ast.walk(func)
        if isinstance(call, ast.Call)
        for kw in call.keywords
        if kw.arg == "payload"
    ]
    [payload] = payloads
    assert isinstance(payload, ast.Dict)
    assert [ast.literal_eval(k) for k in payload.keys if k is not None] == [
        "subscription_id",
        "version",
    ]


def test_the_consumer_never_reaches_a_provider_or_a_canonical_writer() -> None:
    tree = ast.parse((_BILLING_DIR / "projections.py").read_text(encoding="utf-8"))
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert not imported & {
        "saas_os.core.billing.provider",
        "saas_os.core.billing.stripe_provider",
        "saas_os.core.billing.commercial",
        "saas_os.core.billing.service",
        "core.billing.lifecycle_writer",
    }
    assert "set_subscription_status" not in _calls(tree)


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"subscription_id": "x", "version": 1},
        {"subscription_id": "00000000-0000-0000-0000-000000000001", "version": -1},
        {"subscription_id": "00000000-0000-0000-0000-000000000001", "version": 1.0},
    ],
)
def test_a_malformed_event_is_permanent(data: dict[str, object]) -> None:
    with pytest.raises(MalformedProjectionEventError) as excinfo:
        projections._parse_event(data)
    assert isinstance(excinfo.value, PermanentEventError)


def test_the_consumer_name_is_stable() -> None:
    assert projections.SUBSCRIPTION_CHANGED_EVENT_TYPE == "billing.subscription_changed"
    assert set(projections.OUTBOX_EVENT_HANDLERS) == {"billing.subscription_changed"}
