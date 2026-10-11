"""Billing Foundation v2 Phase 2 -- commercial party model, pure unit tests
(no database): the explicit-caller trust boundary, the billing permission
vocabulary, dual authorization's use of `saas_os.core.rbac.can()`, the platform
tenant designation, the frozen `inherits_billing` boundary, product
neutrality, and the migration's schema shape (replayed statically).

docs/ADR/0029-commercial-parties-and-billing-relationships.md is the
source of truth these tests pin.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path
from typing import Any

import pytest

from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.billing import authorization, commercial
from saas_os.core.billing.authorization import (
    BILLING_PERMISSIONS,
    BillingActor,
    TrustedSystemCaller,
    authorize_billing,
    trusted_system,
)
from saas_os.core.billing.errors import BillingActorRequiredError, BillingNotAuthorizedError
from saas_os.core.billing.provider import BillingProvider, FakeBillingProvider
from saas_os.core.billing.service import SubscribeResult
from saas_os.core.billing.stripe_provider import StripeBillingProvider
from saas_os.core.tenancy import (
    PlatformTenantNotConfiguredError,
    TenancyConfigurationError,
    get_platform_tenant_id,
    get_tenancy_config,
)
from saas_os.infra.db.migrations.schema_inventory import schema_at_head

# `can()` and `register_permission()` are replaced in these unit tests, so
# the session they would be evaluated in is never used.
_SESSION: Any = object()

_BILLING_DIR = Path(__file__).resolve().parents[3] / "saas_os" / "core" / "billing"
_PHASE_2_MODULES = ("authorization.py", "commercial.py", "parties.py", "provider_refs.py")


# --- Billing permission vocabulary (ADR-0029, "Billing authorization") -----


def test_billing_permission_vocabulary_is_exactly_the_adr_0029_set() -> None:
    assert set(BILLING_PERMISSIONS) == {
        ("billing.catalog", "read"),
        ("billing.catalog", "manage"),
        ("billing.merchant", "manage"),
        ("billing.account", "read"),
        ("billing.account", "manage"),
        ("billing.account", "charge"),
        ("billing.subscription", "create"),
        ("billing.subscription", "read"),
        ("billing.subscription", "change"),
        ("billing.subscription", "cancel"),
        ("billing.subscription", "reactivate"),
        ("billing.invoice", "read"),
    }
    assert len(BILLING_PERMISSIONS) == len(set(BILLING_PERMISSIONS))


# --- Explicit callers: the trust boundary ----------------------------------


@pytest.mark.parametrize("caller", [None, uuid.uuid4(), "system", object()])
def test_authorize_billing_rejects_anything_but_an_explicit_caller(caller: object) -> None:
    with pytest.raises(BillingActorRequiredError):
        authorize_billing(caller, [], operation="op", session=_SESSION)


@pytest.mark.parametrize("reason", ["", "   "])
def test_trusted_system_requires_a_reason(reason: str) -> None:
    with pytest.raises(ValueError):
        trusted_system(reason)


def test_trusted_system_skips_can_entirely(monkeypatch: pytest.MonkeyPatch) -> None:
    def _must_not_be_called(**_: object) -> bool:
        raise AssertionError("can() must not be evaluated for an explicit trusted system caller")

    monkeypatch.setattr(authorization, "can", _must_not_be_called)
    monkeypatch.setattr(authorization, "register_permission", lambda *_, **__: None)
    caller = trusted_system("unit test")
    authorized = authorize_billing(
        caller, [(uuid.uuid4(), "billing.account", "charge")], operation="op", session=_SESSION
    )
    # Phase 5.3: the deprecated marker maps onto the typed billing purpose;
    # its reason survives only as an audit note.
    assert authorized.caller == SystemCaller(SystemAuthority.BILLING_OPERATIONS)
    assert authorized.audit_note == {"trusted_system_reason": "unit test"}


def _record_can(monkeypatch: pytest.MonkeyPatch, allowed: set[tuple[uuid.UUID, str, str]]):
    calls: list[tuple[uuid.UUID, uuid.UUID, str, str]] = []

    def _fake_can(
        *, actor_id: uuid.UUID, tenant_id: uuid.UUID, action: str, resource: str, session: object
    ) -> bool:
        assert session is _SESSION
        calls.append((actor_id, tenant_id, resource, action))
        return (tenant_id, resource, action) in allowed

    monkeypatch.setattr(authorization, "can", _fake_can)
    monkeypatch.setattr(authorization, "register_permission", lambda *_, **__: None)
    return calls


def test_actor_is_evaluated_by_can_for_every_check(monkeypatch: pytest.MonkeyPatch) -> None:
    payer, service = uuid.uuid4(), uuid.uuid4()
    checks = [(payer, "billing.account", "charge"), (service, "billing.subscription", "create")]
    calls = _record_can(monkeypatch, set(checks))
    actor = BillingActor.user(uuid.uuid4())

    assert authorize_billing(actor, checks, operation="op", session=_SESSION).caller == (
        UserCaller(actor.user_id)
    )
    assert calls == [
        (actor.user_id, payer, "billing.account", "charge"),
        (actor.user_id, service, "billing.subscription", "create"),
    ]


@pytest.mark.parametrize("granted_index", [0, 1])
def test_one_denied_check_denies_the_whole_operation_with_the_same_error(
    monkeypatch: pytest.MonkeyPatch, granted_index: int
) -> None:
    payer, service = uuid.uuid4(), uuid.uuid4()
    checks = [(payer, "billing.account", "charge"), (service, "billing.subscription", "create")]
    _record_can(monkeypatch, {checks[granted_index]})

    with pytest.raises(BillingNotAuthorizedError) as excinfo:
        authorize_billing(
            BillingActor.user(uuid.uuid4()), checks, operation="billing.op", session=_SESSION
        )
    # Same error and message whichever side was denied -- never reveals which.
    assert str(excinfo.value) == "Not authorized to perform billing operation 'billing.op'."


def test_create_subscription_without_an_actor_fails_before_touching_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ordinary consumer-facing path cannot be reached with
    `caller=None`: it fails at the trust boundary, before any tenant,
    account, provider or database access."""

    def _must_not_be_called(*_: object, **__: object) -> None:
        raise AssertionError("nothing past the caller check may run")

    monkeypatch.setattr(commercial, "require_open_tenant", _must_not_be_called)
    monkeypatch.setattr(commercial, "get_billing_account", _must_not_be_called)
    provider = FakeBillingProvider()
    with pytest.raises(BillingActorRequiredError):
        commercial.create_subscription(
            None,
            service_tenant_id=uuid.uuid4(),
            payer_tenant_id=uuid.uuid4(),
            billing_account_id=uuid.uuid4(),
            plan_id=uuid.uuid4(),
            idempotency_key="key-1",
            provider=provider,
        )


def test_trusted_system_caller_is_not_constructible_from_a_missing_actor() -> None:
    assert not isinstance(None, TrustedSystemCaller)
    with pytest.raises(TypeError):
        TrustedSystemCaller()  # type: ignore[call-arg]


# --- Provider name ----------------------------------------------------------


def test_adapters_expose_a_stable_provider_name() -> None:
    assert FakeBillingProvider.name == "fake"
    assert StripeBillingProvider.name == "stripe"
    assert isinstance(FakeBillingProvider(), BillingProvider)


# --- Platform tenant designation (ADR-0029, Decision 0.2) -------------------


@pytest.fixture
def _fresh_tenancy_config():
    get_tenancy_config.cache_clear()
    yield
    get_tenancy_config.cache_clear()


@pytest.mark.usefixtures("_fresh_tenancy_config")
@pytest.mark.parametrize("raw", [None, "", "   "])
def test_unset_platform_tenant_fails_closed(
    monkeypatch: pytest.MonkeyPatch, raw: str | None
) -> None:
    if raw is None:
        monkeypatch.delenv("PLATFORM_TENANT_ID", raising=False)
    else:
        monkeypatch.setenv("PLATFORM_TENANT_ID", raw)
    assert get_tenancy_config().platform_tenant_id is None
    with pytest.raises(PlatformTenantNotConfiguredError):
        get_platform_tenant_id()


@pytest.mark.usefixtures("_fresh_tenancy_config")
def test_configured_platform_tenant_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    tenant_id = uuid.uuid4()
    monkeypatch.setenv("PLATFORM_TENANT_ID", str(tenant_id))
    assert get_platform_tenant_id() == tenant_id


@pytest.mark.usefixtures("_fresh_tenancy_config")
def test_malformed_platform_tenant_is_a_configuration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PLATFORM_TENANT_ID", "not-a-uuid")
    with pytest.raises(TenancyConfigurationError):
        get_tenancy_config()


def test_tenant_model_gains_no_platform_marker() -> None:
    """The designation is configuration, not a tenant attribute."""
    tenant_columns = schema_at_head()["core.tenants"]
    assert not {c for c in tenant_columns if "platform" in c or c in {"type", "tenant_type"}}


# --- inherits_billing is frozen (ADR-0029) ----------------------------------


@pytest.mark.parametrize("module", _PHASE_2_MODULES)
def test_phase_2_modules_never_consult_billing_inheritance(module: str) -> None:
    """New commercial billing code must not decide a payer (or anything
    else) from `inherits_billing`, the owner walk, or the hierarchy."""
    tree = ast.parse((_BILLING_DIR / module).read_text(encoding="utf-8"))
    names = {
        node.attr if isinstance(node, ast.Attribute) else node.id
        for node in ast.walk(tree)
        if isinstance(node, (ast.Attribute, ast.Name))
    }
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    forbidden = {
        "resolve_billing_owner",
        "get_ancestor_chain",
        "get_ancestor_ids",
        "get_descendant_ids",
        "set_tenant_billing_inheritance",
    }
    assert not (names | imported) & forbidden
    # Phase 5.3 step 5: `inherits_billing` may appear only to REFUSE (the
    # create guard / migration precondition read it) or to END inheritance
    # (assigned `False` by the sponsored migration) -- never to decide a
    # payer, and never assigned anything else.
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == "inherits_billing":
                    assert isinstance(node.value, ast.Constant) and node.value.value is False
    reads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and node.attr == "inherits_billing"
        and isinstance(node.ctx, ast.Load)
    ]
    assert len(reads) <= 1


# --- Session boundary / provider neutrality / product neutrality ------------


def _session_scope_call_sites(module: str) -> list[str]:
    tree = ast.parse((_BILLING_DIR / module).read_text(encoding="utf-8"))
    sites = []
    for func in ast.walk(tree):
        if isinstance(func, ast.FunctionDef):
            for node in ast.walk(func):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "session_scope"
                ):
                    sites.append(func.name)
    return sites


@pytest.mark.parametrize("module", ["authorization.py", "commercial.py", "parties.py"])
def test_tenant_owned_party_modules_never_use_the_untenanted_session(module: str) -> None:
    assert _session_scope_call_sites(module) == []


def test_only_the_provider_ref_index_uses_the_untenanted_session() -> None:
    assert set(_session_scope_call_sites("provider_refs.py")) == {
        "register_provider_ref",
        "_lookup",
        "find_provider_object_ref",
    }


@pytest.mark.parametrize("module", _PHASE_2_MODULES)
def test_phase_2_modules_never_import_stripe(module: str) -> None:
    source = (_BILLING_DIR / module).read_text(encoding="utf-8")
    assert "import stripe" not in source
    assert "stripe_provider import" not in source


@pytest.mark.parametrize("module", _PHASE_2_MODULES)
def test_phase_2_modules_carry_no_product_specific_commercial_terms(module: str) -> None:
    tree = ast.parse((_BILLING_DIR / module).read_text(encoding="utf-8"))
    identifiers = {
        (
            node.id
            if isinstance(node, ast.Name)
            else node.attr
            if isinstance(node, ast.Attribute)
            else node.name
        ).lower()
        for node in ast.walk(tree)
        if isinstance(node, (ast.Name, ast.Attribute, ast.FunctionDef, ast.ClassDef))
    }
    string_constants = {
        node.value.lower()
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) < 80
    }
    terms = (
        "agency",
        "reseller",
        "resale",
        "white_label",
        "markup",
        "commission",
        "payout",
        "settlement",
    )
    for term in terms:
        assert not any(term in ident for ident in identifiers), term
        assert not any(term in const for const in string_constants), term


# --- Schema shape (migration replayed statically) --------------------------


def test_migration_produces_the_commercial_party_tables() -> None:
    schema = schema_at_head()
    assert schema["core.billing_merchant_accounts"] >= {
        "id",
        "tenant_id",
        "provider",
        "provider_account_ref",
        "status",
    }
    assert schema["core.billing_accounts"] >= {
        "id",
        "tenant_id",
        "merchant_tenant_id",
        "merchant_account_id",
        "provider_customer_ref",
        "status",
    }
    assert schema["core.billing_provider_refs"] >= {
        "provider",
        "provider_account_ref",
        "object_type",
        "provider_object_ref",
        "tenant_id",
        "local_object_type",
        "local_object_id",
    }
    assert schema["core.billing_subscriptions"] >= {
        "tenant_id",
        "payer_tenant_id",
        "billing_account_id",
        "provider",
    }
    for table, columns in schema.items():
        if table.startswith("core.billing_merchant"):
            assert "merchant_type" not in columns and "type" not in columns


# --- Idempotent result replay stays backward compatible ---------------------


def test_subscribe_result_replays_a_result_stored_before_phase_2() -> None:
    legacy: dict[str, object] = {
        "subscription_id": str(uuid.uuid4()),
        "plan_id": str(uuid.uuid4()),
        "status": "active",
        "provider_subscription_id": "fake_sub_x",
    }
    result = SubscribeResult.from_dict(legacy)
    assert result.payer_tenant_id is None
    assert result.billing_account_id is None
    assert result.provider is None


def test_subscribe_result_round_trips_the_payer_fields() -> None:
    result = SubscribeResult(
        subscription_id=uuid.uuid4(),
        plan_id=uuid.uuid4(),
        status="active",
        provider_subscription_id="fake_sub_y",
        payer_tenant_id=uuid.uuid4(),
        billing_account_id=uuid.uuid4(),
        provider="fake",
    )
    assert SubscribeResult.from_dict(result.to_dict()) == result
