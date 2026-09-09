"""Webhook subscription model shape tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 4.3) -- inspect SQLAlchemy metadata only, no database connection
needed. Mirrors tests/core/api_keys/test_api_keys_models.py.
"""

from __future__ import annotations

import inspect

from core.webhooks.models import WebhookSubscription
from sqlalchemy import Table

_webhook_subscriptions: Table = WebhookSubscription.__table__  # type: ignore[assignment]


def test_webhook_subscriptions_table_is_schema_qualified_core() -> None:
    assert _webhook_subscriptions.schema == "core"
    assert _webhook_subscriptions.name == "webhook_subscriptions"


def test_webhook_subscriptions_has_expected_columns() -> None:
    assert {c.name for c in _webhook_subscriptions.columns} == {
        "id",
        "tenant_id",
        "url",
        "signing_secret",
        "created_at",
        "updated_at",
    }


def test_webhook_subscriptions_has_no_speculative_fields() -> None:
    """No event-type filter, no enable/disable flag, no delivery-history
    columns -- none is specified by the roadmap's Phase 4.3 objective
    ("subscription management, delivery, retry, signing"), and delivery
    execution metadata is infra/jobs' own ownership (core/webhooks/models.py
    docstring)."""
    names = {c.name for c in _webhook_subscriptions.columns}
    assert "event_types" not in names
    assert "is_active" not in names
    assert "status" not in names
    assert "last_delivered_at" not in names


def test_webhook_subscriptions_tenant_id_is_not_nullable() -> None:
    assert _webhook_subscriptions.columns["tenant_id"].nullable is False


def test_webhook_subscriptions_tenant_id_is_a_foreign_key_to_tenants() -> None:
    fk_targets = {fk.target_fullname for fk in _webhook_subscriptions.foreign_keys}
    assert "core.tenants.id" in fk_targets


def test_webhook_subscriptions_url_and_signing_secret_are_not_nullable() -> None:
    assert _webhook_subscriptions.columns["url"].nullable is False
    assert _webhook_subscriptions.columns["signing_secret"].nullable is False


def test_webhook_subscriptions_has_no_plaintext_named_secret_column_beyond_signing_secret() -> None:
    """Only `signing_secret` carries sensitive material -- documents the
    deliberate design (core/webhooks/models.py docstring: this secret is
    stored in plaintext because it must be reused to sign every delivery,
    unlike a one-way-hashed bearer credential)."""
    names = {c.name for c in _webhook_subscriptions.columns}
    assert "password" not in names
    assert "api_key" not in names
    assert "token" not in names


def test_core_webhooks_models_does_not_import_sqlalchemy_directly() -> None:
    """Non-vacuous documentation of the boundary this module relies on --
    the real enforcement is the import-linter contract
    (tests/architecture/test_layer_boundaries.py); this just confirms the
    module's own source doesn't contain a direct sqlalchemy import.
    """
    import core.webhooks.models as models_module

    source = inspect.getsource(models_module)
    assert "import sqlalchemy" not in source
    assert "from sqlalchemy" not in source
