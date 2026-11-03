"""Crash recovery D4, database-free parts (design pull request #195, section
4a; `docs/architecture/OUTBOX-STARTED-MARKER.md`):

- the setting `OUTBOX_EXTERNAL_EFFECT_MARKERS`: off by default, strictly
  parsed, and while off the marker write touches nothing;
- `TenantJobContext.external_effect()`: the starter runs before the block,
  a refusal stops the block, and with no starter nothing happens;
- revisions A and B: re-pointed onto the verified head, the DDL approved in
  D4, and the schema inventory sees both columns (it reads `op.add_column`);
- the ORM model maps exactly the columns the migrations produce.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest

import saas_os.core.outbox.dispatch as dispatch
from saas_os.core.outbox import (
    CRASH_AFTER_START_ERROR,
    OUTCOME_UNKNOWN_PREFIX,
    ExternalEffectNotStartedError,
    OutboxConfigurationError,
    OutboxDispatchConfig,
    OutboxEvent,
    get_outbox_dispatch_config,
    mark_external_effect_started,
)
from saas_os.infra.db.migrations.schema_inventory import schema_at_head
from saas_os.infra.jobs import TenantJobContext

_VERSIONS = (
    Path(__file__).resolve().parents[3] / "saas_os" / "infra" / "db" / "migrations" / "versions"
)
_A = _VERSIONS / "0420025c3b4b_add_outbox_external_started_marker.py"
_B = _VERSIONS / "f0cc2e656d79_validate_outbox_external_started_pair.py"
_MARKER_COLUMNS = {"external_started_at", "external_started_claim"}
_A_ID = "0420025c3b4b"  # pragma: allowlist secret -- an alembic revision id
_B_ID = "f0cc2e656d79"  # pragma: allowlist secret -- an alembic revision id
_HEAD_BEFORE = "c3f9e1a7b5d2"  # pragma: allowlist secret -- an alembic revision id


# --- The setting ------------------------------------------------------------------


def test_markers_are_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OUTBOX_EXTERNAL_EFFECT_MARKERS", raising=False)
    get_outbox_dispatch_config.cache_clear()
    try:
        assert get_outbox_dispatch_config().external_effect_markers is False
        assert OutboxDispatchConfig().external_effect_markers is False
    finally:
        get_outbox_dispatch_config.cache_clear()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", True), ("TRUE", True), ("1", True), ("false", False), ("0", False)],
)
def test_the_setting_is_read_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
) -> None:
    monkeypatch.setenv("OUTBOX_EXTERNAL_EFFECT_MARKERS", raw)
    get_outbox_dispatch_config.cache_clear()
    try:
        assert get_outbox_dispatch_config().external_effect_markers is expected
    finally:
        get_outbox_dispatch_config.cache_clear()


@pytest.mark.parametrize("raw", ["yes", "on", "", "2", "enabled"])
def test_an_unreadable_setting_is_refused(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("OUTBOX_EXTERNAL_EFFECT_MARKERS", raw)
    get_outbox_dispatch_config.cache_clear()
    try:
        with pytest.raises(OutboxConfigurationError, match="OUTBOX_EXTERNAL_EFFECT_MARKERS"):
            get_outbox_dispatch_config()
    finally:
        get_outbox_dispatch_config.cache_clear()


def test_while_off_the_marker_write_opens_no_session(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_database(*args: object, **kwargs: object) -> None:
        raise AssertionError("a session was opened while markers are off")

    monkeypatch.setattr(dispatch, "tenant_session_scope", _no_database)
    assert (
        mark_external_effect_started(
            uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), config=OutboxDispatchConfig()
        )
        is False
    )


def test_the_recorded_texts_name_the_cause() -> None:
    assert CRASH_AFTER_START_ERROR == (
        "CrashAfterStart: outcome unknown; not retried automatically"
    )
    assert OUTCOME_UNKNOWN_PREFIX == "OutcomeUnknown: "
    error = ExternalEffectNotStartedError("e-1")
    assert str(error) == "external effect not started for outbox event e-1"


# --- The context manager -----------------------------------------------------------


def test_external_effect_starts_the_marker_before_the_block() -> None:
    order: list[str] = []
    context = TenantJobContext(
        tenant_id=uuid.uuid4(), start_external_effect=lambda: order.append("marker")
    )

    with context.external_effect():
        order.append("send")

    assert order == ["marker", "send"]


def test_a_refused_marker_stops_the_block() -> None:
    sent: list[str] = []

    def _refuse() -> None:
        raise ExternalEffectNotStartedError("e-1")

    context = TenantJobContext(tenant_id=uuid.uuid4(), start_external_effect=_refuse)
    with pytest.raises(ExternalEffectNotStartedError):
        with context.external_effect():
            sent.append("send")
    assert sent == []


def test_without_a_starter_external_effect_does_nothing() -> None:
    context = TenantJobContext(tenant_id=uuid.uuid4())
    with context.external_effect():
        pass
    # The starter is not part of the context's identity or its repr.
    assert TenantJobContext(tenant_id=context.tenant_id) == TenantJobContext(
        tenant_id=context.tenant_id, start_external_effect=lambda: None
    )
    assert "start_external_effect" not in repr(context)


# --- The migrations ----------------------------------------------------------------


def _assignments(path: Path) -> dict[str, object]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    values: dict[str, object] = {}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            assert node.value is not None
            values[node.target.id] = ast.literal_eval(node.value)
    return values


def test_revision_a_follows_the_verified_head_and_b_follows_a() -> None:
    a, b = _assignments(_A), _assignments(_B)
    assert (a["revision"], a["down_revision"]) == (_A_ID, _HEAD_BEFORE)
    assert (b["revision"], b["down_revision"]) == (_B_ID, _A_ID)


def test_the_approved_ddl_is_what_the_revisions_emit() -> None:
    a, b = _A.read_text(encoding="utf-8"), _B.read_text(encoding="utf-8")
    assert "SET LOCAL lock_timeout = '5s'" in a and "RESET lock_timeout" in a
    assert (
        '" CHECK ((external_started_at IS NULL) = (external_started_claim IS NULL))"\n'
        '        " NOT VALID"'
    ) in a
    assert "autocommit_block()" in b and "SET lock_timeout = '5s'" in b
    assert "VALIDATE CONSTRAINT ck_outbox_events_external_started_pair" in b
    assert "finally:" in b  # the RESET also runs when VALIDATE fails
    assert 'op.execute("SET LOCAL' not in b  # session-level: autocommit


def test_the_schema_inventory_sees_both_marker_columns() -> None:
    columns = schema_at_head()["core.outbox_events"]
    assert _MARKER_COLUMNS <= columns


def test_the_model_maps_exactly_the_columns_the_migrations_produce() -> None:
    mapped = {column.name for column in OutboxEvent.__table__.columns}
    assert mapped == set(schema_at_head()["core.outbox_events"])
