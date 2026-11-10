"""Migration test for `a4c8e1f3b7d5` (ADR-0054 amendment of 2026-11-09, Gap
21a): the nullable `cache_write_per_million`, `per_request`, `unit_rates` and
`reviewed_at` columns and the `ck_ai_model_prices_extra_units` check on
`control_plane.ai_model_prices`.

Additive only. The test asserts the four columns and the check at head (the
types, nullable, no default), that the check refuses a negative rate and a
`unit_rates` value that is not a JSON object, that a downgrade removes exactly
those five objects and nothing else of the table (the other columns and
constraints, the indexes, the privileges and the rows), that the upgrade
restores them with every value NULL (no backfill: an existing price reads as
never confirmed), and that the table stays global: no row-level security, the
application role reads only and the platform-configuration role writes without
delete.

**Destructive to schema state for its duration**: downgrades one revision and
re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
Disposable databases only. Marked `integration`.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from saas_os.infra.db.config import get_migrations_database_config
from saas_os.infra.db.engine import build_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "a4c8e1f3b7d5"  # pragma: allowlist secret
_PREVIOUS = "d2f7a9c4e6b8"  # pragma: allowlist secret
_TABLE = "ai_model_prices"
_CHECK = "ck_ai_model_prices_extra_units"
_COLUMNS = {
    "cache_write_per_million": ("numeric", "YES", None),
    "per_request": ("numeric", "YES", None),
    "unit_rates": ("json", "YES", None),
    "reviewed_at": ("timestamp with time zone", "YES", None),
}
_NEW_COLUMNS_SQL = ", ".join(f"'{name}'" for name in _COLUMNS)


@pytest.fixture(scope="module")
def admin() -> Iterator[Engine]:
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text(f"SELECT 1 FROM control_plane.{_TABLE} LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _columns(admin: Engine) -> dict[str, tuple[str, str, str | None]]:
    with admin.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT column_name, data_type, is_nullable, column_default "
                "FROM information_schema.columns "
                "WHERE table_schema = 'control_plane' AND table_name = :t "
                f"AND column_name IN ({_NEW_COLUMNS_SQL})"
            ),
            {"t": _TABLE},
        ).all()
    return {row[0]: (row[1], row[2], row[3]) for row in rows}


def _numeric_shape(admin: Engine) -> dict[str, tuple[int, int]]:
    with admin.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT column_name, numeric_precision, numeric_scale "
                "FROM information_schema.columns "
                "WHERE table_schema = 'control_plane' AND table_name = :t "
                "AND column_name IN ('cache_write_per_million', 'per_request')"
            ),
            {"t": _TABLE},
        ).all()
    return {row[0]: (row[1], row[2]) for row in rows}


def _check(admin: Engine) -> str | None:
    with admin.connect() as conn:
        return conn.execute(
            text(
                "SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c "
                "JOIN pg_class t ON t.oid = c.conrelid "
                "JOIN pg_namespace n ON n.oid = t.relnamespace "
                "WHERE n.nspname = 'control_plane' AND t.relname = :t AND c.conname = :n"
            ),
            {"t": _TABLE, "n": _CHECK},
        ).scalar_one_or_none()


def _table_shape(admin: Engine) -> dict[str, object]:
    """Everything of the table the migration must leave alone."""
    with admin.connect() as conn:
        columns = conn.execute(
            text(
                "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                "WHERE table_schema = 'control_plane' AND table_name = :t "
                f"AND column_name NOT IN ({_NEW_COLUMNS_SQL}) ORDER BY column_name"
            ),
            {"t": _TABLE},
        ).all()
        constraints = conn.execute(
            text(
                "SELECT conname, pg_get_constraintdef(c.oid) FROM pg_constraint c "
                "JOIN pg_class t ON t.oid = c.conrelid "
                "JOIN pg_namespace n ON n.oid = t.relnamespace "
                f"WHERE n.nspname = 'control_plane' AND t.relname = :t AND conname <> '{_CHECK}' "
                "ORDER BY conname"
            ),
            {"t": _TABLE},
        ).all()
        indexes = conn.execute(
            text(
                "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'control_plane' "
                "AND tablename = :t ORDER BY indexname"
            ),
            {"t": _TABLE},
        ).all()
        policies = conn.execute(
            text(
                "SELECT policyname, cmd, qual FROM pg_policies "
                "WHERE schemaname = 'control_plane' AND tablename = :t ORDER BY policyname"
            ),
            {"t": _TABLE},
        ).all()
        triggers = conn.execute(
            text(
                "SELECT tgname FROM pg_trigger g JOIN pg_class t ON t.oid = g.tgrelid "
                "JOIN pg_namespace n ON n.oid = t.relnamespace "
                "WHERE n.nspname = 'control_plane' AND t.relname = :t AND NOT g.tgisinternal "
                "ORDER BY tgname"
            ),
            {"t": _TABLE},
        ).all()
        privileges = conn.execute(
            text(
                "SELECT grantee, privilege_type FROM information_schema.role_table_grants "
                "WHERE table_schema = 'control_plane' AND table_name = :t "
                "ORDER BY grantee, privilege_type"
            ),
            {"t": _TABLE},
        ).all()
        rls = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'control_plane' AND c.relname = :t"
            ),
            {"t": _TABLE},
        ).one()
        rows = conn.execute(
            text(
                "SELECT id, model_ref, pricing_version, currency, input_per_million, "
                "output_per_million, cached_input_per_million, effective_from "
                f"FROM control_plane.{_TABLE} ORDER BY id"
            )
        ).all()
    return {
        "columns": [tuple(r) for r in columns],
        "constraints": [tuple(r) for r in constraints],
        "indexes": [tuple(r) for r in indexes],
        "policies": [tuple(r) for r in policies],
        "triggers": [r[0] for r in triggers],
        "privileges": [tuple(r) for r in privileges],
        "rls": tuple(rls),
        "rows": [tuple(r) for r in rows],
    }


def _insert_price(conn: Connection, **extra: str) -> None:
    """One provider, one model and one price row, inside the caller's
    transaction (which the caller rolls back). `extra` holds SQL literals for
    the new columns."""
    suffix = uuid.uuid4().hex[:12]
    provider_id = uuid.uuid4()
    model_id = uuid.uuid4()
    conn.execute(
        text(
            "INSERT INTO control_plane.ai_providers "
            "(id, key, protocol, base_url, credential_ref, status, data_handling, version) "
            "VALUES (:id, :key, 'openai_chat_completions', 'https://prices.example.test/v1', "
            "'AI_TEST_PROVIDER_KEY', 'disabled', '{}', 1)"
        ),
        {"id": provider_id, "key": f"mig-price-{suffix}"},
    )
    conn.execute(
        text(
            "INSERT INTO control_plane.ai_models "
            "(id, provider_id, model_id, capabilities, max_output_tokens, lifecycle, version) "
            "VALUES (:id, :provider, 'model-1', '[]', 1024, 'disabled', 1)"
        ),
        {"id": model_id, "provider": provider_id},
    )
    names = "".join(f", {name}" for name in extra)
    values = "".join(f", {value}" for value in extra.values())
    conn.execute(
        text(
            f"INSERT INTO control_plane.{_TABLE} "
            "(id, model_ref, pricing_version, currency, input_per_million, "
            f"output_per_million, effective_from{names}) "
            f"VALUES (:id, :model, 'v1', 'USD', 1, 2, now(){values})"
        ),
        {"id": uuid.uuid4(), "model": model_id},
    )


def test_the_columns_and_the_check_are_as_designed_at_head(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    assert _columns(admin) == _COLUMNS
    assert _numeric_shape(admin) == {
        "cache_write_per_million": (18, 8),
        "per_request": (18, 8),
    }
    check = _check(admin)
    assert check is not None
    assert "cache_write_per_million >= " in check
    assert "per_request >= " in check
    assert "json_typeof(unit_rates) = 'object'" in check


@pytest.mark.parametrize(
    "extra",
    [
        {"cache_write_per_million": "-0.00000001"},
        {"per_request": "-1"},
        {"unit_rates": "'[]'::json"},
        {"unit_rates": "'\"0.5\"'::json"},
        {"unit_rates": "'3'::json"},
        {"unit_rates": "'null'::json"},
    ],
)
def test_the_check_refuses_a_negative_rate_and_a_non_object(
    admin: Engine, extra: dict[str, str]
) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            with pytest.raises(IntegrityError, match=_CHECK):
                _insert_price(conn, **extra)
        finally:
            trans.rollback()


def test_the_check_admits_absent_rates_zero_rates_and_an_object(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    for extra in (
        {},
        {"cache_write_per_million": "0", "per_request": "0"},
        {"cache_write_per_million": "3.75", "per_request": "0.00000001"},
        {"unit_rates": "'{}'::json"},
        {"unit_rates": '\'{"web_search_requests": "0.01"}\'::json'},
        {"reviewed_at": "now()"},
    ):
        with admin.connect() as conn:
            trans = conn.begin()
            try:
                _insert_price(conn, **extra)
            finally:
                trans.rollback()


def test_the_table_stays_global_and_its_privileges_are_unchanged(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    shape = _table_shape(admin)
    # global platform configuration (ADR-0056): no row-level security, no policy
    assert shape["rls"] == (False, False)
    assert shape["policies"] == []
    app_role = os.environ.get("APP_DB_USER", "saas_os_app")
    config_role = os.environ.get("PLATFORM_CONFIG_DB_USER", "saas_os_platform_config")
    privileges: list[tuple[str, str]] = shape["privileges"]  # type: ignore[assignment]

    def granted(role: str) -> set[str]:
        return {privilege for grantee, privilege in privileges if grantee == role}

    assert granted(app_role) == {"SELECT"}
    assert granted(config_role) == {"SELECT", "INSERT", "UPDATE"}


def test_downgrade_removes_only_the_new_objects_and_upgrade_restores_them_null(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    before = _table_shape(admin)
    try:
        command.downgrade(cfg, _PREVIOUS)
        assert _columns(admin) == {} and _check(admin) is None
        # nothing else changed: the other columns, the constraints (including
        # the version key and the two older checks), the indexes, the
        # privileges, the absence of RLS and the rows with their rates
        assert _table_shape(admin) == before
        command.upgrade(cfg, _REVISION)
        assert _columns(admin) == _COLUMNS and _check(admin) is not None
        assert _table_shape(admin) == before
        with admin.connect() as conn:
            filled = conn.execute(
                text(
                    f"SELECT count(*) FROM control_plane.{_TABLE} "
                    "WHERE cache_write_per_million IS NOT NULL OR per_request IS NOT NULL "
                    "OR unit_rates IS NOT NULL OR reviewed_at IS NOT NULL"
                )
            ).scalar_one()
        # no backfill: an existing price has no extra rate and was never
        # confirmed, so it reads as unverifiable until an operator confirms it
        assert filled == 0
    finally:
        command.upgrade(cfg, "head")


def test_the_upgrade_finds_columns_added_by_hand(admin: Engine) -> None:
    """`ADD COLUMN IF NOT EXISTS`: an operator who added the columns beforehand
    finds them in place, and the check is added over them."""
    cfg = _config()
    command.upgrade(cfg, "head")
    try:
        command.downgrade(cfg, _PREVIOUS)
        with admin.begin() as conn:
            conn.execute(
                text(
                    f"ALTER TABLE control_plane.{_TABLE} "
                    "ADD COLUMN cache_write_per_million numeric(18,8), "
                    "ADD COLUMN per_request numeric(18,8), "
                    "ADD COLUMN unit_rates json, "
                    "ADD COLUMN reviewed_at timestamptz"
                )
            )
        command.upgrade(cfg, _REVISION)
        assert _columns(admin) == _COLUMNS and _check(admin) is not None
    finally:
        command.upgrade(cfg, "head")
