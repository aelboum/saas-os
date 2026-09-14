"""`infra.db.orm` public-surface tests (CP-07 J-INFRA-05 remediation).

A live security audit proved that the raw `sqlalchemy.func` namespace,
previously re-exported by `infra.db`, let ordinary Core/Product code call
`func.set_config("app.tenant_id", ..., False)` -- bypassing Row-Level
Security for the rest of the current transaction (and, because
`is_local=False` is session- not transaction-scoped, potentially for
whatever the pooled connection is reused for next). `func` is removed
from the public surface entirely; `now()`/`sum_()` are the two named,
single-purpose replacements for the only two `func` calls any current
consumer actually used.

Pure unit tests -- no database needed. `tests/infra/db/test_func_export_removed_integration.py`
covers the same removal end-to-end against a real, RLS-protected table.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func as _real_sqlalchemy_func

# --- The export is gone -----------------------------------------------------


def test_func_is_not_in_infra_db_public_all() -> None:
    import infra.db

    assert "func" not in infra.db.__all__


def test_func_is_not_in_infra_db_orm_public_all() -> None:
    import infra.db.orm as orm

    assert "func" not in orm.__all__


def test_func_is_not_an_attribute_of_infra_db() -> None:
    """Stronger than the `__all__` check above: `__all__` only governs
    `from infra.db import *`, not `from infra.db import func` directly --
    this proves the name itself is gone, not merely unlisted."""
    import infra.db

    assert not hasattr(infra.db, "func")


def test_func_is_not_an_attribute_of_infra_db_orm() -> None:
    import infra.db.orm as orm

    assert not hasattr(orm, "func")


def test_from_infra_db_import_func_fails() -> None:
    """The exact regression this finding requires: `from infra.db import
    func` -- the shape the original exploit used -- must raise, not
    silently hand back the unrestricted SQLAlchemy function namespace."""
    with pytest.raises(ImportError):
        from infra.db import func  # noqa: F401  # pyright: ignore[reportAttributeAccessIssue]


def test_from_infra_db_orm_import_func_fails() -> None:
    """Same check one layer down -- `infra.db.orm` is where `func` used
    to be imported *from* `sqlalchemy`; a caller reaching past
    `infra.db.__init__` directly at `infra.db.orm` must not find it
    either."""
    with pytest.raises(ImportError):
        from infra.db.orm import func  # noqa: F401  # pyright: ignore[reportAttributeAccessIssue]


def test_no_exported_name_exposes_the_underlying_func_namespace_or_set_config() -> None:
    """Non-vacuous, exhaustive proof: walk every name `infra.db` actually
    exports and confirm none of them *is* the raw `sqlalchemy.func`
    object, and none of them exposes a `.set_config` attribute -- the
    exact shape (`select`/`func`, then `func.set_config(...)`) the
    original exploit used, so this would also catch a future re-export
    under a different alias, not just the literal name `func`."""
    import infra.db

    for name in infra.db.__all__:
        obj = getattr(infra.db, name)
        assert obj is not _real_sqlalchemy_func, (
            f"infra.db.{name} is an alias for the raw sqlalchemy.func "
            "namespace -- exactly the capability this finding removes."
        )
        assert not hasattr(obj, "set_config"), (
            f"infra.db.{name} unexpectedly exposes .set_config -- the "
            "PostgreSQL session-mutating function the original exploit called."
        )


# --- The replacements behave identically to the removed func calls ---------


def test_now_produces_the_same_sql_as_func_now() -> None:
    from infra.db.orm import now

    assert str(now()) == str(_real_sqlalchemy_func.now())


def test_now_compiles_to_a_now_function_call() -> None:
    from infra.db.orm import now

    compiled = str(now().compile(compile_kwargs={"literal_binds": True}))
    assert compiled.strip().lower() == "now()"


def test_sum_produces_the_same_sql_as_func_sum() -> None:
    from infra.db.orm import sum_
    from sqlalchemy import Column, Integer, MetaData, Table

    metadata = MetaData()
    table = Table("widgets", metadata, Column("quantity", Integer))

    assert str(sum_(table.c.quantity)) == str(_real_sqlalchemy_func.sum(table.c.quantity))


def test_sum_compiles_to_a_sum_function_call_over_the_given_column() -> None:
    from infra.db.orm import sum_
    from sqlalchemy import Column, Integer, MetaData, Table

    metadata = MetaData()
    table = Table("widgets", metadata, Column("quantity", Integer))

    compiled = str(sum_(table.c.quantity))
    assert compiled.lower() == "sum(widgets.quantity)"


def test_timestamp_mixin_still_uses_a_now_server_default() -> None:
    """Non-vacuous proof that `TimestampMixin` -- the actual production
    consumer -- was migrated too, not just that a standalone `now()`
    helper exists somewhere unused. Uses a real, minimally-mapped
    subclass: `TimestampMixin`'s own `mapped_column(...)` constructs are
    not yet real `Column` objects until Declarative actually maps them."""
    from infra.db.orm import Base, TimestampMixin, UUIDPrimaryKeyMixin

    class _ScratchModel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
        __tablename__ = "j_infra_05_scratch_model"

    table = _ScratchModel.__table__
    created_at_default = table.c.created_at.server_default.arg
    updated_at_default = table.c.updated_at.server_default.arg
    updated_at_onupdate = table.c.updated_at.onupdate.arg

    assert str(created_at_default).strip().lower() == "now()"
    assert str(updated_at_default).strip().lower() == "now()"
    assert str(updated_at_onupdate).strip().lower() == "now()"
