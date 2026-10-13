"""Session lifecycle management (docs/IMPLEMENTATION-ROADMAP.md Phase 2.1,
tenant-scoping enforcement completed in Phase 3.1).

`session_scope()` is the single sanctioned way to obtain a database
session: a context manager that commits on success, rolls back on
exception, and always closes. No other module opens its own `Session`
directly (docs/MULTI-TENANCY.md section 3: `saas_os/infra/db` is the single
database-access chokepoint).

`tenant_session_scope()` is the same chokepoint, additionally binding the
session to one tenant for its whole transaction: it sets the PostgreSQL
session variable `app.tenant_id` (via `set_config(..., is_local=true)`,
parameter-bound -- never string-interpolated, so an arbitrary/malicious
value can only ever end up stored as an inert setting, never executed as
SQL) that every tenant-owned table's Row-Level Security policy checks
(`saas_os.infra.db.rls`). `is_local=true` is deliberate: the setting is scoped to
the current transaction only and is guaranteed reset by PostgreSQL at
COMMIT/ROLLBACK, even though the underlying connection is pooled and
reused across unrelated sessions -- a session that used
`session_scope()` (no tenant) or a different tenant's
`tenant_session_scope()` earlier on the same pooled connection cannot
leak its setting forward into a later, unrelated transaction.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from functools import lru_cache

from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from saas_os.infra.db.engine import get_engine


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Construct a new session factory bound to an explicit engine.
    Exposed for tests that need a session factory pointed at something
    other than the process-wide engine (docs/IMPLEMENTATION-ROADMAP.md
    Phase 2.1 task 10)."""
    return sessionmaker(bind=engine)


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    """Cached session-factory singleton for the process, bound to
    `saas_os.infra.db.engine.get_engine()`."""
    return build_session_factory(get_engine())


@contextmanager
def session_scope(*, session_factory: sessionmaker[Session] | None = None) -> Iterator[Session]:
    """The single sanctioned way to obtain a database session.

    `session_factory` defaults to the process-wide `get_session_factory()`;
    pass an explicit one in tests to point at a different engine without
    touching global/cached state.
    """
    factory = session_factory or get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def tenant_session_scope(
    tenant_id: uuid.UUID, *, session_factory: sessionmaker[Session] | None = None
) -> Iterator[Session]:
    """The sanctioned way to obtain a database session scoped to one
    tenant for the duration of its transaction (docs/MULTI-TENANCY.md
    section 3). `tenant_id` must be a real `uuid.UUID` -- not a string --
    so a caller cannot pass an arbitrary/malformed value through by
    accident; it is then bound as a query parameter to `set_config()`,
    never interpolated into SQL text.
    """
    if not isinstance(tenant_id, uuid.UUID):
        raise TypeError(f"tenant_id must be a uuid.UUID, got {type(tenant_id).__name__!r}")

    with session_scope(session_factory=session_factory) as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )
        yield session


@contextmanager
def bind_tenant_scope(session: Session, tenant_id: uuid.UUID) -> Iterator[Session]:
    """Re-scope `session`'s *current* transaction to `tenant_id` for the
    duration of the block, then restore whatever tenant scope (or none)
    the transaction had before -- the in-transaction counterpart of
    `tenant_session_scope()` (Foundation Authority & Evidence, ADR-0031).

    It exists for exactly one need: `saas_os.core.rbac.can()` must evaluate an
    authorization decision *inside the protected mutation's own
    transaction* (so the rows it relies on stay locked until that
    mutation commits), yet the decision reads RLS-protected rows at more
    than one tenant (the target and each `SUBTREE` ancestor). Opening a
    second `tenant_session_scope()` per candidate would put those reads in
    separate, already-committed transactions -- the stale-authority window
    this primitive closes.

    It grants nothing `tenant_session_scope()` does not already grant (any
    caller can open a session scoped to any tenant it names); it only lets
    that happen within one transaction. The value is parameter-bound,
    `is_local=true` (reset by PostgreSQL at COMMIT/ROLLBACK, so nothing can
    leak past the transaction onto the pooled connection), and the prior
    binding is restored on exit. If the block fails with a database error
    the transaction is already aborted and will be rolled back -- which
    resets the setting itself -- so a failed restore never masks the
    original error.
    """
    if not isinstance(tenant_id, uuid.UUID):
        raise TypeError(f"tenant_id must be a uuid.UUID, got {type(tenant_id).__name__!r}")

    prior = session.execute(
        text("SELECT coalesce(current_setting('app.tenant_id', true), '')")
    ).scalar_one()
    session.execute(
        text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
        {"tenant_id": str(tenant_id)},
    )
    try:
        yield session
    except BaseException:
        with suppress(SQLAlchemyError):
            _restore_tenant_scope(session, prior)
        raise
    _restore_tenant_scope(session, prior)


def _restore_tenant_scope(session: Session, prior: str) -> None:
    session.execute(
        text("SELECT set_config('app.tenant_id', :tenant_id, true)"), {"tenant_id": prior}
    )


def acquire_tenant_advisory_lock(session: Session, tenant_id: uuid.UUID, key: str) -> None:
    """Acquire a PostgreSQL transaction-scoped advisory lock
    (`pg_advisory_xact_lock`), keyed by `(tenant_id, key)`, on `session`'s
    current transaction (P1.9: `saas_os.core.usage.service.consume_quota()`'s
    atomic check-and-consume mechanism). Auto-released at COMMIT/ROLLBACK
    -- no explicit unlock call exists or is needed.

    This is `saas_os/infra/db`'s one sanctioned, narrowly-scoped exception to "no
    raw SQL outside this chokepoint" (docs/MULTI-TENANCY.md section 3,
    enforced by `tests/infra/test_db_public_surface_unit.py::
    test_no_raw_connection_is_available_outside_the_chokepoint`'s own
    curated export whitelist, run in the default suite -- PRIV-03 P6
    moved it out of the integration-only file where its failure had gone
    unnoticed): PostgreSQL advisory locks have no
    SQLAlchemy Core/ORM expression equivalent, so a literal
    `pg_advisory_xact_lock(...)` call is unavoidable -- but it is
    expressed here, once, as a named primitive a caller invokes with a
    real `uuid.UUID` and a plain string, never as a generic `text()`
    escape hatch exposed to Core/Product/Control-Plane code directly.
    Both arguments are bound as query parameters -- never interpolated
    into SQL text -- and hashed via PostgreSQL's own `hashtext()` into
    the two-int4-argument overload of `pg_advisory_xact_lock`, so lock
    identity collisions are already as unlikely as `hashtext`'s own
    distribution, with no bit-packing logic needed on the Python side.
    """
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:tenant_id), hashtext(:key))"),
        {"tenant_id": str(tenant_id), "key": key},
    )


_QUERY_CANCELED_SQLSTATE = "57014"
_MAX_STATEMENT_TIMEOUT_MILLISECONDS = 2_147_483_647


def set_local_statement_timeout(session: Session, milliseconds: int) -> None:
    """Bound every later statement of `session`'s current transaction to
    `milliseconds`, lock waits included (PostgreSQL `statement_timeout`;
    ADR-0045 section 9d). A statement that runs longer is cancelled by
    PostgreSQL, which aborts the transaction; `is_statement_timeout()`
    recognises the error.

    Transaction-local, like `app.tenant_id`: set with
    `set_config(..., is_local=true)`, so PostgreSQL resets it at COMMIT or
    ROLLBACK and it never reaches the next user of the pooled connection.
    The value is bound as a query parameter, never interpolated.

    It bounds each statement, not the transaction: a transaction of `n`
    statements can run for `n` times the value. PostgreSQL 16 has no
    transaction-wide timeout.

    Like `acquire_tenant_advisory_lock()`, a named primitive rather than
    a `text()` escape hatch: a caller passes an integer and nothing else.
    """
    if (
        isinstance(milliseconds, bool)
        or not isinstance(milliseconds, int)
        or not 1 <= milliseconds <= _MAX_STATEMENT_TIMEOUT_MILLISECONDS
    ):
        raise ValueError("milliseconds must be a positive integer.")
    session.execute(
        text("SELECT set_config('statement_timeout', :milliseconds, true)"),
        {"milliseconds": str(milliseconds)},
    )


def is_statement_timeout(error: BaseException) -> bool:
    """`True` if `error` is PostgreSQL cancelling a statement (SQLSTATE
    57014, `query_canceled`), as it does when `statement_timeout`
    expires. PostgreSQL uses the same code when an administrator cancels
    the backend's statement, and the two cannot be told apart without
    reading the server's translated message; either way the statement did
    not finish."""
    original = getattr(error, "orig", None)
    return getattr(original, "sqlstate", None) == _QUERY_CANCELED_SQLSTATE


_TRANSACTION_CONFLICT_SQLSTATES = frozenset({"40P01", "40001"})


def is_transaction_conflict(error: BaseException) -> bool:
    """`True` if `error` is PostgreSQL aborting a transaction to resolve a
    conflict with another one: a deadlock (SQLSTATE 40P01) or a
    serialization failure (40001). Nothing of the aborted transaction was
    committed, and repeating the operation is safe."""
    original = getattr(error, "orig", None)
    return getattr(original, "sqlstate", None) in _TRANSACTION_CONFLICT_SQLSTATES
