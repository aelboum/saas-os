"""Session lifecycle management (docs/IMPLEMENTATION-ROADMAP.md Phase 2.1,
tenant-scoping enforcement completed in Phase 3.1).

`session_scope()` is the single sanctioned way to obtain a database
session: a context manager that commits on success, rolls back on
exception, and always closes. No other module opens its own `Session`
directly (docs/MULTI-TENANCY.md section 3: `infra/db` is the single
database-access chokepoint).

`tenant_session_scope()` is the same chokepoint, additionally binding the
session to one tenant for its whole transaction: it sets the PostgreSQL
session variable `app.tenant_id` (via `set_config(..., is_local=true)`,
parameter-bound -- never string-interpolated, so an arbitrary/malicious
value can only ever end up stored as an inert setting, never executed as
SQL) that every tenant-owned table's Row-Level Security policy checks
(`infra.db.rls`). `is_local=true` is deliberate: the setting is scoped to
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
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from infra.db.engine import get_engine


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Construct a new session factory bound to an explicit engine.
    Exposed for tests that need a session factory pointed at something
    other than the process-wide engine (docs/IMPLEMENTATION-ROADMAP.md
    Phase 2.1 task 10)."""
    return sessionmaker(bind=engine)


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    """Cached session-factory singleton for the process, bound to
    `infra.db.engine.get_engine()`."""
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


def acquire_tenant_advisory_lock(session: Session, tenant_id: uuid.UUID, key: str) -> None:
    """Acquire a PostgreSQL transaction-scoped advisory lock
    (`pg_advisory_xact_lock`), keyed by `(tenant_id, key)`, on `session`'s
    current transaction (P1.9: `core.usage.service.consume_quota()`'s
    atomic check-and-consume mechanism). Auto-released at COMMIT/ROLLBACK
    -- no explicit unlock call exists or is needed.

    This is `infra/db`'s one sanctioned, narrowly-scoped exception to "no
    raw SQL outside this chokepoint" (docs/MULTI-TENANCY.md section 3,
    enforced by `tests/infra/test_db_integration.py::
    test_no_raw_connection_is_available_outside_the_chokepoint`'s own
    curated export whitelist): PostgreSQL advisory locks have no
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
