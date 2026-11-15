"""Test support: empty the platform and tenant audit reference tables.

Audit identity phase P1 (migration `e2b7c4d9a1f6`): every platform operation
that targets a user writes a row to `core.platform_audit_subject_links`, and
identity erasure writes a marker to `core.platform_audit_subject_erasures`.
The tables have a foreign key onto `core.users`, and the migration refuses to
be downgraded while any of the three tables holds a row, so tests that delete
users or downgrade the schema must start from empty tables. The runtime role
cannot delete from them; this uses the migrations role, the way the platform
test helpers clear the platform tables. It only touches those three tables and
never fails a test: a database that is not configured, not reachable or not
at that revision is skipped silently.

**Disposable databases only.** TRUNCATE is destructive, so before it runs the
migrations database URL must name a loopback host (`localhost`, `127.0.0.0/8`,
`::1`: the disposable PostgreSQL of the local scripts and of CI) or the run
must say so with `SAAS_OS_TEST_DATABASE_DISPOSABLE=1`. Anything else raises
`RuntimeError` and nothing is truncated. (`ENVIRONMENT` is not consulted: tests
set it to `production` or `staging` on purpose while this runs.)
The other test cleanups rely on a docstring; this one checks.

Used by `tests/conftest.py` (after every integration test body) and by
`lifecycle_callers.enroll_test_operator`, whose enrolment writes the
operator's reference inside a test that may downgrade the schema right after.
"""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from typing import Any

_TABLES = (
    "core.platform_audit_subject_links",
    "core.platform_audit_subject_erasures",
    "core.platform_audit_identity_holds",
    # Audit identity phase P3a (migration `c7e3a9f2b4d8`): the tenant tables.
    # Their foreign keys onto `core.tenants` and `core.users` would otherwise
    # block the tests that delete their tenants and users. TRUNCATE is not
    # subject to row-level security.
    "core.audit_subject_links",
    "core.audit_subject_erasures",
    "core.audit_identity_holds",
)


@lru_cache(maxsize=1)
def _engine() -> Any:
    from saas_os.infra.db.config import get_migrations_database_config
    from saas_os.infra.db.engine import build_engine

    return build_engine(get_migrations_database_config(), connect_args={"connect_timeout": 2})


_OPT_IN = "SAAS_OS_TEST_DATABASE_DISPOSABLE"


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_disposable_database(url: str) -> None:
    """Raise `RuntimeError` unless `url` looks like a disposable test database
    (see the module docstring)."""
    from sqlalchemy.engine import make_url

    host = make_url(url).host
    if _is_loopback(host) or os.environ.get(_OPT_IN) == "1":
        return
    raise RuntimeError(
        f"refusing to truncate audit reference tables on host {host!r}: not a loopback "
        f"database; set {_OPT_IN}=1 if it is disposable"
    )


def resolve_tenant_reference(tenant_id: object, reference: object) -> str | None:
    """Test support (audit identity phase P3a): the user id a tenant audit
    reference is linked to, or `None` when it is unlinked or unknown. Reads
    as the migrations role inside a transaction bound to `tenant_id`: the
    tenant tables are under FORCE RLS, which binds the owner too. Read only."""
    from sqlalchemy import text

    with _engine().begin() as conn:
        conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)})
        value = conn.execute(
            text(
                "SELECT user_id FROM core.audit_subject_links "
                "WHERE tenant_id = CAST(:t AS uuid) AND subject_ref = CAST(:r AS uuid)"
            ),
            {"t": str(tenant_id), "r": str(reference)},
        ).scalar()
    return None if value is None else str(value)


def clear_platform_audit_references() -> None:
    """Empty the three reference tables with the migrations role; a no-op
    when there is no database or the tables do not exist. Raises
    `RuntimeError`, before touching anything, when the database does not look
    disposable."""
    url = os.environ.get("MIGRATIONS_DATABASE_URL")
    if not url:
        return
    assert_disposable_database(url)
    try:
        from sqlalchemy import text

        with _engine().begin() as conn:
            # Never wait behind a lock a test still holds: give up instead.
            conn.execute(text("SET LOCAL lock_timeout = '5s'"))
            # Only the tables present at the database's revision.
            present = [
                table
                for table in _TABLES
                if conn.execute(text("SELECT to_regclass(:t)"), {"t": table}).scalar()
            ]
            if present:
                conn.execute(text("TRUNCATE " + ", ".join(present)))
    except Exception:  # noqa: BLE001 -- cleanup only; never fail a test
        return
