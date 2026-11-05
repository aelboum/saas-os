"""Suite-wide test hooks.

**The platform audit reference tables are emptied after the body of every
integration test** (audit identity phase P1, migration `e2b7c4d9a1f6`). Every
platform operation that targets a user (enrolling or revoking an operator,
revoking a user's sessions, resolving a user, ...) now writes a row to
`core.platform_audit_subject_links`, and identity erasure writes a marker to
`core.platform_audit_subject_erasures`. Two things depend on those tables
being empty between tests:

- the tests and fixtures that delete the users they created: both tables
  have a foreign key onto `core.users`, so a user that still has a row cannot
  be deleted (no application path deletes a user; test teardown does);
- the migration rollback tests: the migration refuses to be downgraded while
  any of the three tables holds a row (the link table is the only way to
  resolve a reference already written to the audit log), and CI runs the whole
  integration suite in one serial process against one database, so rows left
  by an earlier test would fail the later rollback tests (the lesson of
  PR #192).

The runtime role cannot delete from these tables; the hook does it with the
migrations role, the way the platform test helpers clear the platform tables.
It runs right after the test body, before the fixtures' teardown, which is
when the users are deleted. It only touches the three tables of that
migration, only for tests marked `integration`, and never fails a test: a
database that is not configured, not reachable or not at that revision is
skipped silently. A test that needs its rows across tests of one module must
not rely on them (no test does).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from audit_references import clear_platform_audit_references


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Iterator[None]:
    yield
    if item.get_closest_marker("integration") is not None:
        clear_platform_audit_references()
