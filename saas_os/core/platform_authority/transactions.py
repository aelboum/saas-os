"""The transaction of a platform mutation (ADR-0045, amendment of
2026-10-14: platform mutations carry a statement timeout).

`platform_change_session()` replaces `session_scope()` at the opening of
every transaction that performs a platform operation. Unless the caller is
a system purpose, its first statement sets the configured statement
timeout (`PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS`) for that transaction
only, so that every later statement -- the locks taken before the
authorization included -- is bounded; a statement PostgreSQL cancels
leaves the block as `PlatformOperationTimeoutError`, after the transaction
was rolled back. That covers a person (`UserCaller`) and also a caller the
operation goes on to refuse (a service account, a malformed caller), which
must not wait on a lock without limit before it is refused either.

A system purpose (`SystemCaller`) gets a plain `session_scope()`: those
run as commands and jobs, and a purge may legitimately run long
statements.

ADR-0056: an operation in `PLATFORM_CONFIGURATION_OPERATIONS` (the AI
configuration writes) runs its whole transaction -- authorization, change
and audit row -- on the platform-configuration connection
(`saas_os.infra.db.platform_config`), whatever the caller. The operation
key selects it, never an argument; without that connection's credential the
operation fails with `DatabaseConfigurationError` before any statement, and
the application role could not write those tables anyway. This module is
the only importer of that connection.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager

from saas_os.core.authority import SystemCaller
from saas_os.core.platform_authority.config import get_platform_mutation_config
from saas_os.core.platform_authority.errors import PlatformOperationTimeoutError
from saas_os.core.platform_authority.operations import PLATFORM_CONFIGURATION_OPERATIONS
from saas_os.infra.db import (
    OperationalError,
    Session,
    is_statement_timeout,
    session_scope,
    set_local_statement_timeout,
)
from saas_os.infra.db.platform_config import platform_config_session_scope


def _open(operation: str) -> AbstractContextManager[Session]:
    # Both openers are named calls here, so the tenant-session boundary
    # scan (tests/architecture/test_tenant_session_boundary.py) sees them.
    if operation in PLATFORM_CONFIGURATION_OPERATIONS:
        return platform_config_session_scope()
    return session_scope()


@contextmanager
def platform_change_session(caller: object, operation: str) -> Iterator[Session]:
    """`session_scope()` for one platform mutation's transaction, bounded
    by the mutation statement timeout unless `caller` is a system purpose.
    `operation` is what the timeout error names: an operation key, or for
    a check that is not one, a fixed label (a permission value,
    `"operator.check"`, `"identity.erase"`).

        with platform_change_session(caller, TENANT_MOVE) as session:
            ...
    """
    if isinstance(caller, SystemCaller):
        with _open(operation) as session:
            yield session
        return
    timeout_ms = get_platform_mutation_config().statement_timeout_ms
    try:
        with _open(operation) as session:
            set_local_statement_timeout(session, timeout_ms)
            yield session
    except OperationalError as error:
        if is_statement_timeout(error):
            raise PlatformOperationTimeoutError(operation, timeout_ms) from error
        raise
