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
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from saas_os.core.authority import SystemCaller
from saas_os.core.platform_authority.config import get_platform_mutation_config
from saas_os.core.platform_authority.errors import PlatformOperationTimeoutError
from saas_os.infra.db import (
    OperationalError,
    Session,
    is_statement_timeout,
    session_scope,
    set_local_statement_timeout,
)


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
        with session_scope() as session:
            yield session
        return
    timeout_ms = get_platform_mutation_config().statement_timeout_ms
    try:
        with session_scope() as session:
            set_local_statement_timeout(session, timeout_ms)
            yield session
    except OperationalError as error:
        if is_statement_timeout(error):
            raise PlatformOperationTimeoutError(operation, timeout_ms) from error
        raise
