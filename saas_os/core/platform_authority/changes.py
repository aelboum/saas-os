"""A platform mutation whose change is supplied by its caller (ADR-0054 AI-C).

Platform operations defined outside Core (the AI Control Plane's provider
configuration, `saas_os.control_plane.inference.config`) need exactly the
transaction Core's own platform mutations use -- refusal recording, the
mutation statement timeout, authorization in the transaction, and the
platform audit row in the same transaction -- without opening an untenanted
session themselves (ADR-0022; tests/architecture/test_tenant_session_boundary.py
allows untenanted openers only in Core). `run_platform_change()` is that
transaction. The change itself runs after authorization, and the success
audit row is written before commit, so a change and its evidence commit
together or not at all. Its callers are direct importers of the platform
authority package, pinned by `_APPROVED_DIRECT_IMPORTERS` in
tests/architecture/test_platform_authority_contract.py.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from saas_os.core.authority import ServiceAccountCaller, require_caller
from saas_os.core.platform_authority.audit import (
    record_platform_event_in_transaction,
    recording_platform_refusal,
    validate_reason,
)
from saas_os.core.platform_authority.authorization import (
    authorize_platform_caller,
    platform_operation,
)
from saas_os.core.platform_authority.errors import PlatformNotAuthorizedError
from saas_os.core.platform_authority.transactions import platform_change_session
from saas_os.infra.db import Session


@dataclass(frozen=True)
class PlatformChange:
    """What a change returns: its value and the facts its audit row records."""

    value: Any
    target_id: str | None = None
    target_tenant_id: uuid.UUID | None = None
    metadata: Mapping[str, object] | None = field(default=None)


def run_platform_change(
    *,
    caller: object,
    operation: str,
    target_type: str,
    change: Callable[[Session], PlatformChange],
    reason: str | None = None,
) -> Any:
    """Authorize `caller` for the platform `operation`, run `change` in the
    same untenanted transaction, and record the platform audit row before
    commit. A refusal is recorded as a `denied` row (best effort, after
    rollback) and re-raised; any other error rolls everything back."""
    require_caller(operation, caller)
    if isinstance(caller, ServiceAccountCaller):
        raise PlatformNotAuthorizedError(operation)
    if reason is not None:
        validate_reason(reason)
    spec = platform_operation(operation)
    with (
        recording_platform_refusal(caller=caller, operation=operation, target_type=target_type),
        platform_change_session(caller, operation) as session,
    ):
        authorize_platform_caller(caller, session=session, operation=operation)
        outcome = change(session)
        record_platform_event_in_transaction(
            session,
            caller=caller,
            action=spec.audit_action,
            target_type=target_type,
            target_id=outcome.target_id,
            target_tenant_id=outcome.target_tenant_id,
            reason=reason,
            metadata=dict(outcome.metadata) if outcome.metadata is not None else None,
        )
        return outcome.value
