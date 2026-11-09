"""Errors of the AI inference configuration. Messages carry a short reason
code only -- never a URL, a credential or a secret name's value."""

from __future__ import annotations


class AIConfigurationError(ValueError):
    """An invalid configuration request; nothing was changed."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"AI configuration refused: {reason}")


class AIConfigurationNotFoundError(LookupError):
    def __init__(self, kind: str) -> None:
        self.kind = kind
        super().__init__(f"AI configuration not found: {kind}")


class AITenantPolicyError(ValueError):
    """An invalid tenant AI policy request; nothing was changed. For
    `destination_not_eligible`, `blocked_by` lists the closed reason codes
    (`model_disabled`, `model_retired`, `destination_policy_denied`,
    `residency`, `retention`, `training_use`); it is empty otherwise."""

    def __init__(self, reason: str, *, blocked_by: tuple[str, ...] = ()) -> None:
        self.reason = reason
        self.blocked_by = blocked_by
        super().__init__(f"tenant AI policy refused: {reason}")


class AITenantHoldError(ValueError):
    """A refused tenant AI hold request; nothing was changed. `reason` is a
    short code: `invalid_reason`, `tenant_unavailable` (an unknown and a
    closed tenant are indistinguishable), `already_held`, `not_held`."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"tenant AI hold refused: {reason}")
