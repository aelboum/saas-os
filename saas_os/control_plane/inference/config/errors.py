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
    """An invalid tenant AI policy request; nothing was changed."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"tenant AI policy refused: {reason}")
