"""Typed errors for `control_plane.development`
(docs/IMPLEMENTATION-ROADMAP.md Phase 7.3)."""

from __future__ import annotations


class PullRequestProviderError(RuntimeError):
    """Raised when a `PullRequestProvider` implementation fails to open a
    pull request -- never carries the provider credential (mirrors
    `core/billing/errors.py::BillingProviderError`'s own convention)."""

    def __init__(self, operation: str, reason: str) -> None:
        self.operation = operation
        super().__init__(f"Pull request provider operation {operation!r} failed: {reason}")


class RepositoryScopeMismatchError(PermissionError):
    """Raised when the invoking agent's declared repository scope does
    not match the target repository of a proposed pull request --
    docs/AI-CONTROL-PLANE.md section 7: "no broader credential is
    granted" -- this is a defense-in-depth check inside the tool handler
    itself, independent of `control_plane.orchestration`'s own scope-match
    authorization gate."""

    def __init__(self, agent_scope_value: str | None, target_repository: str) -> None:
        self.agent_scope_value = agent_scope_value
        self.target_repository = target_repository
        super().__init__(
            f"Agent scoped to {agent_scope_value!r} is not authorized to act on repository "
            f"{target_repository!r}."
        )
