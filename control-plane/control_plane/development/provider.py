"""The pull-request-provider abstraction (docs/IMPLEMENTATION-ROADMAP.md
Phase 7.3; mirrors `core/billing/provider.py::BillingProvider`'s own
provider-abstraction pattern exactly).

`PullRequestProvider` is a `@runtime_checkable` `typing.Protocol` with
exactly one capability: `open_pull_request()`. Deliberately no
`merge_pull_request()`/`push()` method exists anywhere on this interface
-- this is what makes "the tool cannot merge or push directly to a
protected branch" (docs/IMPLEMENTATION-ROADMAP.md Phase 7.3's own Tests
requirement) a *structural* property of the abstraction itself, provable
by inspecting the Protocol's own method set, not a runtime permission
check that could be misconfigured or bypassed.

`FakePullRequestProvider` is the substitution-test double every test in
this phase runs against by default -- no live GitHub network access
needed, exactly mirroring how `core/billing/test_billing_integration.py`
runs against `FakeBillingProvider` by default and only
`test_billing_stripe_integration.py` (skipping cleanly without a real
key) exercises the live provider.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class FileChange:
    path: str
    content: str


@runtime_checkable
class PullRequestProvider(Protocol):
    def open_pull_request(
        self,
        *,
        repository: str,
        base_branch: str,
        branch_name: str,
        title: str,
        body: str,
        file_changes: list[FileChange],
    ) -> str:
        """Open a pull request against `repository`. Returns the
        provider's own pull-request identifier (e.g. a URL or PR
        number). Never merges, never pushes directly to `base_branch`."""
        ...


class FakePullRequestProvider:
    """In-memory `PullRequestProvider` -- no network access, no
    credential. `opened_pull_requests` lets a test assert exactly what
    was proposed without a live GitHub sandbox."""

    def __init__(self) -> None:
        self.opened_pull_requests: dict[str, dict[str, object]] = {}

    def open_pull_request(
        self,
        *,
        repository: str,
        base_branch: str,
        branch_name: str,
        title: str,
        body: str,
        file_changes: list[FileChange],
    ) -> str:
        pr_id = f"fake-pr-{uuid.uuid4().hex[:8]}"
        self.opened_pull_requests[pr_id] = {
            "repository": repository,
            "base_branch": base_branch,
            "branch_name": branch_name,
            "title": title,
            "body": body,
            "file_changes": list(file_changes),
        }
        return pr_id
