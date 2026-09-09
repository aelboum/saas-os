"""Pure unit tests for `control_plane.development` -- no database, no
network. Proves the substitution-test property (docs/IMPLEMENTATION-ROADMAP.md
Phase 7.3's own Tests requirement, mirrors `core/billing`'s established
pattern) and the structural "cannot merge/push directly" guarantee.
"""

from __future__ import annotations

from control_plane.development.provider import (
    FakePullRequestProvider,
    FileChange,
    PullRequestProvider,
)


def test_fake_provider_satisfies_the_pull_request_provider_protocol() -> None:
    """Substitution test: `FakePullRequestProvider` structurally satisfies
    the same interface a real provider (e.g. `GitHubPullRequestProvider`)
    must -- mirrors `core/billing`'s own `isinstance(FakeBillingProvider(),
    BillingProvider)` proof."""
    assert isinstance(FakePullRequestProvider(), PullRequestProvider)


def test_pull_request_provider_protocol_has_no_merge_or_push_method() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 7.3's own Tests requirement:
    "it cannot merge or push directly to a protected branch" -- proven as
    a structural property of the interface itself, not a runtime
    permission check that could be misconfigured."""
    protocol_members = set(dir(PullRequestProvider))
    assert "merge_pull_request" not in protocol_members
    assert "push" not in protocol_members
    assert "merge" not in protocol_members


def test_fake_provider_has_no_merge_or_push_method_either() -> None:
    fake_methods = {
        m
        for m in dir(FakePullRequestProvider)
        if not m.startswith("_") and callable(getattr(FakePullRequestProvider, m))
    }
    assert fake_methods == {"open_pull_request"}


def test_fake_provider_records_opened_pull_requests() -> None:
    provider = FakePullRequestProvider()
    pr_id = provider.open_pull_request(
        repository="example/sandbox-repo",
        base_branch="main",
        branch_name="agent/proposed-change",
        title="Fix typo",
        body="Fixes a typo in the README.",
        file_changes=[FileChange(path="README.md", content="fixed content")],
    )
    assert pr_id in provider.opened_pull_requests
    recorded = provider.opened_pull_requests[pr_id]
    assert recorded["repository"] == "example/sandbox-repo"
    assert recorded["base_branch"] == "main"


def test_fake_provider_opened_pull_requests_start_empty() -> None:
    assert FakePullRequestProvider().opened_pull_requests == {}
