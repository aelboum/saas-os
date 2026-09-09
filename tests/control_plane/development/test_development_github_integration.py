"""Pull-request-provider integration test against GitHub's real API
(docs/IMPLEMENTATION-ROADMAP.md Phase 7.3's own Tests requirement: "the
tool can open a PR in a test/sandbox repository context").

Every assertion below is against `PullRequestProvider`'s own interface
(`open_pull_request()`'s return value) -- never against a raw GitHub API
response shape -- so this test would still pass unmodified if the
provider were swapped for a different code-hosting service entirely
(mirrors `tests/core/billing/test_billing_stripe_integration.py`'s own
discipline).

Marked `integration` and excluded from the default `pytest` run. Skips
cleanly when `GITHUB_TOKEN` is not configured (mirrors
`test_billing_stripe_integration.py`'s own `STRIPE_API_KEY` skip
convention) -- this environment has no real GitHub sandbox repository or
token, so this test is expected to skip here, not fail. A maintainer
with a real GitHub token and a disposable sandbox repository can run it
locally:

    GITHUB_TOKEN=ghp_... \\
    GITHUB_SANDBOX_REPOSITORY=your-org/your-sandbox-repo \\
        pytest -m integration tests/control_plane/development/test_development_github_integration.py
"""

from __future__ import annotations

import os
import uuid

import pytest

from control_plane.development.github_provider import GitHubPullRequestProvider
from control_plane.development.provider import FileChange

pytestmark = pytest.mark.integration


@pytest.fixture
def github_token() -> str:
    try:
        from infra.secrets import get_secrets_provider

        token = get_secrets_provider().get_required("GITHUB_TOKEN")
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"GITHUB_TOKEN not configured for the integration test: {exc}")
    return token


@pytest.fixture
def sandbox_repository() -> str:
    repo = os.environ.get("GITHUB_SANDBOX_REPOSITORY")
    if not repo:
        pytest.skip("GITHUB_SANDBOX_REPOSITORY not configured for the integration test.")
    return repo


def test_open_pull_request_against_a_real_sandbox_repository(
    github_token: str, sandbox_repository: str
) -> None:
    provider = GitHubPullRequestProvider(github_token)
    try:
        pr_url = provider.open_pull_request(
            repository=sandbox_repository,
            base_branch="main",
            branch_name=f"phase7-integration-test-{uuid.uuid4().hex[:8]}",
            title="Phase 7.3 integration test PR",
            body="Opened by tests/control_plane/development/test_development_github_integration.py",
            file_changes=[
                FileChange(
                    path=f"phase7-integration-test-{uuid.uuid4().hex[:8]}.txt",
                    content="Phase 7.3 integration test artifact.",
                )
            ],
        )
        assert pr_url.startswith("https://github.com/")
    finally:
        provider.close()
