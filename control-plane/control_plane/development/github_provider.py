"""The real `PullRequestProvider` implementation, backed by GitHub's REST
API (docs/IMPLEMENTATION-ROADMAP.md Phase 7.3).

Only this module ever imports `httpx` for GitHub calls or knows GitHub's
specific REST shape -- `Core`/`control_plane.orchestration`/
`control_plane.tools` depend on `control_plane.development.provider
.PullRequestProvider` only (the provider-agnostic interface), mirroring
`core/billing/stripe_provider.py`'s own isolation of Stripe specifics
behind `core/billing/provider.py::BillingProvider`.

Credential handling (docs/ADR/0012-secrets-management.md): the token is
never read from `os.environ` directly and never accepted as a
constructor default -- callers resolve it through
`infra.secrets.get_secrets_provider().get_required("GITHUB_TOKEN")`
themselves (exactly like `core/billing/service.py::_default_provider()`
resolves `STRIPE_API_KEY`) and pass the *value* in; this module never
imports `infra.secrets` itself, so it cannot accidentally widen its own
secret-access surface beyond what its caller already decided to grant it.

Uses the Git Data API (blobs -> tree -> commit -> ref -> pull request),
not the simpler Contents API, because a proposed change may touch
multiple files atomically in one commit -- the Contents API only ever
writes one file per call.

`open_pull_request()` is the only method this class exposes (matches
`PullRequestProvider`'s own Protocol exactly) -- there is no
`merge_pull_request()`/`push()` method anywhere in this file.
"""

from __future__ import annotations

import httpx

from control_plane.development.errors import PullRequestProviderError
from control_plane.development.provider import FileChange

_API_BASE = "https://api.github.com"


class GitHubPullRequestProvider:
    def __init__(self, token: str, *, timeout_seconds: float = 30.0) -> None:
        self._client = httpx.Client(
            base_url=_API_BASE,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=timeout_seconds,
        )

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
        try:
            base_ref = self._client.get(f"/repos/{repository}/git/ref/heads/{base_branch}")
            base_ref.raise_for_status()
            base_commit_sha = base_ref.json()["object"]["sha"]

            base_commit = self._client.get(f"/repos/{repository}/git/commits/{base_commit_sha}")
            base_commit.raise_for_status()
            base_tree_sha = base_commit.json()["tree"]["sha"]

            tree_entries = []
            for change in file_changes:
                blob = self._client.post(
                    f"/repos/{repository}/git/blobs",
                    json={"content": change.content, "encoding": "utf-8"},
                )
                blob.raise_for_status()
                tree_entries.append(
                    {
                        "path": change.path,
                        "mode": "100644",
                        "type": "blob",
                        "sha": blob.json()["sha"],
                    }
                )

            new_tree = self._client.post(
                f"/repos/{repository}/git/trees",
                json={"base_tree": base_tree_sha, "tree": tree_entries},
            )
            new_tree.raise_for_status()

            new_commit = self._client.post(
                f"/repos/{repository}/git/commits",
                json={
                    "message": title,
                    "tree": new_tree.json()["sha"],
                    "parents": [base_commit_sha],
                },
            )
            new_commit.raise_for_status()
            new_commit_sha = new_commit.json()["sha"]

            create_ref = self._client.post(
                f"/repos/{repository}/git/refs",
                json={"ref": f"refs/heads/{branch_name}", "sha": new_commit_sha},
            )
            create_ref.raise_for_status()

            pr = self._client.post(
                f"/repos/{repository}/pulls",
                json={"title": title, "body": body, "head": branch_name, "base": base_branch},
            )
            pr.raise_for_status()
            return str(pr.json()["html_url"])
        except httpx.HTTPError as exc:
            raise PullRequestProviderError("open_pull_request", type(exc).__name__) from exc

    def close(self) -> None:
        self._client.close()
