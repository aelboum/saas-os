"""`control_plane.development` -- the autonomous-development agent
category's provider abstraction (docs/IMPLEMENTATION-ROADMAP.md Phase
7.3; docs/AI-CONTROL-PLANE.md section 4: "Autonomous development ...
Lowest blast radius: output is code changes subject to normal
review/CI gates").

Owns:
- `PullRequestProvider` (Protocol) / `FakePullRequestProvider` /
  `GitHubPullRequestProvider` -- the provider abstraction a development
  agent's tool (`control_plane.tools.open_pull_request`) calls through,
  never a specific provider SDK directly.

Does NOT own: the tool definition/handler itself (`control_plane.tools`);
authorization or scope enforcement (`control_plane.orchestration`); the
approval workflow (`control_plane.approvals`).

No merge/direct-push capability exists anywhere in this package -- see
`provider.py`'s own docstring for why that is a structural, not merely
conventional, guarantee.
"""

from control_plane.development.errors import (
    PullRequestProviderError,
    RepositoryScopeMismatchError,
)
from control_plane.development.provider import (
    FakePullRequestProvider,
    FileChange,
    PullRequestProvider,
)

__all__ = [
    "PullRequestProvider",
    "FakePullRequestProvider",
    "FileChange",
    "PullRequestProviderError",
    "RepositoryScopeMismatchError",
]
