"""Every action `.github/workflows/ci.yml` uses is pinned to a commit.

A tag such as `actions/checkout@v4` can be moved to other code without any
change in this repository, and the required checks would then run that code
(ledger row "Container base images and CI Actions are pinned by tag",
`docs/P-ROADMAP.md`). `release.yml` is held to the same rule by
`tests/architecture/test_release_script.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

CI_WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"


def test_every_ci_action_is_pinned_to_a_commit_sha() -> None:
    uses = re.findall(r"uses: (\S+)", CI_WORKFLOW.read_text(encoding="utf-8"))
    assert uses
    unpinned = [ref for ref in uses if not re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref)]
    assert unpinned == []
