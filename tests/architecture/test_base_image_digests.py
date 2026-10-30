"""Every base image is pinned by digest as well as tag
(`docs/SECURITY.md`, "Base image digests"; deferred-issue ledger, "Container
base images and CI Actions are pinned by tag, not by content"). A tag can be
moved upstream; a digest cannot, so a build changes only through a change in
this repository."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILES = ("Dockerfile", "frontend/Dockerfile")
_PINNED = re.compile(r"^FROM [a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}( AS [a-z]+)?$")


def _from_lines(path: str) -> list[str]:
    text = (REPO_ROOT / path).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip().upper().startswith("FROM ")]


@pytest.mark.parametrize("path", DOCKERFILES)
def test_every_base_image_is_pinned_by_tag_and_digest(path: str) -> None:
    lines = _from_lines(path)
    assert lines, path
    unpinned = [line for line in lines if not _PINNED.match(line)]
    assert not unpinned, unpinned


def test_both_node_stages_use_the_same_digest() -> None:
    """The build stage and the runtime stage run the same Node image, so an
    update cannot leave one of them behind."""
    digests = {line.split("@")[1].split()[0] for line in _from_lines("frontend/Dockerfile")}
    assert len(digests) == 1, digests
