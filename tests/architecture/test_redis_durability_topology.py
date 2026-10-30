"""Both Compose files run Redis with an append-only file on a named volume,
so queued and dead-lettered jobs survive a Redis restart or recreate
(`docs/BACKUP-RESTORE.md`, Redis section). The behaviour itself is proven
against real containers by
`tests/infra/jobs/test_redis_persistence_integration.py`; this pins the
configuration that test relies on. The development file had no persistence
until 2026-10-30 (deferred-issue ledger)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _service_block(source: str, name: str) -> str:
    match = re.search(rf"^  {name}:\n((?:    .*\n|\s*\n)+)", source, re.MULTILINE)
    assert match, name
    return match.group(1)


@pytest.mark.parametrize(
    ("compose_file", "volume"),
    [("docker-compose.yml", "redis-data"), ("docker-compose.prod.yml", "redis-data-prod")],
)
def test_redis_keeps_an_append_only_file_on_a_named_volume(compose_file: str, volume: str) -> None:
    source = (REPO_ROOT / compose_file).read_text(encoding="utf-8")
    redis = _service_block(source, "redis")
    assert 'command: ["redis-server", "--appendonly", "yes"]' in redis
    assert f"- {volume}:/data" in redis
    top_level = source[source.index("\nvolumes:\n") :]
    assert f"\n  {volume}:" in top_level
