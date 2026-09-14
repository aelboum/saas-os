"""Dead-letter recording (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4,
docs/ADR/0007-background-job-and-workflow-engine.md, docs/DATA-ARCHITECTURE.md
section 5: "a background job's state ... is owned by infra/jobs as generic
execution metadata").

A dead-lettered job's *outcome* (which function, which tenant, how many
attempts, what error) is recorded in a Redis list -- deliberately narrow
(record + count/peek only; no export, no requeue, no arbitrary mutation --
docs/ADR/0007-...'s "minimal, deliberately narrow interface"). The error is
stored as `f"{type(error).__name__}: {error}"` -- an application error's
own message, never a secret (job producers are responsible for never
putting a secret value into a payload or raising an error that embeds one,
the same discipline `infra/secrets` and `infra/db` already hold their own
errors to).

CP-07 J-INFRA-02: `record_dead_letter()` trims the list to
`config.dead_letter_max_entries` (oldest first) after every push --
this key has no TTL and is shared across every tenant and job type, so
left uncapped it grows without bound under ordinary, even
non-malicious, repeated job failure (`infra/jobs/config.py`'s own
docstring). `LTRIM key -N -1` keeps the *N* most-recently-pushed
entries (the tail, since `RPUSH` appends there) -- a rolling window of
recent failures for operational visibility, not a durable record.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, cast

from infra.jobs.config import JobsConfig

if TYPE_CHECKING:
    from arq import ArqRedis

# redis-py's command mixins are shared between the sync and async clients
# and typed with a `ResponseT = Union[Awaitable[T], T]` alias, so pyright
# can't narrow an `ArqRedis` (a redis.asyncio.Redis subclass) call to the
# awaitable half on its own -- these casts assert what's actually true for
# the async client at runtime, not a real ambiguity in the code.


@dataclass(frozen=True)
class DeadLetterEntry:
    function_name: str
    tenant_id: str | None
    error: str
    attempts: int
    dead_lettered_at: float


async def record_dead_letter(
    pool: ArqRedis,
    config: JobsConfig,
    *,
    function_name: str,
    payload: Any,
    error: BaseException,
    attempts: int,
) -> None:
    entry = DeadLetterEntry(
        function_name=function_name,
        tenant_id=getattr(payload, "tenant_id", None),
        error=f"{type(error).__name__}: {error}",
        attempts=attempts,
        dead_lettered_at=time.time(),
    )
    await cast("Awaitable[int]", pool.rpush(config.dead_letter_key, json.dumps(asdict(entry))))
    await cast(
        "Awaitable[bool]",
        pool.ltrim(config.dead_letter_key, -config.dead_letter_max_entries, -1),
    )


async def count_dead_letters(pool: ArqRedis, config: JobsConfig) -> int:
    return await cast("Awaitable[int]", pool.llen(config.dead_letter_key))


async def list_dead_letters(
    pool: ArqRedis, config: JobsConfig, *, limit: int = 100
) -> list[DeadLetterEntry]:
    raw_entries = await cast(
        "Awaitable[list[bytes]]", pool.lrange(config.dead_letter_key, 0, limit - 1)
    )
    return [DeadLetterEntry(**json.loads(raw)) for raw in raw_entries]
