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


async def count_dead_letters(pool: ArqRedis, config: JobsConfig) -> int:
    return await cast("Awaitable[int]", pool.llen(config.dead_letter_key))


async def list_dead_letters(
    pool: ArqRedis, config: JobsConfig, *, limit: int = 100
) -> list[DeadLetterEntry]:
    raw_entries = await cast(
        "Awaitable[list[bytes]]", pool.lrange(config.dead_letter_key, 0, limit - 1)
    )
    return [DeadLetterEntry(**json.loads(raw)) for raw in raw_entries]
