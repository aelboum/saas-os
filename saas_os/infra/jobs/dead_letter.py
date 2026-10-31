"""Dead-letter recording (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4,
docs/ADR/0007-background-job-and-workflow-engine.md, docs/DATA-ARCHITECTURE.md
section 5: "a background job's state ... is owned by saas_os/infra/jobs as generic
execution metadata").

A dead-lettered job's *outcome* (which function, which tenant, how many
attempts, what error) is recorded in a Redis list -- deliberately narrow
(record + count/peek only; no export, no requeue, no arbitrary mutation --
docs/ADR/0007-...'s "minimal, deliberately narrow interface"). The error is
stored as `f"{type(error).__name__}: {error}"` -- an application error's
own message, never a secret (job producers are responsible for never
putting a secret value into a payload or raising an error that embeds one,
the same discipline `saas_os/infra/secrets` and `saas_os/infra/db` already hold their own
errors to).

CP-07 J-INFRA-02: `record_dead_letter()` trims the list to
`config.dead_letter_max_entries` (oldest first) after every push --
this key has no TTL and is shared across every tenant and job type, so
left uncapped it grows without bound under ordinary, even
non-malicious, repeated job failure (`saas_os/infra/jobs/config.py`'s own
docstring). `LTRIM key -N -1` keeps the *N* most-recently-pushed
entries (the tail, since `RPUSH` appends there) -- a rolling window of
recent failures for operational visibility, not a durable record.

RA-12-7: `purge_tenant_dead_letters()` (and its synchronous bridge,
`purge_tenant_dead_letters_sync()`) is the one exception to "no arbitrary
mutation" above -- `saas_os.core.tenancy.purge_tenant()` needs to remove exactly
one tenant's own entries from this otherwise-shared, otherwise-append-only
list. This does **not** solve general dead-letter retention (RA-12-P6's
own open finding: the list has no time-based bound at all, only the
length cap above) -- it only removes a specific tenant's entries at the
moment that tenant is purged; a future phase may still add an
independent, time-based policy. It also does **not** close the queued-job
residual window RA-12-P7's own design audit identified: a job already
queued before the tenant closed can still be picked up, correctly do
nothing (execution-time lifecycle fencing), and still dead-letter
*after* this cleanup has already run -- bounded by ARQ's own ~24h job-key
TTL (`saas_os/infra/jobs/queue.py`'s own docstring), never eliminated by this
function. See `docs/MULTI-TENANCY.md` section 6's RA-12-7 addendum for
the full accepted-residual-window statement.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Mapping
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, cast

from saas_os.infra.jobs.config import JobsConfig, get_jobs_config

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


# RA-12-7: server-side, single-round-trip filter -- the whole list is read,
# filtered, and (only if something actually matched) replaced inside one
# Lua script, which Redis always executes to completion without any other
# command (a concurrent RPUSH from a job dead-lettering right now, another
# tenant's own purge cleanup, a concurrent LTRIM, or a second concurrent
# call for the *same* tenant) interleaving mid-script -- Redis's own
# single-threaded command execution model, not a lock this codebase
# manages. This is why the design audit (RA-12-P7) rejected client-side
# `LRANGE` + filter + `DEL`/`RPUSH` (a lost-update window between the read
# and the rewrite) and `WATCH`/`MULTI`/`EXEC` (correct, but needs a
# client-side retry loop for no correctness gain over this).
#
# An entry survives unless it decodes cleanly, is a JSON object, and its
# `tenant_id` field is a *string* equal to the target -- one condition
# covers both required cases at once: a `tenant_id: null` entry (JSON
# `null` decodes to `cjson.null`, not the Lua string type) and a
# malformed/undecodable entry (the `pcall` guard) both fail the
# `type(...) == 'string'` check and are therefore always kept, never
# miscounted as removed. Nothing here ever raises past a single bad
# entry -- one malformed historical row can never take unrelated entries
# down with it.
#
# `RPUSH` of the survivors is done in fixed-size chunks (not one
# `unpack()` of the whole list) so this remains correct even with the
# list at its configured maximum (`JOBS_DEAD_LETTER_MAX_ENTRIES`, default
# 10,000) -- `unpack()` over Redis's embedded Lua interpreter has its own
# C-stack argument limit, and a single `RPUSH key <all 10000 args>` risks
# it. When nothing matches, the list is never rewritten at all (`removed`
# stays 0, no `DEL`/`RPUSH` runs) -- a true no-op, not merely a same-
# content rewrite.
_PURGE_TENANT_DEAD_LETTERS_LUA = """
local key = KEYS[1]
local tenant_id = ARGV[1]
local raw_entries = redis.call('LRANGE', key, 0, -1)
local survivors = {}
local removed = 0
for i = 1, #raw_entries do
    local raw = raw_entries[i]
    local ok, decoded = pcall(cjson.decode, raw)
    if ok and type(decoded) == 'table' and type(decoded.tenant_id) == 'string'
        and decoded.tenant_id == tenant_id then
        removed = removed + 1
    else
        survivors[#survivors + 1] = raw
    end
end
if removed > 0 then
    redis.call('DEL', key)
    local chunk_size = 200
    local n = #survivors
    for i = 1, n, chunk_size do
        local j = math.min(i + chunk_size - 1, n)
        local chunk = {}
        for k = i, j do
            chunk[#chunk + 1] = survivors[k]
        end
        redis.call('RPUSH', key, unpack(chunk))
    end
end
return removed
"""


async def purge_tenant_dead_letters(pool: ArqRedis, config: JobsConfig, *, tenant_id: str) -> int:
    """RA-12-7 -- atomically remove every `arq:dead-letter` entry whose
    `tenant_id` field equals `tenant_id` (module comment above the Lua
    script for the exact matching/safety rules). Returns the number of
    entries removed -- never their contents. Idempotent: a second call
    once nothing matches returns `0` and leaves the list untouched. Never
    touches an entry belonging to a different tenant, an entry with no
    tenant association (`tenant_id: null`), or an entry this function
    cannot safely interpret.
    """
    removed = await cast(
        "Awaitable[int]",
        pool.eval(_PURGE_TENANT_DEAD_LETTERS_LUA, 1, config.dead_letter_key, tenant_id),
    )
    return int(removed)


def purge_tenant_dead_letters_sync(tenant_id: str, *, config: JobsConfig | None = None) -> int:
    """RA-12-7 -- the synchronous bridge `saas_os.core.tenancy.service.purge_tenant()`
    (a plain `def`, never `async def`) needs: every Redis client in this
    codebase (`saas_os.infra.jobs`, `saas_os.infra.ratelimit`) is async-only, and this
    function does not introduce a second, synchronous Redis connection
    architecture to avoid that -- it opens the exact same connection
    `enqueue_job()`/`build_worker()` already use
    (`saas_os.infra.jobs.queue.get_redis_pool()`), runs the one atomic operation
    above, and closes it, all within one `asyncio.run()` call. Deferred
    import of `get_redis_pool`: `saas_os/infra/jobs/queue.py` already imports
    `record_dead_letter` from this module at its own top level, so an
    unconditional top-level import the other way would be a load-time
    import cycle between the two modules.

    Owns the pool's full lifecycle -- nothing is left open past this call,
    and no connection is shared with, or reused from, a caller's own
    session. Safe to call from a context with no already-running asyncio
    event loop (`purge_tenant()`'s own callers today: tests and future
    synchronous ops/admin tooling, never a request handler or an ARQ job
    handler, both of which already run inside their own event loop).
    """
    from saas_os.infra.jobs.queue import get_redis_pool

    async def _run() -> int:
        cfg = config or get_jobs_config()
        pool = await get_redis_pool(cfg)
        try:
            return await purge_tenant_dead_letters(pool, cfg, tenant_id=tenant_id)
        finally:
            await pool.aclose()

    return asyncio.run(_run())


# Rewrites, in place and in one script, the `error` field of every entry that
# starts with one of the given prefixes (ARGV: prefix, replacement, prefix,
# replacement, ...; ARGV[1] is "1" to write, "0" to count only). An entry that
# does not decode to an object with a string `error` is left untouched, like
# the purge script above. `LSET` keeps each entry's position, so a
# concurrent `RPUSH`/`LTRIM` cannot interleave (the script runs atomically)
# and no other entry is rewritten. `cjson.encode` re-serializes the entry,
# with its keys in another order.
_REWRITE_DEAD_LETTER_ERRORS_LUA = """
local key = KEYS[1]
local write = ARGV[1] == '1'
local raw_entries = redis.call('LRANGE', key, 0, -1)
local matched = 0
for i = 1, #raw_entries do
    local ok, decoded = pcall(cjson.decode, raw_entries[i])
    if ok and type(decoded) == 'table' and type(decoded.error) == 'string' then
        for j = 2, #ARGV, 2 do
            local prefix = ARGV[j]
            if string.sub(decoded.error, 1, #prefix) == prefix then
                matched = matched + 1
                if write then
                    decoded.error = ARGV[j + 1]
                    redis.call('LSET', key, i - 1, cjson.encode(decoded))
                end
                break
            end
        end
    end
end
return matched
"""


async def rewrite_dead_letter_errors(
    pool: ArqRedis, config: JobsConfig, replacements: Mapping[str, str], *, apply: bool
) -> int:
    """Replace the `error` of every dead-letter entry that starts with one of
    `replacements`' prefixes by that prefix's replacement. Returns how many
    entries match; with `apply=False` nothing is written. Every other field
    and every other entry is kept."""
    argv = ["1" if apply else "0"]
    for prefix, replacement in replacements.items():
        argv += [prefix, replacement]
    matched = await cast(
        "Awaitable[int]",
        pool.eval(_REWRITE_DEAD_LETTER_ERRORS_LUA, 1, config.dead_letter_key, *argv),
    )
    return int(matched)
