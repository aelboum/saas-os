# ADR-0034: Atomic rate-limit increment (Foundation Reliability & Events, RE-3)

Status: Accepted and implemented
Date: 2026-10-02
Supersedes / Superseded by: — (Reliability & Events audit finding RE-F6)

## Context

`infra.ratelimit.check_rate_limit()` ran a fixed-window counter as separate Redis round trips: `INCR`, then `EXPIRE` when the count was 1, then `TTL`. A client timeout, a cancelled request, a Redis error or a crash between `INCR` and `EXPIRE` left the key with no TTL. Its count then only grew, so once past the limit that tenant route (or, on `/auth/*`, that client address) stayed rate-limited until someone deleted the key.

## Decision

- The increment, the window's expiry and the TTL read are one Lua script, which Redis executes atomically:
  - `INCR` the key;
  - if this is the first request (`count == 1`), or the key has no TTL (`TTL == -1`), `EXPIRE` it for the window;
  - return `{count, ttl}`.
- The script runs through redis-py's `register_script()` on the existing per-call client. That means `EVALSHA` with an automatic reload when Redis reports `NOSCRIPT`, for example after a Redis restart or `SCRIPT FLUSH`. No script state is held in the process and nothing is tied to one connection.
- **Unchanged:**
  - the policy: threshold, whole-second fixed window started by the first request and never extended by later ones, and `retry_after` from `TTL`;
  - the key format `ratelimit:{key}` (`{tenant_id}:{path}`, `auth:{client}`);
  - the configuration names;
  - the fail-closed contract: any Redis error, including one raised inside the script, becomes `RateLimitBackendError`, which callers turn into 503.
- **One behaviour change:** a key the old code left without a TTL is given a fresh window by its next request, so existing stuck keys repair themselves.

## Consequences

- Each check is one round trip instead of up to three.
- Real-Redis tests cover:
  - the first increment creating the window, and later ones not extending it;
  - natural expiry starting a new window;
  - concurrent first requests (one window, no lost increments);
  - a probe that never observes the counter without a TTL;
  - repair of a TTL-less key;
  - an in-script error failing closed;
  - script-cache flush recovery;
  - an unreachable Redis.
- Against the old two-step code, the probe and repair tests fail.

## Explicitly not part of this decision (deferred)

- **RE-F9 (rate-limit dimensions).** Keys use the raw request path, so resource ids and trailing-slash variants get separate budgets. There is also no per-user or per-API-key dimension. Changing either is a policy decision needing product sign-off.
- **Algorithm.** The fixed window allows up to twice the limit across a window boundary; a sliding-window or token-bucket algorithm is a separate change.
- **Client reuse.** A Redis client is still opened per check (the existing event-loop-safety design), which is unrelated to this finding.

## Related

`infra/ratelimit/limiter.py`; `tests/infra/ratelimit/test_ratelimit_atomicity_integration.py`; `tests/infra/ratelimit/test_ratelimit_backend_failure_unit.py`; [ADR-0033](0033-durable-outbox-dispatcher.md).
