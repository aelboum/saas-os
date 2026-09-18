"""`infra/jobs` configuration (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4,
docs/ADR/0007-background-job-and-workflow-engine.md).

`REDIS_URL` is retrieved through `infra.secrets` -- like `DATABASE_URL`
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.3), a connection URL can embed
credentials, so it is never read from `os.environ` directly. The retry
policy's own tunables (`JOBS_MAX_TRIES`, `JOBS_RETRY_BACKOFF_BASE_SECONDS`)
are plain, non-secret configuration and are read directly from the
environment, the same convention `infra/observability/config.py` uses for
its own non-secret tunables.

**S-05 (BANK-SEC-01/05, `docs/ADR/0021-database-redis-transport-encryption.md`)**:
for Redis, unlike PostgreSQL, there is no query-parameter equivalent to
upgrade a connection after the fact -- `redis://` and `rediss://` are two
different URL schemes, and `arq.connections.RedisSettings.from_dsn()`
(confirmed by reading its actual source, not assumed) sets
`ssl=(scheme == "rediss")` directly from that scheme. `JobsConfig`
therefore *validates* rather than *rewrites*: when TLS is required
(`ENVIRONMENT=production` by default, or `REDIS_REQUIRE_TLS` explicitly),
`REDIS_URL` must already use `rediss://` -- a `redis://` URL fails closed
at configuration time rather than silently connecting in plaintext.
`infra/ratelimit/config.py` independently applies the identical check to
its own, separately-configured `REDIS_URL` read (`infra` submodules
deliberately do not import each other for this, matching
`infra/secrets/config.py`'s own established convention).

`dead_letter_max_entries` (CP-07 J-INFRA-02): the dead-letter list
(`infra.jobs.dead_letter.record_dead_letter`) is one Redis key shared by
every tenant and every job type, with no TTL. Left uncapped, ordinary
tenant activity that keeps failing (e.g. a webhook subscription pointed
at a permanently-erroring endpoint) grows it without bound, and that
same Redis instance also backs the job queue and `infra/ratelimit`.
`record_dead_letter()` trims the list to this many most-recent entries
(oldest dropped first) after every push -- a rolling window, not a
retention/audit guarantee (docs/ADR/0007's own "minimal, deliberately
narrow interface": this list is operational visibility into recent
failures, never the durable record of what happened, which belongs to
whatever audit trail the failing job's own domain already keeps).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

from infra.jobs.errors import JobsConfigurationError
from infra.secrets import get_secrets_provider

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True)
class JobsConfig:
    redis_url: str
    max_tries: int = 3
    retry_backoff_base_seconds: float = 1.0
    dead_letter_key: str = "arq:dead-letter"
    dead_letter_max_entries: int = 10_000
    # S-05: exposed for tests/introspection, mirrors `DatabaseConfig.require_tls`
    # -- never itself read by `infra.jobs.queue`, which only ever needs
    # `redis_url`, already validated by the time this dataclass exists.
    require_tls: bool = False

    def __post_init__(self) -> None:
        if self.max_tries < 1:
            raise JobsConfigurationError(f"JOBS_MAX_TRIES must be >= 1, got: {self.max_tries}")
        if self.retry_backoff_base_seconds <= 0:
            raise JobsConfigurationError(
                "JOBS_RETRY_BACKOFF_BASE_SECONDS must be > 0, got: "
                f"{self.retry_backoff_base_seconds}"
            )
        if self.dead_letter_max_entries < 1:
            raise JobsConfigurationError(
                f"JOBS_DEAD_LETTER_MAX_ENTRIES must be >= 1, got: {self.dead_letter_max_entries}"
            )


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise JobsConfigurationError(f"{name} must be an integer, got: {raw!r}") from exc


def _parse_float(name: str, raw: str) -> float:
    try:
        return float(raw)
    except ValueError as exc:
        raise JobsConfigurationError(f"{name} must be a number, got: {raw!r}") from exc


def _parse_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise JobsConfigurationError(f"{name} must be a boolean-like value, got: {raw!r}")


def _require_tls_default() -> bool:
    """S-05: mirrors `infra.db.config._require_tls_default()` exactly --
    see that function's own docstring for the "read `ENVIRONMENT`
    independently" rationale."""
    override = os.environ.get("REDIS_REQUIRE_TLS")
    if override is not None:
        return _parse_bool("REDIS_REQUIRE_TLS", override)
    return os.environ.get("ENVIRONMENT") == "production"


def _validate_redis_tls(redis_url: str, *, require_tls: bool) -> None:
    """S-05: unlike PostgreSQL's `sslmode`, Redis has no in-URL parameter
    this module can safely add after the fact -- the scheme itself
    (`redis://` vs `rediss://`) is what `arq.connections.RedisSettings.
    from_dsn()` inspects to decide `ssl=True/False` (verified by reading
    its actual source: `ssl=conf.scheme == "rediss"`). So this function
    validates rather than rewrites: a `redis://` URL when TLS is required
    fails closed with a clear, actionable error -- it never silently
    connects in plaintext, and never guesses at rewriting the scheme
    (which could easily target the wrong port/protocol on a server that
    does not actually speak TLS there)."""
    if not require_tls:
        return
    scheme = urlsplit(redis_url).scheme
    if scheme != "rediss":
        raise JobsConfigurationError(
            f"REDIS_REQUIRE_TLS is enabled but REDIS_URL uses scheme {scheme!r}, not "
            "'rediss' -- this repository never silently connects to Redis in plaintext. "
            "Use a rediss:// URL or explicitly set REDIS_REQUIRE_TLS=false if this "
            "connection is intentionally over a trusted, isolated network."
        )


def _jobs_config_from_env() -> JobsConfig:
    redis_url = get_secrets_provider().get("REDIS_URL")
    if not redis_url:
        raise JobsConfigurationError(
            "REDIS_URL is not set. Copy .env.example to .env and set a value "
            "(see docs/ADR/0012-secrets-management.md)."
        )
    require_tls = _require_tls_default()
    _validate_redis_tls(redis_url, require_tls=require_tls)

    max_tries_raw = os.environ.get("JOBS_MAX_TRIES")
    backoff_raw = os.environ.get("JOBS_RETRY_BACKOFF_BASE_SECONDS")
    dead_letter_max_entries_raw = os.environ.get("JOBS_DEAD_LETTER_MAX_ENTRIES")

    return JobsConfig(
        redis_url=redis_url,
        max_tries=_parse_int("JOBS_MAX_TRIES", max_tries_raw) if max_tries_raw is not None else 3,
        retry_backoff_base_seconds=(
            _parse_float("JOBS_RETRY_BACKOFF_BASE_SECONDS", backoff_raw)
            if backoff_raw is not None
            else 1.0
        ),
        dead_letter_max_entries=(
            _parse_int("JOBS_DEAD_LETTER_MAX_ENTRIES", dead_letter_max_entries_raw)
            if dead_letter_max_entries_raw is not None
            else 10_000
        ),
        require_tls=require_tls,
    )


@lru_cache
def get_jobs_config() -> JobsConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. Tests that need a different configuration should call
    `get_jobs_config.cache_clear()` after `monkeypatch.setenv(...)`.
    """
    return _jobs_config_from_env()
