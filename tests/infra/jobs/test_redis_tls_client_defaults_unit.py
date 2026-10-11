"""ADR-0021 -- regression cover for the *Redis client's own* TLS defaults.

`saas_os/infra/jobs/config.py`/`saas_os/infra/ratelimit/config.py` validate only the
`rediss://` scheme; they deliberately expose no `ssl_ca_certs`/
`ssl_cert_reqs` surface. What actually happens on the wire is therefore a
property of the resolved `redis-py`, not of this repository's code -- and
`pyproject.toml` declares `redis>=5.0`, a floor rather than an exact pin.

These tests pin that observed behavior so a dependency bump that silently
stopped verifying Redis server certificates fails here instead of in
production. No Redis server is contacted: `Redis.from_url()` only builds a
connection pool, and `SSLConnection` is inspected without connecting.
"""

from __future__ import annotations

import ssl

import pytest
import redis
from redis.connection import SSLConnection


def test_rediss_url_selects_the_tls_connection_class() -> None:
    """`rediss://` is the only switch -- there is no query-parameter
    equivalent to PostgreSQL's `sslmode` (ADR-0021)."""
    pool = redis.Redis.from_url("rediss://redis.invalid:6379/0").connection_pool
    assert pool.connection_class is SSLConnection


def test_redis_client_verifies_the_server_certificate_by_default() -> None:
    """The property ADR-0021's correction records: a `rediss://` connection
    verifies the server certificate against the client's default trust
    store. A bump that flipped this to `CERT_NONE` would silently downgrade
    every production Redis connection to an unauthenticated one."""
    connection = SSLConnection()
    assert connection.cert_reqs == ssl.CERT_REQUIRED


def test_redis_client_does_not_check_hostname_by_default() -> None:
    """The other half of the same fact: it is *hostname* checking, not
    certificate verification, that is off by default."""
    assert SSLConnection().check_hostname is False


def test_redis_client_has_no_default_ca_bundle_of_its_own() -> None:
    """With no explicit CA, verification falls back to
    `ssl.create_default_context()`'s own trust store -- which is what makes
    a privately-signed Redis certificate a trust-store concern rather than
    an application-configuration one (ADR-0021, ADR-0027)."""
    connection = SSLConnection()
    assert connection.ca_certs is None
    assert connection.ca_path is None
    assert connection.ca_data is None


@pytest.mark.parametrize("module", ["saas_os.infra.jobs.config", "saas_os.infra.ratelimit.config"])
def test_no_verification_bypass_is_configured_anywhere(module: str) -> None:
    """Neither Redis-owning config module may introduce a verification
    bypass. Asserted against the module source so a future edit that adds
    one is caught here, not merely reviewed."""
    import importlib
    import inspect

    source = inspect.getsource(importlib.import_module(module))
    for bypass in ("ssl_cert_reqs", "CERT_NONE", "check_hostname", "ssl_ca_certs"):
        assert bypass not in source, f"{module} must not configure {bypass} (ADR-0021)"
