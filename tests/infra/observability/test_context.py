"""Correlation context tests (docs/IMPLEMENTATION-ROADMAP.md Phase 2.2)."""

from __future__ import annotations

import asyncio

from infra.observability.context import bind_correlation_context, get_correlation_context


def test_no_context_bound_by_default() -> None:
    ctx = get_correlation_context()
    assert ctx.tenant_id is None
    assert ctx.user_id is None
    assert ctx.request_id is None
    assert ctx.agent_id is None
    assert ctx.action_id is None


def test_bind_correlation_context_sets_fields() -> None:
    with bind_correlation_context(tenant_id="t1", user_id="u1", request_id="r1"):
        ctx = get_correlation_context()
        assert ctx.tenant_id == "t1"
        assert ctx.user_id == "u1"
        assert ctx.request_id == "r1"
        assert ctx.agent_id is None
        assert ctx.action_id is None


def test_context_reverts_after_the_with_block() -> None:
    with bind_correlation_context(tenant_id="t1"):
        pass
    assert get_correlation_context().tenant_id is None


def test_nested_bind_inherits_and_extends_parent_context() -> None:
    with bind_correlation_context(tenant_id="t1", request_id="r1"):
        with bind_correlation_context(agent_id="a1", action_id="act1"):
            ctx = get_correlation_context()
            assert ctx.tenant_id == "t1"  # inherited, not overwritten to None
            assert ctx.request_id == "r1"
            assert ctx.agent_id == "a1"
            assert ctx.action_id == "act1"
        # back to the outer context -- inner-only fields gone
        outer_ctx = get_correlation_context()
        assert outer_ctx.tenant_id == "t1"
        assert outer_ctx.agent_id is None


def test_context_reverts_even_if_the_block_raises() -> None:
    class ProbeError(Exception):
        pass

    try:
        with bind_correlation_context(tenant_id="t1"):
            raise ProbeError
    except ProbeError:
        pass
    assert get_correlation_context().tenant_id is None


def test_context_is_isolated_across_concurrent_asyncio_tasks() -> None:
    """Non-vacuous proof that this is contextvars-based (async-safe), not
    a thread-local or a plain module-level global -- a plain global would
    leak one task's tenant_id into a concurrently-running task's context.
    """

    results: dict[str, str | None] = {}

    async def _worker(tenant_id: str, delay: float) -> None:
        with bind_correlation_context(tenant_id=tenant_id):
            await asyncio.sleep(delay)
            # If context were a shared global instead of a ContextVar, the
            # *other* task's tenant_id could have overwritten this one by
            # the time we wake up here.
            results[tenant_id] = get_correlation_context().tenant_id

    async def _run() -> None:
        await asyncio.gather(
            _worker("tenant-a", 0.02),
            _worker("tenant-b", 0.01),
        )

    asyncio.run(_run())

    assert results == {"tenant-a": "tenant-a", "tenant-b": "tenant-b"}
