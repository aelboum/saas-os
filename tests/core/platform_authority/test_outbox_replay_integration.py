"""Operator replay of dead-lettered outbox events (outbox decision brief Q2,
option 2A; ADR-0045 amendment of 2026-10-31): `platform.outbox:replay`, one
tenant, a dry run that changes nothing, dual evidence, and the tenant
predicate. PostgreSQL."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from phase_c_helpers import BILLING, PROVISIONING, REASON, P, Scene
from platform_helpers import PlatformWorld

import saas_os.core.outbox.replay as replay_module
from saas_os.core.authority import ServiceAccountCaller
from saas_os.core.outbox import (
    MAX_REPLAY_EVENTS,
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OutboxDispatchConfig,
    append_event,
    claim_due_events,
    fail_event,
    replay_dead_lettered_events,
)
from saas_os.core.platform_authority import InvalidPlatformRequestError, PlatformNotAuthorizedError
from saas_os.core.tenancy import TenantClosedError, TenantStatus
from saas_os.infra.db import tenant_session_scope

pytestmark = pytest.mark.integration

_CONFIG = OutboxDispatchConfig(max_attempts=1, retry_jitter_ratio=0)


def _dead_lettered(tenant_id: uuid.UUID, count: int = 1) -> list[uuid.UUID]:
    """`count` events of `tenant_id`, each claimed once and failed into the
    dead letter (max_attempts=1). Claims run across every open tenant, so
    events of other tests' tenants may be claimed too; only ours are failed."""
    ids = []
    with tenant_session_scope(tenant_id) as session:
        for n in range(count):
            ids.append(
                append_event(
                    session,
                    tenant_id=tenant_id,
                    event_type="test.replay",
                    aggregate_type="test",
                    aggregate_id=str(n),
                    payload={"n": n},
                )
            )
    at = datetime.now(UTC) + timedelta(seconds=1)
    for claim in claim_due_events(config=_CONFIG, now=at):
        if claim.id in ids:
            fail_event(
                tenant_id, claim.id, claim.claim_token, "Boom: provider quota", config=_CONFIG
            )
    return ids


def _row(platform: PlatformWorld, event_id: uuid.UUID) -> dict[str, Any]:
    (row,) = platform.execute(
        "SELECT status, attempts, last_error, claim_token, next_attempt_at "
        "FROM core.outbox_events WHERE id = :i",
        {"i": event_id},
    )
    return dict(zip(("status", "attempts", "last_error", "claim_token", "due"), row, strict=True))


def test_a_dry_run_counts_and_changes_nothing(scene: Scene, platform: PlatformWorld) -> None:
    tenant = scene.tenant()
    events = _dead_lettered(tenant, 2)
    operator, _ = platform.operator([P.OUTBOX_REPLAY])
    platform.clear_audit()

    result = replay_dead_lettered_events(tenant, caller=operator, reason=REASON, event_ids=events)

    assert (result.matched, result.replayed, result.applied) == (2, 0, False)
    assert all(_row(platform, e)["status"] == OUTBOX_STATUS_DEAD_LETTERED for e in events)
    assert platform.audit(action="platform.outbox.replay") == []
    assert scene.tenant_audit(tenant, "outbox.replay") == []


def test_apply_replays_only_the_named_dead_lettered_events_with_dual_evidence(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = scene.tenant()
    replayed, untouched = _dead_lettered(tenant, 2)
    operator, _ = platform.operator([P.OUTBOX_REPLAY])
    platform.clear_audit()
    before = datetime.now(UTC)

    result = replay_dead_lettered_events(
        tenant, caller=operator, reason=REASON, event_ids=[replayed], apply=True
    )

    assert (result.matched, result.replayed, result.applied) == (1, 1, True)
    row = _row(platform, replayed)
    assert row["status"] == OUTBOX_STATUS_PENDING
    assert row["attempts"] == 0 and row["claim_token"] is None
    assert row["last_error"] == "Boom: provider quota"  # the history stays readable
    assert before - timedelta(seconds=5) <= row["due"] <= datetime.now(UTC)
    assert _row(platform, untouched)["status"] == OUTBOX_STATUS_DEAD_LETTERED

    (audit,) = platform.audit(action="platform.outbox.replay", outcome="success")
    assert audit["actor_user_id"] == operator.user_id
    assert audit["target_tenant_id"] == tenant and audit["reason"] == REASON
    assert audit["metadata"] == {"events_replayed": 1, "selection": "event_ids"}
    (own,) = scene.tenant_audit(tenant, "outbox.replay")
    assert own["actor_user_id"] == operator.user_id
    assert str(replayed) not in str(own) and str(replayed) not in str(audit)


def test_a_replayed_event_is_claimed_and_runs_again(scene: Scene, platform: PlatformWorld) -> None:
    tenant = scene.tenant()
    (event,) = _dead_lettered(tenant)
    operator, _ = platform.operator([P.OUTBOX_REPLAY])
    replay_dead_lettered_events(
        tenant, caller=operator, reason=REASON, event_ids=[event], apply=True
    )
    claims = claim_due_events(now=datetime.now(UTC) + timedelta(seconds=1))
    (mine,) = [c for c in claims if c.id == event]
    assert mine.attempts == 1  # a fresh budget of attempts


def test_since_selects_by_the_time_of_dead_lettering(scene: Scene, platform: PlatformWorld) -> None:
    tenant = scene.tenant()
    old, recent = _dead_lettered(tenant, 2)
    platform.execute(
        "UPDATE core.outbox_events SET updated_at = now() - interval '2 days' WHERE id = :i",
        {"i": old},
    )
    operator, _ = platform.operator([P.OUTBOX_REPLAY])
    platform.clear_audit()
    result = replay_dead_lettered_events(
        tenant,
        caller=operator,
        reason=REASON,
        dead_lettered_since=datetime.now(UTC) - timedelta(days=1),
        apply=True,
    )
    assert result.replayed == 1
    assert _row(platform, recent)["status"] == OUTBOX_STATUS_PENDING
    assert _row(platform, old)["status"] == OUTBOX_STATUS_DEAD_LETTERED
    (audit,) = platform.audit(action="platform.outbox.replay", outcome="success")
    assert audit["metadata"]["selection"] == "dead_lettered_since"


def test_another_tenants_event_and_a_live_event_are_never_replayed(
    scene: Scene, platform: PlatformWorld
) -> None:
    """The tenant predicate: naming another tenant's dead-lettered event, or
    one of this tenant's events that is not dead-lettered, matches nothing."""
    tenant, other = scene.tenant(), scene.tenant()
    (foreign,) = _dead_lettered(other)
    with tenant_session_scope(tenant) as session:
        live = append_event(
            session,
            tenant_id=tenant,
            event_type="test.replay",
            aggregate_type="test",
            aggregate_id="live",
            payload={},
        )
    operator, _ = platform.operator([P.OUTBOX_REPLAY])

    result = replay_dead_lettered_events(
        tenant, caller=operator, reason=REASON, event_ids=[foreign, live], apply=True
    )
    assert (result.matched, result.replayed) == (0, 0)
    assert _row(platform, foreign)["status"] == OUTBOX_STATUS_DEAD_LETTERED
    assert _row(platform, live)["attempts"] == 0


@pytest.mark.parametrize("who", ["no_permission", "other_permission", "service_account", "system"])
def test_only_a_holder_of_the_permission_may_replay(
    scene: Scene, platform: PlatformWorld, who: str
) -> None:
    tenant = scene.tenant()
    (event,) = _dead_lettered(tenant)
    callers: dict[str, Any] = {
        "no_permission": lambda: platform.operator([])[0],
        "other_permission": lambda: platform.operator([P.TENANT_MOVE])[0],
        "service_account": lambda: ServiceAccountCaller(uuid.uuid4(), tenant),
        "system": lambda: PROVISIONING,
    }
    caller = callers[who]()
    platform.clear_audit()
    with pytest.raises(PlatformNotAuthorizedError):
        replay_dead_lettered_events(
            tenant, caller=caller, reason=REASON, event_ids=[event], apply=True
        )
    with pytest.raises(PlatformNotAuthorizedError):
        replay_dead_lettered_events(tenant, caller=BILLING, reason=REASON, event_ids=[event])
    assert _row(platform, event)["status"] == OUTBOX_STATUS_DEAD_LETTERED
    assert platform.audit(action="platform.outbox.replay", outcome="success") == []


@pytest.mark.parametrize("status", [TenantStatus.DELETED, TenantStatus.PURGED])
def test_a_closed_tenant_is_refused(
    scene: Scene, platform: PlatformWorld, status: TenantStatus
) -> None:
    tenant = scene.tenant()
    (event,) = _dead_lettered(tenant)
    scene.set_status(tenant, status)
    operator, _ = platform.operator([P.OUTBOX_REPLAY])
    platform.clear_audit()
    with pytest.raises(TenantClosedError):
        replay_dead_lettered_events(
            tenant, caller=operator, reason=REASON, event_ids=[event], apply=True
        )
    assert _row(platform, event)["status"] == OUTBOX_STATUS_DEAD_LETTERED
    denied = platform.audit(action="platform.outbox.replay", outcome="denied")
    assert [row["reason"] for row in denied] == ["tenant_closed"]


def test_a_selection_above_the_bound_is_refused(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = scene.tenant()
    events = _dead_lettered(tenant, 3)
    monkeypatch.setattr(replay_module, "MAX_REPLAY_EVENTS", 2)
    operator, _ = platform.operator([P.OUTBOX_REPLAY])
    with pytest.raises(InvalidPlatformRequestError):
        replay_dead_lettered_events(
            tenant,
            caller=operator,
            reason=REASON,
            dead_lettered_since=datetime.now(UTC) - timedelta(days=1),
            apply=True,
        )
    assert all(_row(platform, e)["status"] == OUTBOX_STATUS_DEAD_LETTERED for e in events)


@pytest.mark.parametrize(
    "selection",
    [
        {},
        {"event_ids": [uuid.uuid4()], "dead_lettered_since": datetime.now(UTC)},
        {"event_ids": []},
        {"event_ids": ["not-a-uuid"]},
        {"dead_lettered_since": datetime(2030, 1, 1)},  # naive
        {"event_ids": [uuid.uuid4() for _ in range(MAX_REPLAY_EVENTS + 1)]},
    ],
)
def test_an_invalid_selection_is_refused_before_anything_is_read(
    platform: PlatformWorld, selection: dict[str, Any]
) -> None:
    operator, _ = platform.operator([P.OUTBOX_REPLAY])
    with pytest.raises(InvalidPlatformRequestError):
        replay_dead_lettered_events(uuid.uuid4(), caller=operator, reason=REASON, **selection)


def test_a_timed_out_event_runs_again_only_through_an_audited_replay(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ledger row F5 (owner decision of 2026-11-01): a consumer that ran out
    of time leaves its event dead-lettered; it is not claimed again until an
    operator holding `platform.outbox:replay` replays it, and the replay is
    audited."""
    import asyncio

    import saas_os.api.outbox_dispatcher as outbox_dispatcher
    from saas_os.infra.jobs import TenantJobContext, TenantJobPayload

    tenant = scene.tenant()
    with tenant_session_scope(tenant) as session:
        event = append_event(
            session,
            tenant_id=tenant,
            event_type="test.f5",
            aggregate_type="test",
            aggregate_id="f5",
            payload={},
        )
    runs: list[int] = []

    async def _hangs(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        runs.append(1)
        await asyncio.sleep(5)

    monkeypatch.setattr(outbox_dispatcher, "OUTBOX_CONSUMER_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(outbox_dispatcher, "outbox_event_handlers", lambda: {"test.f5": _hangs})
    at = datetime.now(UTC) + timedelta(seconds=1)
    (claim,) = [c for c in claim_due_events(now=at) if c.id == event]
    asyncio.run(
        outbox_dispatcher._run_outbox_event(  # pyright: ignore[reportPrivateUsage]
            TenantJobContext(tenant_id=tenant),
            TenantJobPayload(
                tenant_id=str(tenant),
                data={"outbox_event_id": str(event), "claim_token": str(claim.claim_token)},
            ),
        )
    )
    timed_out = _row(platform, event)
    assert timed_out["status"] == OUTBOX_STATUS_DEAD_LETTERED
    assert str(timed_out["last_error"]).startswith("ConsumerTimedOut:")
    later = datetime.now(UTC) + timedelta(days=2)
    assert [c for c in claim_due_events(now=later) if c.id == event] == []

    operator, _ = platform.operator([P.OUTBOX_REPLAY])
    platform.clear_audit()
    dry = replay_dead_lettered_events(tenant, caller=operator, reason=REASON, event_ids=[event])
    assert (dry.matched, dry.replayed, dry.applied) == (1, 0, False)
    assert _row(platform, event)["status"] == OUTBOX_STATUS_DEAD_LETTERED

    replay_dead_lettered_events(
        tenant, caller=operator, reason=REASON, event_ids=[event], apply=True
    )
    assert _row(platform, event)["status"] == OUTBOX_STATUS_PENDING
    (audit,) = platform.audit(action="platform.outbox.replay", outcome="success")
    assert audit["actor_user_id"] == operator.user_id
    (again,) = [
        c for c in claim_due_events(now=datetime.now(UTC) + timedelta(seconds=1)) if c.id == event
    ]
    assert again.attempts == 1
    assert runs == [1]  # nothing ran it between the timeout and the replay


def test_an_ambiguous_event_replayed_after_its_window_runs_once_and_is_not_retried(
    scene: Scene, platform: PlatformWorld
) -> None:
    """Owner decision of 2026-11-01: an ambiguous outcome whose idempotency
    window has closed is dead-lettered; the operator's replay runs it once
    (the operator checked the destination), and a retry of that run would
    start after the window, so it is dead-lettered instead of running."""
    from saas_os.core.outbox import AmbiguousOutcomeError, begin_event_execution
    from saas_os.core.outbox.dispatch import record_ambiguous_outcome

    config = OutboxDispatchConfig(max_attempts=3, retry_jitter_ratio=0)
    tenant = scene.tenant()
    with tenant_session_scope(tenant) as session:
        event = append_event(
            session,
            tenant_id=tenant,
            event_type="test.f5.ambiguous",
            aggregate_type="test",
            aggregate_id="f5",
            payload={},
        )
    (created,) = platform.execute(
        "SELECT created_at FROM core.outbox_events WHERE id = :i", {"i": event}
    )[0]
    window = timedelta(seconds=1)
    error = AmbiguousOutcomeError("read_timeout", phase="read", retry_within=window)

    late = created + timedelta(seconds=5)
    (claim,) = [c for c in claim_due_events(config=config, now=late) if c.id == event]
    status = record_ambiguous_outcome(
        tenant, event, claim.claim_token, error, config=config, now=late
    )
    assert status == OUTBOX_STATUS_DEAD_LETTERED
    assert str(_row(platform, event)["last_error"]).startswith(
        "OutcomeUnknown: read_timeout (read); idempotency window closed"
    )
    assert [
        c for c in claim_due_events(config=config, now=late + timedelta(days=2)) if c.id == event
    ] == []  # noqa: E501

    operator, _ = platform.operator([P.OUTBOX_REPLAY])
    replay_dead_lettered_events(
        tenant, caller=operator, reason=REASON, event_ids=[event], apply=True
    )
    now = max(datetime.now(UTC), created) + timedelta(seconds=10)
    (claim,) = [c for c in claim_due_events(config=config, now=now) if c.id == event]
    assert claim.attempts == 1
    # The replayed run itself runs, although the window closed long ago.
    assert begin_event_execution(tenant, event, claim.claim_token, config=config, now=now)
    fail_event(tenant, event, claim.claim_token, "ConnectError: refused", config=config, now=now)
    row = _row(platform, event)
    assert row["status"] == OUTBOX_STATUS_PENDING
    assert str(row["last_error"]).startswith("ConnectError: refused [idempotent-retry-until ")

    later = row["due"] + timedelta(seconds=1)
    (claim,) = [c for c in claim_due_events(config=config, now=later) if c.id == event]
    assert begin_event_execution(tenant, event, claim.claim_token, config=config, now=later) is None
    assert _row(platform, event)["status"] == OUTBOX_STATUS_DEAD_LETTERED


def test_a_bare_consumer_timeout_runs_again_only_through_an_audited_replay(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Owner decision D of 2026-11-01: a bare `TimeoutError` that escapes a
    consumer is an unknown outcome -- dead-lettered, never claimed again --
    and the audited replay brings it back exactly like any other one."""
    import asyncio

    import saas_os.api.outbox_dispatcher as outbox_dispatcher
    from saas_os.infra.jobs import TenantJobContext, TenantJobPayload

    tenant = scene.tenant()
    with tenant_session_scope(tenant) as session:
        event = append_event(
            session,
            tenant_id=tenant,
            event_type="test.d.timeout",
            aggregate_type="test",
            aggregate_id="d",
            payload={},
        )
    runs: list[int] = []

    async def _client_timeout(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        runs.append(1)
        raise TimeoutError("client read timeout")

    monkeypatch.setattr(
        outbox_dispatcher, "outbox_event_handlers", lambda: {"test.d.timeout": _client_timeout}
    )
    at = datetime.now(UTC) + timedelta(seconds=1)
    (claim,) = [c for c in claim_due_events(now=at) if c.id == event]
    asyncio.run(
        outbox_dispatcher._run_outbox_event(  # pyright: ignore[reportPrivateUsage]
            TenantJobContext(tenant_id=tenant),
            TenantJobPayload(
                tenant_id=str(tenant),
                data={"outbox_event_id": str(event), "claim_token": str(claim.claim_token)},
            ),
        )
    )
    unknown = _row(platform, event)
    assert unknown["status"] == OUTBOX_STATUS_DEAD_LETTERED
    assert str(unknown["last_error"]).startswith("OutcomeUnknown: TimeoutError (unclassified);")
    later = datetime.now(UTC) + timedelta(days=2)
    assert [c for c in claim_due_events(now=later) if c.id == event] == []

    operator, _ = platform.operator([P.OUTBOX_REPLAY])
    platform.clear_audit()
    replay_dead_lettered_events(
        tenant, caller=operator, reason=REASON, event_ids=[event], apply=True
    )
    assert _row(platform, event)["status"] == OUTBOX_STATUS_PENDING
    (audit,) = platform.audit(action="platform.outbox.replay", outcome="success")
    assert audit["actor_user_id"] == operator.user_id
    (again,) = [
        c for c in claim_due_events(now=datetime.now(UTC) + timedelta(seconds=1)) if c.id == event
    ]
    assert again.attempts == 1
    assert runs == [1]  # nothing ran it between the timeout and the replay

    # The replayed run executes the consumer once more; this time it
    # succeeds, and the event is published.
    async def _succeeds(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        runs.append(2)

    monkeypatch.setattr(
        outbox_dispatcher, "outbox_event_handlers", lambda: {"test.d.timeout": _succeeds}
    )
    asyncio.run(
        outbox_dispatcher._run_outbox_event(  # pyright: ignore[reportPrivateUsage]
            TenantJobContext(tenant_id=tenant),
            TenantJobPayload(
                tenant_id=str(tenant),
                data={"outbox_event_id": str(event), "claim_token": str(again.claim_token)},
            ),
        )
    )
    assert runs == [1, 2]
    assert _row(platform, event)["status"] == "published"
