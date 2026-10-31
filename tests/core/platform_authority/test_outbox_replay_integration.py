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
