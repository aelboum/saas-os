"""The tenant's own AI usage report against a real PostgreSQL (ADR-0054
amendment of 2026-11-09; Gap 22a).

Pinned: sums of tokens and estimated cost equal an independent `Decimal`
oracle for every grouping; unknown usage and unknown cost are counted, never
read as zero; cost is never summed across currencies; the window is
`[since, until)` in UTC and bounded; only a user holding `ai.usage:read`
reads (not `billing.subscription:read`, not `ai.policy:*`, not a service
account, a system purpose or support access); one tenant's report never
contains another's rows and an unknown tenant is refused like a foreign one;
every allowed read writes one `ai.usage.read` audit row with the window and
grouping only and a refusal writes a `denied` row; nothing but closed
vocabulary and aggregates is returned; the limits block keeps an invalid or
unreadable quota distinct from "no limit". Rows are seeded directly: no
provider, no network.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import AIWorld, admin_scalar
from lifecycle_callers import PROVISIONING
from saas_os.control_plane.inference import tenant_usage
from saas_os.control_plane.inference.tenant_usage import (
    AIUsageGroupBy,
    AIUsageReadError,
    AIUsageReport,
    read_tenant_ai_usage,
)
from saas_os.core.authority import ServiceAccountCaller, UserCaller
from saas_os.core.identity.service import create_service_account
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import approve_support_access, create_support_access_request
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

USAGE = ("ai.usage", "read")
SINCE = datetime(2026, 3, 1, tzinfo=UTC)
UNTIL = datetime(2026, 3, 4, tzinfo=UTC)
_NO_LIMIT: Callable[[uuid.UUID], dict[str, object]] = lambda _t: {}  # noqa: E731


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM control_plane.ai_inference_attempts LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"AI tables missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch, platform_config_database: None) -> None:
    from saas_os.control_plane.inference.config import service as ai_config

    class _Secrets:
        def get(self, name: str) -> str | None:
            return "placeholder" if name.startswith("AI_TEST_") else None

    monkeypatch.setattr(ai_config, "get_secrets_provider", lambda: _Secrets())
    monkeypatch.setenv("AI_PROVIDER_CREDENTIALS", "AI_TEST_PROVIDER_KEY,AI_TEST_ROTATED")


@pytest.fixture
def world() -> Iterator[AIWorld]:
    w = AIWorld()
    try:
        yield w
    finally:
        w.cleanup()


@dataclasses.dataclass(frozen=True)
class Seed:
    provider: str
    model: str
    use_case: str
    state: str
    provenance: str
    at: datetime
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached: int | None = None
    cost: Decimal | None = None
    currency: str | None = None


def _insert(tenant_id: uuid.UUID, seed: Seed) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO control_plane.ai_inference_attempts (id, tenant_id, request_id, "
                    "attempt_number, actor_type, use_case, alias, provider_key, model_id, "
                    "provider_config_version, model_config_version, effective_classification, "
                    "decision, state, started_at, finished_at, input_tokens, output_tokens, "
                    "cached_input_tokens, usage_provenance, estimated_cost, currency) VALUES "
                    "(:id, :t, :r, 1, 'service_account', :uc, 'alias', :p, :m, 1, 1, "
                    "'tenant_data', CAST(:d AS json), :s, :at, :fin, :i, :o, :c, :prov, "
                    ":cost, :cur)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "t": str(tenant_id),
                    "r": str(uuid.uuid4()),
                    "uc": seed.use_case,
                    "p": seed.provider,
                    "m": seed.model,
                    "d": json.dumps({"sentinel": "DECISION-SENTINEL"}),
                    "s": seed.state,
                    "at": seed.at,
                    "fin": None if seed.state == "started" else seed.at + timedelta(seconds=1),
                    "i": seed.input_tokens,
                    "o": seed.output_tokens,
                    "c": seed.cached,
                    "prov": seed.provenance,
                    "cost": seed.cost,
                    "cur": seed.currency,
                },
            )
    finally:
        engine.dispose()


def _reader(world: AIWorld, tenant_id: uuid.UUID) -> UserCaller:
    return world.member(tenant_id, USAGE)


def _day(day: int, hour: int = 12, minute: int = 0, second: int = 0) -> datetime:
    return datetime(2026, 3, day, hour, minute, second, tzinfo=UTC)


def _seeds(tag: str) -> list[Seed]:
    """Seven attempts inside `[SINCE, UNTIL)`: two providers, two models, two use
    cases, three states, all three provenances, two currencies, three unpriced."""
    p1, p2 = f"{tag}-p1", f"{tag}-p2"
    return [
        Seed(
            p1,
            "m1",
            "uc-a",
            "succeeded",
            "provider_reported",
            _day(1, 10),
            100,
            50,
            10,
            Decimal("0.01000000"),
            "USD",
        ),
        Seed(
            p1,
            "m1",
            "uc-a",
            "succeeded",
            "estimated",
            _day(1, 23, 59, 59),
            20,
            10,
            None,
            Decimal("0.00200000"),
            "USD",
        ),
        Seed(p1, "m2", "uc-b", "failed", "unknown", _day(2)),
        Seed(
            p2,
            "m1",
            "uc-a",
            "succeeded",
            "provider_reported",
            _day(3, 0, 0, 0),
            7,
            3,
            1,
            Decimal("0.50000000"),
            "EUR",
        ),
        Seed(p1, "m1", "uc-b", "started", "unknown", _day(3, 23)),
        Seed(
            p1,
            "m1",
            "uc-a",
            "succeeded",
            "provider_reported",
            _day(2, 5),
            1,
            1,
            0,
            Decimal("0.00000007"),
            "USD",
        ),
        Seed(p2, "m1", "uc-b", "succeeded", "provider_reported", _day(2, 6), 4, 4, 0),
    ]


def _outside(tag: str) -> list[Seed]:
    """One second before `since` and exactly at `until`: both excluded."""
    return [
        Seed(
            f"{tag}-p1",
            "m1",
            "uc-a",
            "succeeded",
            "provider_reported",
            SINCE - timedelta(seconds=1),
            999,
            999,
            0,
            Decimal("9"),
            "USD",
        ),
        Seed(
            f"{tag}-p1",
            "m1",
            "uc-a",
            "succeeded",
            "provider_reported",
            UNTIL,
            999,
            999,
            0,
            Decimal("9"),
            "USD",
        ),
    ]


def _blank() -> dict[str, object]:
    return {
        "attempts": 0,
        "in": 0,
        "out": 0,
        "cached": 0,
        "cost": {},
        "uu": 0,
        "cu": 0,
        "state": {},
        "prov": {},
    }


def _oracle(seeds: list[Seed], key: Callable[[Seed], str]) -> dict[str, dict[str, object]]:
    """Independent of the implementation: plain Python over the seed list."""
    out: dict[str, dict[str, object]] = {}
    for s in seeds:
        g = out.setdefault(key(s), _blank())
        g["attempts"] += 1  # type: ignore[operator]
        g["in"] += s.input_tokens or 0  # type: ignore[operator]
        g["out"] += s.output_tokens or 0  # type: ignore[operator]
        g["cached"] += s.cached or 0  # type: ignore[operator]
        g["uu"] += 1 if s.provenance == "unknown" else 0  # type: ignore[operator]
        g["state"][s.state] = g["state"].get(s.state, 0) + 1  # type: ignore[attr-defined]
        g["prov"][s.provenance] = g["prov"].get(s.provenance, 0) + 1  # type: ignore[attr-defined]
        if s.cost is None:
            g["cu"] += 1  # type: ignore[operator]
        else:
            assert s.currency is not None
            cost: dict[str, Decimal] = g["cost"]  # type: ignore[assignment]
            cost[s.currency] = cost.get(s.currency, Decimal(0)) + s.cost
    return out


def _check(report: AIUsageReport, expected: dict[str, dict[str, object]]) -> None:
    assert {g.key for g in report.groups} == set(expected)
    for group in report.groups:
        want = expected[group.key]
        a = group.amounts
        assert a.attempts == want["attempts"]
        assert (a.input_tokens, a.output_tokens, a.cached_input_tokens) == (
            want["in"],
            want["out"],
            want["cached"],
        )
        assert {c.currency: c.estimated for c in a.cost} == want["cost"]
        assert a.usage_unknown_attempts == want["uu"]
        assert a.cost_unknown_attempts == want["cu"]
        assert dict(a.attempts_by_state) == want["state"]
        assert {t.provenance: t.attempts for t in a.tokens_by_provenance} == want["prov"]


# --- aggregation accuracy ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("group_by", "key"),
    [
        (AIUsageGroupBy.PROVIDER, lambda s: s.provider),
        (AIUsageGroupBy.MODEL, lambda s: f"{s.provider}/{s.model}"),
        (AIUsageGroupBy.USE_CASE, lambda s: s.use_case),
        (AIUsageGroupBy.PROVENANCE, lambda s: s.provenance),
        (AIUsageGroupBy.STATE, lambda s: s.state),
        (AIUsageGroupBy.DAY, lambda s: s.at.date().isoformat()),
    ],
)
def test_every_grouping_equals_an_independent_oracle(
    world: AIWorld, group_by: AIUsageGroupBy, key: Callable[[Seed], str]
) -> None:
    tenant_id = world.tenant()
    tag = f"t{uuid.uuid4().hex[:6]}"
    seeds = _seeds(tag)
    for seed in [*seeds, *_outside(tag)]:
        _insert(tenant_id, seed)

    report = read_tenant_ai_usage(
        tenant_id,
        caller=_reader(world, tenant_id),
        since=SINCE,
        until=UNTIL,
        group_by=group_by,
        entitlements=_NO_LIMIT,
    )

    expected = _oracle(seeds, key)
    if group_by is AIUsageGroupBy.DAY:
        # every day of the window is present, an empty one included
        assert [g.key for g in report.groups] == ["2026-03-01", "2026-03-02", "2026-03-03"]
        expected = {k: expected.get(k, _blank()) for k in (g.key for g in report.groups)}
    _check(report, expected)
    whole = _oracle(seeds, lambda _s: "all")["all"]
    assert report.totals.attempts == whole["attempts"] == 7
    assert report.totals.input_tokens == whole["in"] == 132
    assert report.totals.usage_unknown_attempts == whole["uu"] == 2
    assert report.totals.cost_unknown_attempts == whole["cu"] == 3
    assert {c.currency: c.estimated for c in report.totals.cost} == whole["cost"]
    assert sum(g.amounts.attempts for g in report.groups) == report.totals.attempts
    assert report.basis == "rows_present"
    assert report.budget.state == "unconfigured"


def test_cost_is_never_summed_across_currencies_and_unknown_is_not_zero(world: AIWorld) -> None:
    tenant_id = world.tenant()
    for seed in _seeds(f"t{uuid.uuid4().hex[:6]}"):
        _insert(tenant_id, seed)
    report = read_tenant_ai_usage(
        tenant_id,
        caller=_reader(world, tenant_id),
        since=SINCE,
        until=UNTIL,
        entitlements=_NO_LIMIT,
    )
    cost = {c.currency: c.estimated for c in report.totals.cost}
    assert cost == {"EUR": Decimal("0.50000000"), "USD": Decimal("0.01200007")}
    assert all(isinstance(c.estimated, Decimal) for c in report.totals.cost)
    by_provenance = {t.provenance: t for t in report.totals.tokens_by_provenance}
    # provider-reported and estimated tokens stay separate; unknown contributes none
    assert by_provenance["provider_reported"].input_tokens == 100 + 7 + 1 + 4
    assert by_provenance["estimated"].input_tokens == 20
    assert (by_provenance["unknown"].attempts, by_provenance["unknown"].input_tokens) == (2, 0)


def test_the_same_model_id_under_two_providers_stays_separate(world: AIWorld) -> None:
    tenant_id = world.tenant()
    tag = f"t{uuid.uuid4().hex[:6]}"
    for seed in _seeds(tag):
        _insert(tenant_id, seed)
    report = read_tenant_ai_usage(
        tenant_id,
        caller=_reader(world, tenant_id),
        since=SINCE,
        until=UNTIL,
        group_by="model",
        entitlements=_NO_LIMIT,
    )
    assert {f"{tag}-p1/m1", f"{tag}-p2/m1"} <= {g.key for g in report.groups}


# --- window -----------------------------------------------------------------------------


def test_the_window_is_inclusive_start_exclusive_end_and_the_default_is_the_utc_month(
    world: AIWorld,
) -> None:
    tenant_id = world.tenant()
    reader = _reader(world, tenant_id)
    now = datetime.now(UTC)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    for at in (month_start, month_start - timedelta(seconds=1), now):
        _insert(tenant_id, Seed("pw", "m", "uc", "succeeded", "provider_reported", at, 1, 1, 0))
    default = read_tenant_ai_usage(tenant_id, caller=reader, entitlements=_NO_LIMIT)
    assert default.since == month_start
    assert default.totals.attempts == 2  # the start instant is in, the second before is out
    exact = read_tenant_ai_usage(
        tenant_id,
        caller=reader,
        since=month_start,
        until=month_start + timedelta(seconds=1),
        entitlements=_NO_LIMIT,
    )
    assert exact.totals.attempts == 1


def test_a_leap_day_belongs_to_its_own_utc_day(world: AIWorld) -> None:
    tenant_id = world.tenant()
    leap = datetime(2028, 2, 29, 23, 59, 59, tzinfo=UTC)
    _insert(tenant_id, Seed("pl", "m", "uc", "succeeded", "provider_reported", leap, 1, 1, 0))
    report = read_tenant_ai_usage(
        tenant_id,
        caller=_reader(world, tenant_id),
        since=datetime(2028, 2, 28, tzinfo=UTC),
        until=datetime(2028, 3, 2, tzinfo=UTC),
        group_by="day",
        entitlements=_NO_LIMIT,
    )
    assert {g.key: g.amounts.attempts for g in report.groups} == {
        "2028-02-28": 0,
        "2028-02-29": 1,
        "2028-03-01": 0,
    }


def test_invalid_windows_and_groupings_are_refused_before_anything_is_read(
    world: AIWorld,
) -> None:
    tenant_id = world.tenant()
    reader = _reader(world, tenant_id)
    for kwargs in (
        {"since": SINCE},  # since without until
        {"until": UNTIL},  # until without since
        {"since": SINCE, "until": SINCE},
        {"since": UNTIL, "until": SINCE},
        {"since": SINCE, "until": SINCE + timedelta(days=93, seconds=1)},
        {"since": datetime(2026, 3, 1), "until": datetime(2026, 3, 2)},  # noqa: DTZ001 -- naive
        {"since": "2026-03-01", "until": UNTIL},
    ):
        with pytest.raises(AIUsageReadError) as caught:
            read_tenant_ai_usage(tenant_id, caller=reader, **kwargs)  # type: ignore[arg-type]
        assert caught.value.reason == "invalid_window"
    for bad in ("decision", "tenant", "", None, 7):
        with pytest.raises(AIUsageReadError) as caught:
            read_tenant_ai_usage(tenant_id, caller=reader, group_by=bad)  # type: ignore[arg-type]
        assert caught.value.reason == "invalid_group_by"
    ok = read_tenant_ai_usage(
        tenant_id,
        caller=reader,
        since=SINCE,
        until=SINCE + timedelta(days=93),
        entitlements=_NO_LIMIT,
    )
    assert ok.totals.attempts == 0
    assert _audit(tenant_id, "success") == 1  # only the one allowed read wrote evidence


# --- authorization ----------------------------------------------------------------------


def _drop_service_account(account_id: uuid.UUID) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            params = {"a": str(account_id)}
            conn.execute(
                text("DELETE FROM core.audit_log WHERE actor_service_account_id = :a"), params
            )
            conn.execute(text("DELETE FROM core.service_accounts WHERE id = :a"), params)
    finally:
        engine.dispose()


def _audit(tenant_id: uuid.UUID, outcome: str) -> int:
    return admin_scalar(
        "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t AND action = 'ai.usage.read' "
        "AND outcome = :o",
        t=str(tenant_id),
        o=outcome,
    )


def test_only_a_user_holding_ai_usage_read_reads_and_every_refusal_is_audited(
    world: AIWorld,
) -> None:
    scene = world.scene()
    tenant_id = scene.tenant_id
    engineer = world.user()
    approver = world.member(tenant_id, ("support_access_request", "approve"))
    request = create_support_access_request(
        caller=UserCaller(engineer),
        tenant_id=tenant_id,
        reason="usage boundary",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    approve_support_access(caller=approver, tenant_id=tenant_id, request_id=request.id)
    billing = world.member(tenant_id, ("billing.subscription", "read"))
    refused_users: list[UserCaller] = [
        scene.member,  # runs inference, holds nothing else
        scene.manager,  # ai.policy:manage and ai.policy:read
        billing,
        UserCaller(engineer),  # support access never satisfies it
    ]
    for caller in refused_users:
        with pytest.raises(AuthorityNotAuthorizedError):
            read_tenant_ai_usage(tenant_id, caller=caller, entitlements=_NO_LIMIT)
    assert _audit(tenant_id, "denied") == len(refused_users)

    account = create_service_account(tenant_id, f"svc-{uuid.uuid4().hex[:6]}", caller=PROVISIONING)
    try:
        with pytest.raises(AuthorityNotAuthorizedError):
            read_tenant_ai_usage(
                tenant_id,
                caller=ServiceAccountCaller(account.id, tenant_id),
                entitlements=_NO_LIMIT,
            )
        assert _audit(tenant_id, "denied") == len(refused_users) + 1
    finally:
        _drop_service_account(account.id)
    # a service account that does not exist is refused the same way, with no row to attach
    with pytest.raises(AuthorityNotAuthorizedError):
        read_tenant_ai_usage(
            tenant_id,
            caller=ServiceAccountCaller(uuid.uuid4(), tenant_id),
            entitlements=_NO_LIMIT,
        )
    with pytest.raises(AuthorityNotAuthorizedError):
        read_tenant_ai_usage(tenant_id, caller=PROVISIONING, entitlements=_NO_LIMIT)
    with pytest.raises(Exception) as caught:  # noqa: PT011 -- a non-caller object
        read_tenant_ai_usage(tenant_id, caller=object(), entitlements=_NO_LIMIT)
    assert not isinstance(caught.value, AIUsageReadError)
    assert _audit(tenant_id, "success") == 0

    read_tenant_ai_usage(tenant_id, caller=_reader(world, tenant_id), entitlements=_NO_LIMIT)
    assert _audit(tenant_id, "success") == 1


def test_a_tenants_usage_is_not_readable_from_another_tenant_and_unknown_is_identical(
    world: AIWorld,
) -> None:
    mine = world.tenant()
    theirs = world.tenant()
    for seed in _seeds(f"t{uuid.uuid4().hex[:6]}"):
        _insert(theirs, seed)
    reader = _reader(world, mine)
    with pytest.raises(AuthorityNotAuthorizedError) as foreign:
        read_tenant_ai_usage(theirs, caller=reader, since=SINCE, until=UNTIL)
    with pytest.raises(AuthorityNotAuthorizedError) as unknown:
        read_tenant_ai_usage(uuid.uuid4(), caller=reader, since=SINCE, until=UNTIL)
    assert type(foreign.value) is type(unknown.value)
    # my own report never contains the other tenant's rows
    own = read_tenant_ai_usage(
        mine, caller=reader, since=SINCE, until=UNTIL, entitlements=_NO_LIMIT
    )
    assert own.totals.attempts == 0
    assert own.groups == ()


# --- audit and privacy ------------------------------------------------------------------


def test_the_audit_row_holds_the_window_and_grouping_only(world: AIWorld) -> None:
    tenant_id = world.tenant()
    for seed in _seeds(f"t{uuid.uuid4().hex[:6]}"):
        _insert(tenant_id, seed)
    read_tenant_ai_usage(
        tenant_id,
        caller=_reader(world, tenant_id),
        since=SINCE,
        until=UNTIL,
        group_by=AIUsageGroupBy.MODEL,
        entitlements=_NO_LIMIT,
    )
    metadata = admin_scalar(
        "SELECT metadata::text FROM core.audit_log WHERE tenant_id = :t "
        "AND action = 'ai.usage.read' AND outcome = 'success'",
        t=str(tenant_id),
    )
    assert json.loads(metadata) == {
        "since": SINCE.isoformat(),
        "until": UNTIL.isoformat(),
        "group_by": "model",
    }


def test_a_failed_audit_write_fails_the_read(
    world: AIWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = world.tenant()
    reader = _reader(world, tenant_id)

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(tenant_usage, "record_in_transaction", broken)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        read_tenant_ai_usage(tenant_id, caller=reader, entitlements=_NO_LIMIT)
    assert _audit(tenant_id, "success") == 0


def test_the_report_is_a_closed_set_with_no_content_credential_or_decision(
    world: AIWorld,
) -> None:
    tenant_id = world.tenant()
    for seed in _seeds(f"t{uuid.uuid4().hex[:6]}"):
        _insert(tenant_id, seed)
    report = read_tenant_ai_usage(
        tenant_id,
        caller=_reader(world, tenant_id),
        since=SINCE,
        until=UNTIL,
        entitlements=_NO_LIMIT,
    )
    rendered = repr(report)
    assert "DECISION-SENTINEL" not in rendered
    for forbidden in ("decision", "provider_request_id", "other_usage", "credential", "prompt"):
        assert forbidden not in rendered.lower()

    def fields(obj: object) -> set[str]:
        return {f.name for f in dataclasses.fields(obj)}  # type: ignore[arg-type]

    assert fields(report) == {
        "tenant_id",
        "since",
        "until",
        "group_by",
        "basis",
        "totals",
        "groups",
        "quota",
        "budget",
    }
    assert fields(report.totals) == {
        "attempts",
        "attempts_by_state",
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "tokens_by_provenance",
        "cost",
        "usage_unknown_attempts",
        "cost_unknown_attempts",
    }
    assert fields(report.quota) == {"state", "limit", "used", "remaining", "basis"}


# --- limits block -----------------------------------------------------------------------


def test_the_quota_block_distinguishes_no_limit_invalid_unavailable_ok_and_exhausted(
    world: AIWorld,
) -> None:
    tenant_id = world.tenant()
    reader = _reader(world, tenant_id)
    _insert(
        tenant_id,
        Seed("pq", "m", "uc", "succeeded", "provider_reported", datetime.now(UTC), 60, 40, 0),
    )

    def quota(entitlements: Callable[[uuid.UUID], object]) -> tuple[object, ...]:
        q = read_tenant_ai_usage(
            tenant_id,
            caller=reader,
            entitlements=entitlements,  # type: ignore[arg-type]
        ).quota
        return q.state, q.limit, q.used, q.remaining

    assert quota(_NO_LIMIT) == ("unlimited", None, 100, None)  # None, not zero
    assert quota(lambda _t: {"ai.tokens": 1000}) == ("ok", 1000, 100, 900)
    assert quota(lambda _t: {"ai.tokens": 100}) == ("exhausted", 100, 100, 0)
    assert quota(lambda _t: {"ai.tokens": 50}) == ("exhausted", 50, 100, 0)
    for malformed in ("1000", 1.5, -1, True):
        assert quota(lambda _t, v=malformed: {"ai.tokens": v}) == ("invalid", None, None, None)

    def unreadable(_t: uuid.UUID) -> object:
        raise RuntimeError("entitlements unavailable")

    assert quota(unreadable) == ("unavailable", None, None, None)


def test_the_usage_permission_is_never_default_granted(world: AIWorld) -> None:
    scene = world.scene()
    granted = admin_scalar(
        "SELECT count(*) FROM core.role_permissions rp JOIN core.permissions p "
        "ON p.id = rp.permission_id WHERE rp.tenant_id = :t AND p.resource = 'ai.usage'",
        t=str(scene.tenant_id),
    )
    assert granted == 0
