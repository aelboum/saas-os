"""AI usage reads and the token-quota projection at 1,000,000 attempts
(Gap 22 acceptance criterion 12; ADR-0054 amendment of 2026-11-11).

Opt-in: marked `performance`, not `integration`, so neither the default run
nor the integration gate (`pytest -m integration`) collects it. Run it alone
against a disposable, migrated PostgreSQL:

    pytest -m performance tests/control_plane/inference/test_ai_usage_performance.py

It seeds two tenants with 1,000,000 finished attempts each, directly through
the migrations role (`generate_series`, committed in chunks of 20,000 rows;
the rollup trigger fires for every row, as it does for the governed path):

- **spread**: 1,000,000 attempts over the twelve whole UTC months before the
  current one (about 83,000 a month). A month report reads one month of them.
- **hot**: 1,000,000 attempts in the current UTC month, the worst case for the
  reads of the current month: the limits read, the default usage read, and the
  soft token quota's projection that `run_inference` makes before every call
  when a token quota is configured (`accounting.recorded_tokens`).

Pinned, as the criterion asks, by the query plan and not by wall time alone:
the month report's aggregate, run as the application role with the tenant set
(row-level security in force), reads `ix_ai_inference_attempts_tenant_started`
and never scans the attempts table sequentially. Each read also stays inside a
stated bound (the constants below, about three times the time measured on the
reference run recorded in the gap register). The bounds are for a disposable
local PostgreSQL; they are a regression signal, not a service-level promise.

Cleanup deletes both tenants' attempts and rollup rows through the migrations
role. No provider, no network.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import AIWorld
from saas_os.control_plane.inference.accounting import month_window, recorded_tokens
from saas_os.control_plane.inference.tenant_usage import (
    AIUsageGroupBy,
    read_tenant_ai_limits,
    read_tenant_ai_monthly_usage,
    read_tenant_ai_usage,
)
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import tenant_session_scope

pytestmark = [pytest.mark.performance]

ATTEMPTS = 1_000_000
# One transaction per chunk: the rollup trigger updates the same few hundred
# `ai_usage_monthly` rows for every attempt, and inside one transaction none of
# those row versions can be pruned, so a single 1,000,000-row statement slows
# with every row it adds (it had not finished after 75 minutes).
SEED_CHUNK = 20_000
INDEX = "ix_ai_inference_attempts_tenant_started"

# Stated bounds, in seconds (module docstring): about three times the reference
# run of 2026-11-12 (PostgreSQL 16 in Docker Desktop, Windows 11), whose times
# follow each bound.
MONTH_REPORT_BOUND = 1.0  # 0.345 s
MONTH_REPORT_BY_DAY_BOUND = 1.5  # 0.482 s
MONTHLY_ROLLUP_BOUND = 0.25  # 0.084 s
HOT_MONTH_REPORT_BOUND = 2.5  # 0.876 s
HOT_LIMITS_BOUND = 1.0  # 0.314 s
HOT_QUOTA_PROJECTION_BOUND = 0.75  # 0.245 s

USAGE = ("ai.usage", "read")
_NO_LIMIT: Callable[[uuid.UUID], dict[str, object]] = lambda _t: {}  # noqa: E731
_NO_PLANS: Callable[[uuid.UUID], list[uuid.UUID]] = lambda _t: []  # noqa: E731


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
            conn.execute(text("SELECT 1 FROM control_plane.ai_usage_monthly LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"AI tables missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


def _admin(sql: str, **params: object) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(text(sql), params)
    finally:
        engine.dispose()


# Varied keys so the report has groups to build: three providers, four models,
# three use cases, every finished state and provenance, two currencies, and
# attempts with no price or no usage.
_SEED = """
INSERT INTO control_plane.ai_inference_attempts (
    id, tenant_id, request_id, attempt_number, actor_type, use_case, alias,
    provider_key, model_id, provider_config_version, model_config_version,
    effective_classification, decision, state, started_at, finished_at,
    input_tokens, output_tokens, cached_input_tokens, usage_provenance,
    estimated_cost, currency)
SELECT gen_random_uuid(), CAST(:t AS uuid), gen_random_uuid(), 1, 'service_account',
       'uc-' || (g % 3), 'alias', 'p' || (g % 3), 'm' || (g % 4), 1, 1, 'tenant_data',
       CAST('{}' AS json),
       CASE WHEN g % 50 = 0 THEN 'failed' WHEN g % 97 = 0 THEN 'interrupted'
            ELSE 'succeeded' END,
       ts, ts,
       CASE WHEN g % 50 = 0 THEN NULL ELSE 100 + g % 400 END,
       CASE WHEN g % 50 = 0 THEN NULL ELSE 20 + g % 200 END,
       CASE WHEN g % 7 = 0 THEN 10 ELSE NULL END,
       CASE WHEN g % 50 = 0 THEN 'unknown' WHEN g % 11 = 0 THEN 'estimated'
            ELSE 'provider_reported' END,
       CASE WHEN g % 50 = 0 OR g % 13 = 0 THEN NULL ELSE 0.00012345 END,
       CASE WHEN g % 50 = 0 OR g % 13 = 0 THEN NULL
            WHEN g % 5 = 0 THEN 'EUR' ELSE 'USD' END
FROM (
    SELECT g, CAST(:since AS timestamptz)
              + (CAST(:until AS timestamptz) - CAST(:since AS timestamptz))
                * ((g - 1)::float8 / :n) AS ts
    FROM generate_series(CAST(:lo AS integer), CAST(:hi AS integer)) AS g
) AS s
"""


class _Seeded:
    def __init__(self, world: AIWorld) -> None:
        self.spread = world.tenant()
        self.hot = world.tenant()
        self.spread_reader = world.member(self.spread, USAGE)
        self.hot_reader = world.member(self.hot, USAGE)
        self.current_start, _ = month_window()
        self.spread_since = _add_months(self.current_start, -12)
        self.seed_seconds: dict[str, float] = {}


def _add_months(start: datetime, months: int) -> datetime:
    index = start.year * 12 + start.month - 1 + months
    return start.replace(year=index // 12, month=index % 12 + 1)


@pytest.fixture(scope="module")
def seeded() -> Iterator[_Seeded]:
    world = AIWorld()
    data = _Seeded(world)
    try:
        now = datetime.now(UTC)
        for name, tenant, since, until in (
            ("spread", data.spread, data.spread_since, data.current_start),
            ("hot", data.hot, data.current_start, max(now - timedelta(seconds=1),
                                                      data.current_start + timedelta(seconds=1))),
        ):  # fmt: skip
            began = time.perf_counter()
            for lo in range(1, ATTEMPTS + 1, SEED_CHUNK):
                hi = min(lo + SEED_CHUNK - 1, ATTEMPTS)
                _admin(_SEED, t=str(tenant), since=since, until=until, n=ATTEMPTS, lo=lo, hi=hi)
            data.seed_seconds[name] = time.perf_counter() - began
        _admin("ANALYZE control_plane.ai_inference_attempts")
        _admin("ANALYZE control_plane.ai_usage_monthly")
        yield data
    finally:
        tenants = [str(data.spread), str(data.hot)]
        _admin(
            "DELETE FROM control_plane.ai_inference_attempts WHERE tenant_id = ANY(:t)", t=tenants
        )
        _admin("DELETE FROM control_plane.ai_usage_monthly WHERE tenant_id = ANY(:t)", t=tenants)
        world.cleanup()


def _best_of(times: int, call: Callable[[], Any]) -> tuple[float, Any]:
    """The fastest of `times` runs (the first warms the cache) and its result."""
    best, result = float("inf"), None
    for _ in range(times):
        began = time.perf_counter()
        result = call()
        best = min(best, time.perf_counter() - began)
    return best, result


class _Captured:
    """The SQL of the attempts aggregate, as SQLAlchemy sent it."""

    def __init__(self) -> None:
        self.statements: list[tuple[str, Any]] = []

    def __call__(self, conn: Any, cursor: Any, statement: str, parameters: Any, *_: Any) -> None:
        if "ai_inference_attempts" in statement and "GROUP BY" in statement:
            self.statements.append((statement, parameters))


def _plan_nodes(plan: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield plan
    for child in plan.get("Plans", []):
        yield from _plan_nodes(child)


def _attempt_scans(tenant_id: uuid.UUID, statement: str, parameters: Any) -> list[dict[str, Any]]:
    """EXPLAIN the captured statement as the application role with the
    tenant set (row-level security in force), and return the plan nodes that
    read the attempts table."""
    with tenant_session_scope(tenant_id) as session:
        raw = (
            session.connection()
            .exec_driver_sql("EXPLAIN (FORMAT JSON) " + statement, parameters)
            .scalar_one()
        )
    document = raw if isinstance(raw, list) else json.loads(raw)
    return [
        node
        for node in _plan_nodes(document[0]["Plan"])
        if node.get("Relation Name") == "ai_inference_attempts"
        or INDEX in str(node.get("Index Name", ""))
    ]


def _report(label: str, seconds: float, bound: float) -> None:
    print(f"\n[ai-usage-performance] {label}: {seconds:.3f} s (bound {bound} s)")  # noqa: T201


# --- spread: a month of 1,000,000 attempts over twelve months --------------------------------


def test_a_month_report_reads_the_tenant_started_index_and_stays_in_bound(
    seeded: _Seeded,
) -> None:
    month_start = _add_months(seeded.current_start, -1)
    capture = _Captured()
    event.listen(Engine, "before_cursor_execute", capture)
    try:
        seconds, report = _best_of(
            3,
            lambda: read_tenant_ai_usage(
                seeded.spread,
                caller=seeded.spread_reader,
                since=month_start,
                until=seeded.current_start,
                entitlements=_NO_LIMIT,
                budget_plans=_NO_PLANS,
            ),
        )
    finally:
        event.remove(Engine, "before_cursor_execute", capture)

    print(f"\n[ai-usage-performance] seed seconds: {seeded.seed_seconds}")  # noqa: T201
    _report("month report, one month of ~83k (1M over 12 months)", seconds, MONTH_REPORT_BOUND)
    assert 80_000 < report.totals.attempts < 87_000
    assert capture.statements, "the attempts aggregate was not captured"
    statement, parameters = capture.statements[-1]
    scans = _attempt_scans(seeded.spread, statement, parameters)
    node_types = {node["Node Type"] for node in scans}
    assert any(INDEX == node.get("Index Name") for node in scans), node_types
    assert "Seq Scan" not in node_types, node_types
    assert seconds < MONTH_REPORT_BOUND


def test_a_month_report_by_day_stays_in_bound(seeded: _Seeded) -> None:
    month_start = _add_months(seeded.current_start, -1)
    seconds, report = _best_of(
        2,
        lambda: read_tenant_ai_usage(
            seeded.spread,
            caller=seeded.spread_reader,
            since=month_start,
            until=seeded.current_start,
            group_by=AIUsageGroupBy.DAY,
            entitlements=_NO_LIMIT,
            budget_plans=_NO_PLANS,
        ),
    )
    _report("month report by day (one query per day)", seconds, MONTH_REPORT_BY_DAY_BOUND)
    assert 80_000 < report.totals.attempts < 87_000
    assert seconds < MONTH_REPORT_BY_DAY_BOUND


def test_the_monthly_rollup_read_of_twelve_months_stays_in_bound(seeded: _Seeded) -> None:
    seconds, report = _best_of(
        3,
        lambda: read_tenant_ai_monthly_usage(
            seeded.spread,
            caller=seeded.spread_reader,
            since=seeded.spread_since,
            until=seeded.current_start,
        ),
    )
    _report("monthly rollup read, 12 months", seconds, MONTHLY_ROLLUP_BOUND)
    assert report.totals.attempts == ATTEMPTS
    assert seconds < MONTHLY_ROLLUP_BOUND


# --- hot: 1,000,000 attempts in the current month ---------------------------------------------


def test_the_current_month_report_of_one_million_attempts_stays_in_bound(
    seeded: _Seeded,
) -> None:
    seconds, report = _best_of(
        2,
        lambda: read_tenant_ai_usage(
            seeded.hot,
            caller=seeded.hot_reader,
            entitlements=_NO_LIMIT,
            budget_plans=_NO_PLANS,
        ),
    )
    _report("current month report, 1M in the month", seconds, HOT_MONTH_REPORT_BOUND)
    assert report.totals.attempts == ATTEMPTS
    assert seconds < HOT_MONTH_REPORT_BOUND


def test_the_limits_read_of_a_month_of_one_million_attempts_stays_in_bound(
    seeded: _Seeded,
) -> None:
    seconds, report = _best_of(
        3,
        lambda: read_tenant_ai_limits(
            seeded.hot,
            caller=seeded.hot_reader,
            entitlements=lambda _t: {"ai.tokens": 10**12},
            budget_plans=_NO_PLANS,
        ),
    )
    _report("limits read, 1M in the month", seconds, HOT_LIMITS_BOUND)
    assert report.quota.state == "ok"
    assert (report.quota.used or 0) > 0
    assert seconds < HOT_LIMITS_BOUND


def test_the_token_quota_projection_of_a_month_of_one_million_attempts_stays_in_bound(
    seeded: _Seeded,
) -> None:
    """`recorded_tokens` runs before every governed call of a tenant with a
    token quota (`check_soft_token_quota`)."""
    since, until = month_window()
    seconds, used = _best_of(3, lambda: recorded_tokens(seeded.hot, since, until))
    _report("token quota projection per call, 1M in the month", seconds,
            HOT_QUOTA_PROJECTION_BOUND)  # fmt: skip
    assert used > 0
    assert seconds < HOT_QUOTA_PROJECTION_BOUND
