"""Audit digests: tamper evidence for the audit tables, anchored outside
the database (docs/ADR/0053-audit-digests-in-external-logs.md).

`core.audit_log` and `core.platform_audit_log` are append-only for the
application role (ADR-0051), but the table owner and superusers can still
change or delete rows. This module makes such a change detectable:

1. `digest_settled_windows()` (run every minute by the worker,
   `saas_os.core.audit_digest.jobs`) digests each settled window of both
   tables: every row created in `[window_start, window_end)` is serialized
   canonically and hashed with SHA-256 -- per tenant for `core.audit_log`,
   whole for `core.platform_audit_log`. Each record names the digest of
   the window before it, so the records form a chain.
2. Each record is written to the process log as one canonical JSON string
   (`audit_digest_record`) **before** it is stored in `core.audit_digests`.
   The log line is the evidence: the deployment ships the worker's log to
   an append-only store the database owner cannot change (ADR-0053,
   "Deployment requirement"). The table only tells the job where to resume.
3. `verify_records()` (`python -m saas_os.ops.audit_digest verify`) takes the
   records **from that external store**, checks their digests and the
   chain, recomputes every window from the database, and reports each
   window, table and tenant whose rows no longer match.

The application role computes the digests with the access it already
has: `core.audit_log` one tenant at a time under that tenant's RLS scope,
`core.platform_audit_log` and `core.tenants` from an untenanted session
(both are global). No `BYPASSRLS`, no `SECURITY DEFINER`, no new grant
beyond `SELECT` and `INSERT` on `core.audit_digests`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from saas_os.core.audit_digest.config import AuditDigestConfig, get_audit_digest_config
from saas_os.core.audit_digest.models import AuditDigest
from saas_os.core.audit_log import AuditLogEntry
from saas_os.core.platform_authority.models import PlatformAuditLogEntry
from saas_os.core.tenancy.models import Tenant
from saas_os.infra.db import (
    IntegrityError,
    Text,
    now,
    select,
    session_scope,
    tenant_session_scope,
)

logger = logging.getLogger(__name__)

RECORD_FORMAT = "saas-os-audit-digest/1"
LOG_EVENT = "audit_digest"
LOG_RECORD_FIELD = "audit_digest_record"
LOG_DIGEST_FIELD = "audit_digest"

# The columns each row is serialized with, in format version 1. Fixed here,
# not read from the table: a column added later must not change the digest
# of a window recorded earlier. A test fails when a table gains a column
# these lists do not name, so adding one is a deliberate format change.
AUDIT_LOG_COLUMNS: tuple[str, ...] = (
    "id",
    "tenant_id",
    "actor_type",
    "actor_user_id",
    "actor_service_account_id",
    "acting_as_tenant_id",
    "delegation_grant_id",
    "support_access_id",
    "action",
    "resource_type",
    "resource_id",
    "outcome",
    "correlation_id",
    "metadata",
    "created_at",
)
PLATFORM_AUDIT_LOG_COLUMNS: tuple[str, ...] = (
    "id",
    "actor_type",
    "actor_user_id",
    "system_authority",
    "action",
    "target_type",
    "target_id",
    "target_tenant_id",
    "outcome",
    "reason",
    "correlation_id",
    "metadata",
    "created_at",
)

# Windows recomputed per pass when verifying: one query per tenant covers
# this many contiguous windows.
_VERIFY_CHUNK = 168


# --- Canonical form -------------------------------------------------------------


def _canonical_value(value: object) -> object:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    return value


def canonical_json(value: object) -> str:
    """JSON with sorted keys and no whitespace: the same value always
    yields the same text."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_row(columns: Sequence[str], values: Sequence[object]) -> str:
    """One row as canonical JSON: the named columns, UUIDs as strings,
    timestamps in UTC with microseconds. `metadata` arrives as the column's
    stored text (`_selected`), so any edit to it -- even one that leaves
    the JSON value equal -- changes the row."""
    return canonical_json(
        {name: _canonical_value(value) for name, value in zip(columns, values, strict=True)}
    )


def _sha256_lines(lines: Iterable[str]) -> ScopeDigest:
    digest = hashlib.sha256()
    count = 0
    for line in lines:
        digest.update(line.encode("utf-8"))
        digest.update(b"\n")
        count += 1
    return ScopeDigest(count, digest.hexdigest())


@dataclass(frozen=True)
class ScopeDigest:
    """Rows and SHA-256 of one table, or one tenant's part of it, in one window."""

    rows: int
    sha256: str

    def to_json(self) -> dict[str, object]:
        return {"rows": self.rows, "sha256": self.sha256}


@dataclass(frozen=True)
class WindowDigest:
    """The digests of one window, before it is chained into a record."""

    window_start: datetime
    window_end: datetime
    tenants: Mapping[str, ScopeDigest]
    platform: ScopeDigest

    @property
    def audit_log(self) -> ScopeDigest:
        """The tenants' digests combined: one `tenant:rows:sha256` line per
        tenant with rows, sorted by tenant id. A tenant whose rows all
        disappeared drops out of the list, which changes this digest too."""
        combined = _sha256_lines(
            f"{tenant}:{scope.rows}:{scope.sha256}"
            for tenant, scope in sorted(self.tenants.items())
        )
        return ScopeDigest(sum(scope.rows for scope in self.tenants.values()), combined.sha256)


def build_record(window: WindowDigest, previous: str | None) -> dict[str, Any]:
    """The record logged for `window`; `previous` is the digest of the
    previous window's record, `None` for the first."""
    audit_log = window.audit_log
    return {
        "format": RECORD_FORMAT,
        "window_start": _canonical_value(window.window_start),
        "window_end": _canonical_value(window.window_end),
        "audit_log": {
            **audit_log.to_json(),
            "tenants": {
                tenant: scope.to_json() for tenant, scope in sorted(window.tenants.items())
            },
        },
        "platform_audit_log": window.platform.to_json(),
        "previous": previous,
    }


def record_digest(record: Mapping[str, Any]) -> str:
    """SHA-256 of the record's canonical JSON."""
    return hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()


# --- Reading the audit tables ---------------------------------------------------


def _selected(table: Any, columns: Sequence[str]) -> list[Any]:
    """The columns to read, with `metadata` as its stored text rather than
    a decoded JSON value: `json` keeps its input text, so a rewrite that
    decodes to the same value (key order, spacing, `1e2` for `100.0`, a
    duplicate key, SQL NULL for JSON `null`) is still a change."""
    return [
        table.c[name].cast(Text).label(name) if name == "metadata" else table.c[name]
        for name in columns
    ]


def _tenant_ids() -> list[uuid.UUID]:
    with session_scope() as session:
        return sorted(session.execute(select(Tenant.id)).scalars().all())


def _tenant_rows(
    tenant_id: uuid.UUID, start: datetime, end: datetime
) -> list[tuple[datetime, str]]:
    """(`created_at`, canonical row) for one tenant's `core.audit_log` rows
    in `[start, end)`, read under that tenant's RLS scope, in
    `(created_at, id)` order."""
    table = AuditLogEntry.__table__
    created = AUDIT_LOG_COLUMNS.index("created_at")
    with tenant_session_scope(tenant_id) as session:
        rows = session.execute(
            select(*_selected(table, AUDIT_LOG_COLUMNS))
            .where(
                table.c.tenant_id == tenant_id,
                table.c.created_at >= start,
                table.c.created_at < end,
            )
            .order_by(table.c.created_at, table.c.id)
        ).all()
    return [(row[created], canonical_row(AUDIT_LOG_COLUMNS, row)) for row in rows]


def _tenant_earliest(tenant_id: uuid.UUID) -> datetime | None:
    table = AuditLogEntry.__table__
    with tenant_session_scope(tenant_id) as session:
        return session.execute(
            select(table.c.created_at)
            .where(table.c.tenant_id == tenant_id)
            .order_by(table.c.created_at)
            .limit(1)
        ).scalar_one_or_none()


def _platform_rows(start: datetime, end: datetime) -> list[tuple[datetime, str]]:
    """The same for `core.platform_audit_log` (global, read untenanted)."""
    table = PlatformAuditLogEntry.__table__
    created = PLATFORM_AUDIT_LOG_COLUMNS.index("created_at")
    with session_scope() as session:
        rows = session.execute(
            select(*_selected(table, PLATFORM_AUDIT_LOG_COLUMNS))
            .where(table.c.created_at >= start, table.c.created_at < end)
            .order_by(table.c.created_at, table.c.id)
        ).all()
    return [(row[created], canonical_row(PLATFORM_AUDIT_LOG_COLUMNS, row)) for row in rows]


def _platform_earliest() -> datetime | None:
    table = PlatformAuditLogEntry.__table__
    with session_scope() as session:
        return session.execute(
            select(table.c.created_at).order_by(table.c.created_at).limit(1)
        ).scalar_one_or_none()


# Rows outside the covered range are counted up to this many per scope;
# more is reported as "more than".
_OUTSIDE_CAP = 1000


def _outside_ranges(
    before: datetime, after: datetime, until: datetime | None
) -> list[tuple[datetime | None, datetime]]:
    """`[None, before)`, and `[after, until)` when `until` is past `after`."""
    ranges: list[tuple[datetime | None, datetime]] = [(None, before)]
    if until is not None and until > after:
        ranges.append((after, until))
    return ranges


def _tenant_outside(
    tenant_id: uuid.UUID, before: datetime, after: datetime, until: datetime | None
) -> list[int]:
    """One tenant's rows created before `before`, and -- when `until` is
    given -- from `after` up to `until`: rows no record covers."""
    table = AuditLogEntry.__table__
    counts: list[int] = []
    with tenant_session_scope(tenant_id) as session:
        for low, high in _outside_ranges(before, after, until):
            query = select(table.c.id).where(
                table.c.tenant_id == tenant_id, table.c.created_at < high
            )
            if low is not None:
                query = query.where(table.c.created_at >= low)
            counts.append(len(session.execute(query.limit(_OUTSIDE_CAP + 1)).all()))
    return counts


def _platform_outside(before: datetime, after: datetime, until: datetime | None) -> list[int]:
    """The same for `core.platform_audit_log`."""
    table = PlatformAuditLogEntry.__table__
    counts: list[int] = []
    with session_scope() as session:
        for low, high in _outside_ranges(before, after, until):
            query = select(table.c.id).where(table.c.created_at < high)
            if low is not None:
                query = query.where(table.c.created_at >= low)
            counts.append(len(session.execute(query.limit(_OUTSIDE_CAP + 1)).all()))
    return counts


def _bucket(
    rows: Sequence[tuple[datetime, str]], starts: Sequence[datetime], width: timedelta
) -> list[list[str]]:
    buckets: list[list[str]] = [[] for _ in starts]
    for created_at, line in rows:
        buckets[(created_at - starts[0]) // width].append(line)
    return buckets


def compute_windows(starts: Sequence[datetime], width: timedelta) -> list[WindowDigest]:
    """The digests of the contiguous windows `[s, s + width)`, one per `s`
    in `starts` (ascending, `width` apart). Each tenant is read once for
    the whole range."""
    if not starts:
        return []
    begin, end = starts[0], starts[-1] + width
    tenants: list[dict[str, ScopeDigest]] = [{} for _ in starts]
    for tenant_id in _tenant_ids():
        rows = _tenant_rows(tenant_id, begin, end)
        if rows:
            for index, lines in enumerate(_bucket(rows, starts, width)):
                if lines:
                    tenants[index][str(tenant_id)] = _sha256_lines(lines)
    platform = _bucket(_platform_rows(begin, end), starts, width)
    return [
        WindowDigest(
            window_start=start,
            window_end=start + width,
            tenants=tenants[index],
            platform=_sha256_lines(platform[index]),
        )
        for index, start in enumerate(starts)
    ]


# --- Digesting settled windows --------------------------------------------------


def floor_to_window(moment: datetime, width: timedelta) -> datetime:
    """The start of the window containing `moment` (windows aligned to the
    Unix epoch, in UTC)."""
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    return epoch + ((moment - epoch) // width) * width


def _earliest_row() -> datetime | None:
    found = [moment for moment in map(_tenant_earliest, _tenant_ids()) if moment is not None]
    platform = _platform_earliest()
    if platform is not None:
        found.append(platform)
    return min(found) if found else None


@dataclass(frozen=True)
class _Stored:
    window_end: datetime
    digest: str
    record: str


def _cursor() -> tuple[datetime, _Stored | None]:
    """The database clock, and the last stored window."""
    with session_scope() as session:
        clock = session.execute(select(now())).scalar_one()
        last = session.execute(
            select(AuditDigest.window_end, AuditDigest.digest, AuditDigest.record)
            .order_by(AuditDigest.window_start.desc())
            .limit(1)
        ).one_or_none()
    return clock, _Stored(last[0], last[1], last[2]) if last is not None else None


def settled_until(config: AuditDigestConfig | None = None) -> datetime:
    """The end of the newest window that has settled by the database
    clock: every row before it should be covered by a record."""
    cfg = config or get_audit_digest_config()
    clock, _ = _cursor()
    return floor_to_window(clock - cfg.settle, cfg.window)


def _store(window: WindowDigest, record: Mapping[str, Any], digest: str) -> bool:
    """Store the record; `False` when another run stored this window first."""
    try:
        with session_scope() as session:
            session.add(
                AuditDigest(
                    window_start=window.window_start,
                    window_end=window.window_end,
                    digest=digest,
                    record=canonical_json(record),
                )
            )
    except IntegrityError:
        return False
    return True


def emit_record(record: Mapping[str, Any], digest: str) -> None:
    """Write `record` to the log as one canonical JSON string -- the line
    the deployment ships to its append-only store (module docstring)."""
    logger.info(
        LOG_EVENT,
        extra={
            LOG_RECORD_FIELD: canonical_json(record),
            LOG_DIGEST_FIELD: digest,
            "window_start": record["window_start"],
            "window_end": record["window_end"],
        },
    )


@dataclass
class DigestRun:
    """What one `digest_settled_windows()` run did."""

    records: list[dict[str, Any]] = field(default_factory=list)
    digests: list[str] = field(default_factory=list)
    stopped_by_concurrent_run: bool = False


def digest_settled_windows(config: AuditDigestConfig | None = None) -> DigestRun:
    """Digest every window settled since the last one stored, at most
    `max_windows_per_run`. A window has settled once the database clock
    is past its end plus `settle_seconds`: a row is stamped with its
    transaction's start time, so a transaction still open at the window's
    end can add a row to it until it commits.

    The first run starts at the window of the oldest audit row, so
    existing history is covered. Each record is logged first, then stored:
    a crash between the two logs the record again on the next run. A run
    that digests new windows first logs the previous stored record once
    more, so every record is logged at least twice, a window apart, and
    one line lost on its way to the store is not a gap. When another
    worker stored a window first, this run stops.

    Delivery cannot be confirmed from here: a record whose lines all fail
    to reach the store is a `gap` for the verifier (ADR-0053)."""
    cfg = config or get_audit_digest_config()
    width, settle = cfg.window, cfg.settle
    clock, last = _cursor()
    if last is not None:
        start, previous = last.window_end, last.digest
    else:
        earliest = _earliest_row()
        start = floor_to_window(earliest if earliest is not None else clock, width)
        previous = None

    starts: list[datetime] = []
    while len(starts) < cfg.max_windows_per_run and start + width + settle <= clock:
        starts.append(start)
        start += width

    run = DigestRun()
    if starts and last is not None:
        emit_record(json.loads(last.record), last.digest)
    for window in compute_windows(starts, width):
        record = build_record(window, previous)
        digest = record_digest(record)
        emit_record(record, digest)
        if not _store(window, record, digest):
            run.stopped_by_concurrent_run = True
            break
        run.records.append(record)
        run.digests.append(digest)
        previous = digest
    return run


# --- Verification ---------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One problem `verify_records()` found. `window_start` is `None` when
    the problem concerns the input as a whole."""

    kind: str
    window_start: str | None
    detail: str


@dataclass
class Verification:
    windows: int = 0
    findings: list[Finding] = field(default_factory=list)
    covered_from: str | None = None
    covered_until: str | None = None

    @property
    def ok(self) -> bool:
        return self.windows > 0 and not self.findings


@dataclass(frozen=True)
class LoggedRecord:
    """A record as found in the external store, with the digest its log
    line stated."""

    record: dict[str, Any]
    stated_digest: str | None


def records_from_log_lines(lines: Iterable[str]) -> list[LoggedRecord]:
    """The digest records in exported log lines (one JSON object per line,
    as the worker's formatter writes them). Other lines are skipped. A
    plain record per line (the `audit_digest_record` value itself) is
    accepted too."""
    found: list[LoggedRecord] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        if LOG_RECORD_FIELD in entry:
            try:
                record = json.loads(entry[LOG_RECORD_FIELD])
            except (TypeError, ValueError):
                found.append(LoggedRecord({}, entry.get(LOG_DIGEST_FIELD)))
                continue
            found.append(LoggedRecord(record, entry.get(LOG_DIGEST_FIELD)))
        elif entry.get("format") == RECORD_FORMAT:
            found.append(LoggedRecord(entry, None))
    return found


def _check_chain(records: Sequence[LoggedRecord], result: Verification) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for logged in records:
        record = logged.record
        window = record.get("window_start")
        if record.get("format") != RECORD_FORMAT:
            result.findings.append(
                Finding("unknown_format", window, f"format {record.get('format')!r}")
            )
            continue
        digest = record_digest(record)
        if logged.stated_digest is not None and logged.stated_digest != digest:
            result.findings.append(
                Finding("record_altered", window, "the log line's digest does not match its record")
            )
            continue
        unique.setdefault(digest, record)

    ordered = sorted(unique.items(), key=lambda item: (item[1]["window_start"], item[0]))
    chain: list[dict[str, Any]] = []
    prior: tuple[str, dict[str, Any]] | None = None
    for digest, record in ordered:
        window = record["window_start"]
        if prior is None:
            if record["previous"] is not None:
                result.findings.append(
                    Finding("chain_start_missing", window, "the first record names a predecessor")
                )
        else:
            prior_digest, prior_record = prior
            if prior_record["window_start"] == window:
                result.findings.append(
                    Finding("conflicting_records", window, "two different records for one window")
                )
                continue
            if prior_record["window_end"] != window:
                result.findings.append(
                    Finding("gap", window, f"no record from {prior_record['window_end']}")
                )
            if record["previous"] != prior_digest:
                kind = "chain_restarted" if record["previous"] is None else "chain_broken"
                result.findings.append(
                    Finding(kind, window, "previous does not name the prior record's digest")
                )
        prior = (digest, record)
        chain.append(record)
    return chain


def _compare(result: Verification, record: Mapping[str, Any], actual: WindowDigest) -> None:
    window = record["window_start"]
    recorded_tenants: Mapping[str, Any] = record["audit_log"]["tenants"]
    actual_tenants = {tenant: scope.to_json() for tenant, scope in actual.tenants.items()}
    for tenant in sorted(set(recorded_tenants) | set(actual_tenants)):
        if recorded_tenants.get(tenant) != actual_tenants.get(tenant):
            result.findings.append(
                Finding(
                    "audit_log_changed",
                    window,
                    f"tenant {tenant}: recorded {recorded_tenants.get(tenant)}, "
                    f"now {actual_tenants.get(tenant)}",
                )
            )
    if record["platform_audit_log"] != actual.platform.to_json():
        result.findings.append(
            Finding(
                "platform_audit_log_changed",
                window,
                f"recorded {record['platform_audit_log']}, now {actual.platform.to_json()}",
            )
        )


def _check_coverage(
    result: Verification, before: datetime, after: datetime, until: datetime | None
) -> None:
    """Rows no record covers: any before the first window -- inserted
    there after the chain began, or left behind by a restarted chain --
    and, when `until` is given, any in settled windows after the last
    record (a truncated export, or records lost on the way to the store)."""
    outside = {
        f"tenant {tenant}": _tenant_outside(tenant, before, after, until)
        for tenant in _tenant_ids()
    }
    outside["platform"] = _platform_outside(before, after, until)
    for scope, counts in sorted(outside.items()):
        for (low, high), found in zip(_outside_ranges(before, after, until), counts, strict=True):
            if not found:
                continue
            amount = f"more than {_OUTSIDE_CAP}" if found > _OUTSIDE_CAP else str(found)
            if low is None:
                kind, span = "rows_before_coverage", f"before {_canonical_value(high)}"
            else:
                kind = "rows_after_coverage"
                span = f"from {_canonical_value(low)} to {_canonical_value(high)}"
            result.findings.append(Finding(kind, None, f"{scope}: {amount} rows {span}"))


def verify_records(
    records: Iterable[LoggedRecord], *, settled_until: datetime | None = None
) -> Verification:
    """Check records taken from the external store against the database:

    - each log line's digest matches its record;
    - the windows are contiguous and each names the previous record's
      digest, from one first record (`previous: null`) on;
    - each window's rows, recomputed now, match the record -- per tenant
      for `core.audit_log`, whole for `core.platform_audit_log`.

    - no audit row lies before the first window, and -- when
      `settled_until` is given -- none lies between the last window and
      `settled_until` (pass `settled_until()` to require the export to
      reach the newest settled window).

    The same record logged twice counts once. `covered_until` says where
    coverage ends."""
    result = Verification()
    chain = _check_chain(list(records), result)
    if not chain:
        result.findings.append(Finding("no_records", None, "no digest records in the input"))
        return result

    batch: list[Mapping[str, Any]] = []

    def flush() -> None:
        if not batch:
            return
        width = datetime.fromisoformat(batch[0]["window_end"]) - datetime.fromisoformat(
            batch[0]["window_start"]
        )
        starts = [datetime.fromisoformat(record["window_start"]) for record in batch]
        for record, actual in zip(batch, compute_windows(starts, width), strict=True):
            _compare(result, record, actual)
            result.windows += 1
        batch.clear()

    for record in chain:
        start = datetime.fromisoformat(record["window_start"])
        width = datetime.fromisoformat(record["window_end"]) - start
        if batch:
            batch_width = datetime.fromisoformat(batch[-1]["window_end"]) - datetime.fromisoformat(
                batch[-1]["window_start"]
            )
            contiguous = batch[-1]["window_end"] == record["window_start"] and batch_width == width
            if not contiguous or len(batch) >= _VERIFY_CHUNK:
                flush()
        batch.append(record)
    flush()
    result.covered_from = chain[0]["window_start"]
    result.covered_until = chain[-1]["window_end"]
    _check_coverage(
        result,
        datetime.fromisoformat(chain[0]["window_start"]),
        datetime.fromisoformat(chain[-1]["window_end"]),
        settled_until,
    )
    return result
