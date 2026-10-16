"""ADR-0053 -- the audit digests' canonical form, records, log lines and
chain checks, without a database (the window computation is replaced by
recorded values where verification needs it)."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest

from saas_os.core.audit_digest import (
    AUDIT_LOG_COLUMNS,
    LOG_EVENT,
    PLATFORM_AUDIT_LOG_COLUMNS,
    RECORD_FORMAT,
    AuditDigestConfig,
    AuditDigestConfigurationError,
    Finding,
    LoggedRecord,
    ScopeDigest,
    Verification,
    WindowDigest,
    build_record,
    canonical_json,
    canonical_row,
    floor_to_window,
    record_digest,
    records_from_log_lines,
    verify_records,
)
from saas_os.core.audit_digest import service as digest_service
from saas_os.core.audit_log import AuditLogEntry
from saas_os.core.platform_authority.models import PlatformAuditLogEntry
from saas_os.infra.observability.logging import JsonFormatter

T0 = datetime(2026, 10, 16, 10, tzinfo=UTC)
HOUR = timedelta(hours=1)
_TENANT = "6f1c2a4e-0000-4000-8000-000000000001"


def test_the_column_lists_name_every_column_of_both_tables() -> None:
    # A new column changes the canonical form: it must be added here, with a
    # new format version, deliberately.
    assert set(AUDIT_LOG_COLUMNS) == {c.name for c in AuditLogEntry.__table__.columns}
    assert set(PLATFORM_AUDIT_LOG_COLUMNS) == {
        c.name for c in PlatformAuditLogEntry.__table__.columns
    }
    assert RECORD_FORMAT == "saas-os-audit-digest/1"


def test_a_row_has_one_canonical_form() -> None:
    row_id = uuid.UUID("12345678-1234-5678-1234-567812345678")
    plus_two = timezone(timedelta(hours=2))
    a = canonical_row(
        ("id", "metadata", "created_at"),
        (row_id, {"b": 1, "a": {"y": 2, "x": 1}}, datetime(2026, 1, 1, 12, tzinfo=plus_two)),
    )
    b = canonical_row(
        ("created_at", "id", "metadata"),
        (datetime(2026, 1, 1, 10, tzinfo=UTC), row_id, {"a": {"x": 1, "y": 2}, "b": 1}),
    )
    assert a == b
    assert a == (
        '{"created_at":"2026-01-01T10:00:00.000000+00:00",'
        '"id":"12345678-1234-5678-1234-567812345678","metadata":{"a":{"x":1,"y":2},"b":1}}'
    )


def _window(tenants: dict[str, ScopeDigest], start: datetime = T0) -> WindowDigest:
    return WindowDigest(start, start + HOUR, tenants, ScopeDigest(0, "e" * 64))


def test_a_tenant_dropping_out_changes_the_table_digest() -> None:
    both = _window({_TENANT: ScopeDigest(1, "a" * 64), "7" + _TENANT[1:]: ScopeDigest(1, "b" * 64)})
    one = _window({_TENANT: ScopeDigest(1, "a" * 64)})
    assert both.audit_log.rows == 2 and one.audit_log.rows == 1
    assert both.audit_log.sha256 != one.audit_log.sha256


def test_a_record_and_its_digest() -> None:
    record = build_record(_window({_TENANT: ScopeDigest(2, "a" * 64)}), None)
    assert record["format"] == RECORD_FORMAT
    assert record["window_start"] == "2026-10-16T10:00:00.000000+00:00"
    assert record["audit_log"]["tenants"] == {_TENANT: {"rows": 2, "sha256": "a" * 64}}
    assert record["previous"] is None
    digest = record_digest(record)
    assert digest == record_digest(dict(reversed(list(record.items()))))
    assert record_digest({**record, "previous": "0" * 64}) != digest


def test_windows_align_to_the_epoch() -> None:
    assert floor_to_window(datetime(2026, 10, 16, 10, 59, 59, tzinfo=UTC), HOUR) == T0
    assert (
        floor_to_window(datetime(2026, 10, 16, 12, 30, tzinfo=timezone(timedelta(hours=2))), HOUR)
        == T0
    )


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"window_seconds": 7000}, "AUDIT_DIGEST_WINDOW_SECONDS"),
        ({"window_seconds": 240}, "AUDIT_DIGEST_WINDOW_SECONDS"),
        ({"settle_seconds": 30}, "AUDIT_DIGEST_SETTLE_SECONDS"),
        ({"max_windows_per_run": 0}, "AUDIT_DIGEST_MAX_WINDOWS_PER_RUN"),
    ],
)
def test_bad_configuration_is_refused(values: dict[str, int], message: str) -> None:
    with pytest.raises(AuditDigestConfigurationError, match=message):
        AuditDigestConfig(**values)


def _logged_lines(records: list[dict], caplog: pytest.LogCaptureFixture) -> list[str]:
    caplog.set_level(logging.INFO, logger=digest_service.__name__)
    caplog.clear()
    for record in records:
        digest_service.emit_record(record, record_digest(record))
    return [JsonFormatter().format(r) for r in caplog.records if r.getMessage() == LOG_EVENT]


def _chain(count: int) -> list[dict]:
    records, previous = [], None
    for index in range(count):
        record = build_record(
            _window({_TENANT: ScopeDigest(index, f"{index:064x}")}, T0 + index * HOUR), previous
        )
        previous = record_digest(record)
        records.append(record)
    return records


def test_a_logged_record_survives_the_formatter_and_redaction(
    caplog: pytest.LogCaptureFixture,
) -> None:
    records = _chain(2)
    lines = _logged_lines(records, caplog)
    parsed = records_from_log_lines(["not json", '{"message": "other"}', *lines, ""])
    assert [p.record for p in parsed] == records
    assert [p.stated_digest for p in parsed] == [record_digest(r) for r in records]
    # A bare record per line is accepted too.
    (bare,) = records_from_log_lines([canonical_json(records[0])])
    assert bare.record == records[0] and bare.stated_digest is None


@pytest.fixture
def matching_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Recompute each window as recorded in `_chain`, so only the chain
    checks can produce findings."""

    def fake(starts: list[datetime], width: timedelta) -> list[WindowDigest]:
        return [
            _window({_TENANT: ScopeDigest(int((s - T0) / HOUR), f"{int((s - T0) / HOUR):064x}")}, s)
            for s in starts
        ]

    monkeypatch.setattr(digest_service, "compute_windows", fake)


def _kinds(records: list[LoggedRecord]) -> list[str]:
    return [finding.kind for finding in verify_records(records).findings]


def _logged(records: list[dict]) -> list[LoggedRecord]:
    return [LoggedRecord(r, record_digest(r)) for r in records]


@pytest.mark.usefixtures("matching_windows")
def test_an_intact_chain_verifies_and_duplicates_count_once() -> None:
    records = _chain(3)
    result = verify_records(_logged([*records, records[1]]))
    assert result.ok and result.windows == 3
    assert result.covered_until == (T0 + 3 * HOUR).isoformat(timespec="microseconds")


@pytest.mark.usefixtures("matching_windows")
def test_chain_problems_are_findings() -> None:
    records = _chain(4)
    assert _kinds(_logged([records[0], records[1], records[3]])) == ["gap", "chain_broken"]
    assert _kinds(_logged(records[1:])) == ["chain_start_missing"]
    restarted = build_record(_window({_TENANT: ScopeDigest(2, f"{2:064x}")}, T0 + 2 * HOUR), None)
    assert _kinds(_logged([records[0], records[1], restarted])) == ["chain_restarted"]
    other = build_record(_window({}, T0 + HOUR), record_digest(records[0]))
    assert "conflicting_records" in _kinds(_logged([records[0], records[1], other]))
    altered = [LoggedRecord(records[0], "f" * 64), *_logged(records[1:])]
    assert _kinds(altered)[0] == "record_altered"
    assert _kinds([LoggedRecord({**records[0], "format": "v0"}, None)])[0] == "unknown_format"
    empty = verify_records([])
    assert not empty.ok and [f.kind for f in empty.findings] == ["no_records"]


@pytest.mark.usefixtures("matching_windows")
def test_a_window_that_no_longer_matches_names_its_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    records = _chain(1)

    def changed(starts: list[datetime], width: timedelta) -> list[WindowDigest]:
        return [_window({_TENANT: ScopeDigest(1, "9" * 64)}, s) for s in starts]

    monkeypatch.setattr(digest_service, "compute_windows", changed)
    (finding,) = verify_records(_logged(records)).findings
    assert finding.kind == "audit_log_changed" and _TENANT in finding.detail


def test_the_verify_command_exit_codes(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from saas_os.ops import audit_digest as cli

    monkeypatch.setattr(cli, "validate_application_role", lambda engine: None)
    monkeypatch.setattr(cli, "get_engine", lambda: None)
    records = _chain(1)
    export = tmp_path / "export.jsonl"
    export.write_text(canonical_json(records[0]) + "\n", encoding="utf-8")

    monkeypatch.setattr(cli, "verify_records", lambda found: Verification(windows=1))
    assert cli.main(["verify", str(export)]) == 0
    assert '"ok": true' in capsys.readouterr().out

    def mismatch(found: object) -> Verification:
        return Verification(windows=1, findings=[Finding("audit_log_changed", "w", "tenant t")])

    monkeypatch.setattr(cli, "verify_records", mismatch)
    assert cli.main(["verify", str(export)]) == 1

    empty = tmp_path / "empty.jsonl"
    empty.write_text('{"message": "other"}\n', encoding="utf-8")
    assert cli.main(["verify", str(empty)]) == 2
    assert cli.main(["verify", str(tmp_path / "missing.jsonl")]) == 2
