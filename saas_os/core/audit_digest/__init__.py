"""Audit digests: tamper evidence for `core.audit_log` and
`core.platform_audit_log`, anchored in the deployment's external log store
(docs/ADR/0053-audit-digests-in-external-logs.md).

The worker's schedule lives in `saas_os.core.audit_digest.jobs`, imported
by the worker only: registering a job resolves `REDIS_URL`."""

from saas_os.core.audit_digest.config import (
    AuditDigestConfig,
    AuditDigestConfigurationError,
    get_audit_digest_config,
)
from saas_os.core.audit_digest.models import AuditDigest
from saas_os.core.audit_digest.service import (
    AUDIT_LOG_COLUMNS,
    LOG_DIGEST_FIELD,
    LOG_EVENT,
    LOG_RECORD_FIELD,
    PLATFORM_AUDIT_LOG_COLUMNS,
    RECORD_FORMAT,
    DigestRun,
    Finding,
    LoggedRecord,
    ScopeDigest,
    Verification,
    WindowDigest,
    build_record,
    canonical_json,
    canonical_row,
    compute_windows,
    digest_settled_windows,
    floor_to_window,
    record_digest,
    records_from_log_lines,
    settled_until,
    verify_records,
)

__all__ = [
    "AUDIT_LOG_COLUMNS",
    "LOG_DIGEST_FIELD",
    "LOG_EVENT",
    "LOG_RECORD_FIELD",
    "PLATFORM_AUDIT_LOG_COLUMNS",
    "RECORD_FORMAT",
    "AuditDigest",
    "AuditDigestConfig",
    "AuditDigestConfigurationError",
    "DigestRun",
    "Finding",
    "LoggedRecord",
    "ScopeDigest",
    "Verification",
    "WindowDigest",
    "build_record",
    "canonical_json",
    "canonical_row",
    "compute_windows",
    "digest_settled_windows",
    "floor_to_window",
    "get_audit_digest_config",
    "record_digest",
    "records_from_log_lines",
    "settled_until",
    "verify_records",
]
