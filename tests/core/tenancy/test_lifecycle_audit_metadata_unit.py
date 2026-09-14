"""PRIV-03 Phase P4 -- the lifecycle audit metadata shapes are a contract
with `core.audit_log.metadata.validate_metadata()`: every key is fixed,
flat, bounded, and never one the audit log's credential denylist rejects
(a nested `{"authorization": n}` from a per-step count dict would be).
Pure unit tests, no database.
"""

from __future__ import annotations

from core.audit_log.metadata import MAX_METADATA_BYTES, validate_metadata
from core.tenancy.service import _purge_completed_metadata

from core.tenancy import PURGE_STEPS


def test_purge_completed_metadata_is_flat_counts_only_and_passes_the_audit_contract() -> None:
    metadata = _purge_completed_metadata(
        passes=2,
        deleted=dict.fromkeys(PURGE_STEPS, 3),
        retained_service_accounts=1,
        retained_delegation_grants=0,
    )
    validate_metadata(metadata)  # must not raise
    assert metadata["from_status"] == "purging"
    assert metadata["to_status"] == "purged"
    assert metadata["passes"] == 2
    assert metadata["deleted_total"] == 3 * len(PURGE_STEPS)
    for step in PURGE_STEPS:
        assert metadata[f"deleted_{step}"] == 3
    # Flat: no nested containers anywhere.
    assert all(not isinstance(value, dict | list) for value in metadata.values())
    assert len(str(metadata).encode()) < MAX_METADATA_BYTES


def test_purge_completed_metadata_tolerates_a_partial_deleted_map() -> None:
    metadata = _purge_completed_metadata(
        passes=1, deleted={"api_keys": 1}, retained_service_accounts=0, retained_delegation_grants=0
    )
    validate_metadata(metadata)
    assert metadata["deleted_api_keys"] == 1
    assert metadata["deleted_memberships"] == 0


def test_other_lifecycle_metadata_shapes_pass_the_audit_contract() -> None:
    validate_metadata({"from_status": "active", "to_status": "deleted"})
    validate_metadata({"from_status": "deleted", "to_status": "purging", "resumed": False})
    validate_metadata(
        {
            "failure_class": "step_error",
            "failed_step": "authorization",
            "error_type": "RuntimeError",
            "passes_completed": 0,
        }
    )
