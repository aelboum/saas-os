"""PRIV-03 Phase P4 -- the lifecycle audit metadata shapes are a contract
with `saas_os.core.audit_log.metadata.validate_metadata()`: every key is fixed,
flat, bounded, and never one the audit log's credential denylist rejects
(a nested `{"authorization": n}` from a per-step count dict would be).
Pure unit tests, no database.
"""

from __future__ import annotations

from saas_os.core.audit_log.metadata import MAX_METADATA_BYTES, validate_metadata
from saas_os.core.tenancy import PURGE_STEPS
from saas_os.core.tenancy.service import _purge_completed_metadata


def test_purge_completed_metadata_is_flat_counts_only_and_passes_the_audit_contract() -> None:
    metadata = _purge_completed_metadata(
        passes=2,
        deleted=dict.fromkeys(PURGE_STEPS, 3),
        retained_service_accounts=1,
        retained_delegation_grants=0,
        participants_run=2,
        dead_letter_entries_purged=4,
    )
    validate_metadata(metadata)  # must not raise
    assert metadata["from_status"] == "purging"
    assert metadata["to_status"] == "purged"
    assert metadata["passes"] == 2
    assert metadata["deleted_total"] == 3 * len(PURGE_STEPS)
    assert metadata["participants_run"] == 2
    assert metadata["dead_letter_entries_purged"] == 4
    # Issue #95: no declaration, no key -- the default shape is unchanged.
    assert "product_participants_skipped" not in metadata
    for step in PURGE_STEPS:
        assert metadata[f"deleted_{step}"] == 3
    # Flat: no nested containers anywhere.
    assert all(not isinstance(value, dict | list) for value in metadata.values())
    assert len(str(metadata).encode()) < MAX_METADATA_BYTES


def test_purge_completed_metadata_tolerates_a_partial_deleted_map() -> None:
    metadata = _purge_completed_metadata(
        passes=1,
        deleted={"api_keys": 1},
        retained_service_accounts=0,
        retained_delegation_grants=0,
        participants_run=0,
        dead_letter_entries_purged=0,
    )
    validate_metadata(metadata)
    assert metadata["deleted_api_keys"] == 1
    assert metadata["deleted_memberships"] == 0
    assert metadata["participants_run"] == 0
    assert metadata["dead_letter_entries_purged"] == 0


def test_a_declared_skip_adds_exactly_one_flat_key() -> None:
    """Issue #95: `product_participants_skipped=True` adds the one key
    `product_participants_skipped: true` and changes nothing else."""
    common: dict[str, object] = {
        "passes": 1,
        "deleted": dict.fromkeys(PURGE_STEPS, 0),
        "retained_service_accounts": 0,
        "retained_delegation_grants": 0,
        "participants_run": 0,
        "dead_letter_entries_purged": 0,
    }
    plain = _purge_completed_metadata(**common)  # type: ignore[arg-type]
    explicit_false = _purge_completed_metadata(**common, product_participants_skipped=False)  # type: ignore[arg-type]
    skipped = _purge_completed_metadata(**common, product_participants_skipped=True)  # type: ignore[arg-type]
    validate_metadata(skipped)
    assert explicit_false == plain
    assert "product_participants_skipped" not in plain
    assert skipped == {**plain, "product_participants_skipped": True}
    assert len(str(skipped).encode()) < MAX_METADATA_BYTES


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
    # RA-12-2: a registered Product purge participant's own failure shape --
    # `failed_step` names the participant, never the Product or its exception's
    # message.
    validate_metadata(
        {
            "failure_class": "participant_error",
            "failed_step": "participant:reference_consumer.widgets",
            "error_type": "RuntimeError",
            "passes_completed": 1,
        }
    )
    # RA-12-7: the Redis dead-letter cleanup step's own failure shape --
    # `error_type` only, never the underlying Redis exception's message.
    validate_metadata(
        {
            "failure_class": "redis_cleanup_error",
            "failed_step": "redis_dead_letters",
            "error_type": "TimeoutError",
            "passes_completed": 1,
        }
    )
