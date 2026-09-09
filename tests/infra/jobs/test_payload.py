"""`TenantJobPayload` schema tests (docs/IMPLEMENTATION-ROADMAP.md Phase
2.4, docs/MULTI-TENANCY.md section 4)."""

from __future__ import annotations

import pytest
from infra.jobs.errors import MissingTenantIdError
from infra.jobs.payload import TenantJobPayload


def test_tenant_job_payload_holds_tenant_id_and_data() -> None:
    payload = TenantJobPayload(tenant_id="t1", data={"call_id": "c1"})
    assert payload.tenant_id == "t1"
    assert payload.data == {"call_id": "c1"}


def test_tenant_job_payload_defaults_data_to_empty_dict() -> None:
    payload = TenantJobPayload(tenant_id="t1")
    assert payload.data == {}


def test_missing_tenant_id_is_rejected_at_construction() -> None:
    """Schema-level check: an empty tenant_id is rejected by the dataclass
    itself, before the payload can ever reach enqueue_job().
    """
    with pytest.raises(MissingTenantIdError):
        TenantJobPayload(tenant_id="")


def test_none_tenant_id_is_rejected_at_construction() -> None:
    with pytest.raises(MissingTenantIdError):
        TenantJobPayload(tenant_id=None)  # type: ignore[arg-type]
