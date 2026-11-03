"""The permission grant ledger retention routes of the opt-in platform-admin
router (owner decisions of 2026-11-03;
`docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md`), without a database.

The dependency chain is the real one with its lookups stubbed (the `chain`
fixture of `test_platform_admin_unit.py`); every Core function a retention
route calls is replaced by a spy. What is shown: a body carrying any field
it does not declare -- an identity field above all -- is a `422`
(`extra_forbidden`) and Core is never called; a valid request reaches Core
with the session's own user as the caller and that session as the evidence;
every retention refusal code maps to exactly one status, and an unknown
code stays a 500.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_platform_admin_unit import _BEARER, _USER, _Chain, chain  # noqa: F401

import saas_os.api.platform_admin.router as router_module
from saas_os.api.platform_admin import build_platform_admin_router
from saas_os.api.platform_admin.router import PREFIX, RETENTION_STATUS, _retention_response
from saas_os.core.authority import UserCaller
from saas_os.core.permission_grants import (
    APPROVAL_NOT_FOUND_CODES,
    APPROVAL_REFUSAL_CODES,
    LedgerApprovalRefusedError,
    PermissionGrantLedgerRetentionError,
)
from saas_os.core.platform_authority import PlatformSessionEvidence

_G = f"{PREFIX}/permission-grant-ledger"
_R = f"{_G}/approver-register"
_ID = uuid.uuid4()
_DIGEST = "a" * 64
_LATER = "2027-06-01T00:00:00+00:00"

# (path, Core function the handler calls, a valid body)
_POSTS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    (f"{_G}/retention-report", "permission_grant_ledger_retention_report", {
        "tenant_ids": [str(_ID)], "reason": "T-1"}),
    (f"{_G}/holds", "place_permission_grant_ledger_hold", {
        "tenant_id": str(_ID), "reference": "LEGAL-1", "reason": "T-1"}),
    (f"{_G}/holds/{_ID}/release", "release_permission_grant_ledger_hold", {"reason": "T-1"}),
    (f"{_G}/deletion-requests", "request_permission_grant_ledger_deletion", {
        "tenant_ids": [str(_ID)], "eligible_ledger_rows": 1, "eligible_digest": _DIGEST,
        "reason": "T-1"}),
    (f"{_G}/deletion-requests/{_ID}/approve", "approve_permission_grant_ledger_deletion", {
        "eligible_ledger_rows": 1, "eligible_digest": _DIGEST, "reason": "T-1"}),
    (f"{_G}/deletion-requests/{_ID}/execution-authorizations",
     "authorize_permission_grant_ledger_deletion_execution", {"reason": "T-1"}),
    (f"{_R}/representatives/{_ID}/proposals", "propose_representative_designation", {
        "designation_ref": "BOARD-1", "ticket_ref": "T-1", "valid_until": _LATER,
        "reason": "T-1"}),
    (f"{_R}/representatives/{_ID}/proposals/{_ID}/confirm",
     "confirm_representative_designation", {"ticket_ref": "T-1", "reason": "T-1"}),
    (f"{_R}/representatives/{_ID}/designations/{_ID}/revoke", "revoke_register_entry", {
        "ticket_ref": "T-1", "reason": "T-1"}),
    (f"{_R}/representatives/{_ID}/designations/{_ID}/security-revoke", "revoke_register_entry",
     {"ticket_ref": "T-1", "reason": "T-1"}),
    (f"{_R}/approvers/{_ID}/enrolments", "enrol_approver", {
        "natural_person_ref": "P-1", "verification_ref": "V-1", "authorisation_ref": "A-1",
        "ticket_ref": "T-1", "valid_until": _LATER, "reason": "T-1"}),
    (f"{_R}/approvers/{_ID}/enrolments/{_ID}/revoke", "revoke_register_entry", {
        "ticket_ref": "T-1", "reason": "T-1"}),
    (f"{_R}/approvers/{_ID}/enrolments/{_ID}/security-revoke", "revoke_register_entry", {
        "ticket_ref": "T-1", "reason": "T-1"}),
)  # fmt: skip

_IDENTITY_FIELDS = ("operator", "user_id", "actor_user_id", "approver", "requested_by")


class _Stop(PermissionGrantLedgerRetentionError):
    """What every spy raises once it has recorded the call: a code the
    router does not map, so the request ends in a 500 and no response model
    is needed."""

    code = "spy_called"


@pytest.fixture
def spies(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, tuple[Any, ...], dict[str, Any]]]:
    seen: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
    for name in {function for _path, function, _body in _POSTS}:

        def spy(*args: Any, _name: str = name, **kwargs: Any) -> Any:
            seen.append((_name, args, kwargs))
            raise _Stop("spy")

        monkeypatch.setattr(router_module, name, spy)
    return seen


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(build_platform_admin_router())
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize(("path", "function", "body"), _POSTS)
@pytest.mark.parametrize("field", _IDENTITY_FIELDS)
def test_identity_fields_in_any_retention_body_are_rejected(
    chain: _Chain,  # noqa: F811
    spies: list[Any],
    path: str,
    function: str,
    body: dict[str, Any],
    field: str,
) -> None:
    response = _client().post(path, headers=_BEARER, json={**body, field: str(uuid.uuid4())})
    assert response.status_code == 422, response.text
    assert any(e["type"] == "extra_forbidden" for e in response.json()["detail"])
    assert spies == []  # Core was never called


@pytest.mark.parametrize(("path", "function", "body"), _POSTS)
def test_a_valid_body_reaches_core_as_the_session_user_with_its_session(
    chain: _Chain,  # noqa: F811
    spies: list[Any],
    path: str,
    function: str,
    body: dict[str, Any],
) -> None:
    response = _client().post(path, headers=_BEARER, json=body)
    assert response.status_code == 500  # the spy's unmapped code
    ((name, _args, kwargs),) = spies
    assert name == function
    assert kwargs["caller"] == UserCaller(_USER)
    if function == "revoke_register_entry":
        expected = {
            "designations/": {
                "/revoke": "permission_grant_ledger.representative_revoke_by_owner",
                "/security-revoke": "permission_grant_ledger.representative_revoke_by_security",
            },
            "enrolments/": {
                "/revoke": "permission_grant_ledger.approver_revoke_by_representative",
                "/security-revoke": "permission_grant_ledger.approver_revoke_by_security",
            },
        }
        kind = "designations/" if "designations/" in path else "enrolments/"
        suffix = "/security-revoke" if path.endswith("/security-revoke") else "/revoke"
        assert kwargs["operation"] == expected[kind][suffix]
    assert not set(_IDENTITY_FIELDS) & set(kwargs)
    if function != "permission_grant_ledger_retention_report":
        evidence = kwargs["session_evidence"]
        assert isinstance(evidence, PlatformSessionEvidence)
        assert chain.session is not None and evidence.session_id == chain.session.id
        assert evidence.multi_factor_required is False  # the test deployment's setting


def test_every_retention_code_maps_to_exactly_one_status_and_unknown_is_a_500() -> None:
    assert set(APPROVAL_REFUSAL_CODES) <= set(RETENTION_STATUS)
    assert set(APPROVAL_NOT_FOUND_CODES) <= set(RETENTION_STATUS)
    assert {RETENTION_STATUS[c] for c in APPROVAL_REFUSAL_CODES} == {409}
    assert {RETENTION_STATUS[c] for c in APPROVAL_NOT_FOUND_CODES} == {404}
    for code in sorted(APPROVAL_REFUSAL_CODES):
        response = _retention_response(LedgerApprovalRefusedError(code))
        assert response is not None and response.status_code == 409
        assert response.detail == code
    assert _retention_response(_Stop("x")) is None
    with pytest.raises(ValueError, match="unknown approval refusal code"):
        LedgerApprovalRefusedError("not_a_code")
