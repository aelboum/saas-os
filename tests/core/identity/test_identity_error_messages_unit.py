"""Identity errors whose input identifies a person keep it out of their
message (2026-10-28 audit of errors that put caller input in their
message). An unhandled error is written, with its message, to the API
middleware's `unhandled_request_error` line and the request span. No
database: the chained database errors are covered by
`test_identity_integration.py` and `test_invitation_integration.py`.
"""

from __future__ import annotations

import uuid

import pytest

from saas_os.core.identity.errors import (
    DuplicateExternalIdentityError,
    DuplicateInvitationError,
    InvalidInvitationEmailError,
)
from saas_os.core.identity.service import _normalize_email  # pyright: ignore[reportPrivateUsage]
from unhandled_error_sinks import unhandled_error_sinks

_ISSUER = "https://issuer-canary-0928.example.test"
_SUBJECT = "subject-canary-0928"
_EMAIL = "invitee-canary-0928@example.test"
_REJECTED = "rejected-canary-0928-no-at-sign"
_CANARIES = ("issuer-canary-0928", _SUBJECT, "invitee-canary-0928", "rejected-canary-0928")


def _assert_no_canary(*texts: str) -> None:
    for text in texts:
        for canary in _CANARIES:
            assert canary not in text, (canary, text)


def test_the_messages_name_no_identity_or_address() -> None:
    tenant_id = uuid.uuid4()
    duplicate_identity = DuplicateExternalIdentityError(_ISSUER, _SUBJECT)
    duplicate_invitation = DuplicateInvitationError(tenant_id, _EMAIL)

    assert str(duplicate_identity) == "External identity is already linked."
    assert str(duplicate_invitation) == (
        f"A pending invitation for this email already exists in tenant {tenant_id}."
    )
    _assert_no_canary(
        str(duplicate_identity),
        repr(duplicate_identity),
        str(duplicate_invitation),
        repr(duplicate_invitation),
    )
    # The values stay available to a caller that handles the error, and the
    # types are unchanged.
    assert (duplicate_identity.issuer, duplicate_identity.subject) == (_ISSUER, _SUBJECT)
    assert duplicate_invitation.invited_email == _EMAIL
    assert isinstance(duplicate_identity, ValueError)
    assert isinstance(duplicate_invitation, ValueError)


@pytest.mark.parametrize("value", [_REJECTED, f"@{_REJECTED}", f"  {_REJECTED}  "])
def test_a_rejected_address_is_not_repeated(value: str) -> None:
    with pytest.raises(InvalidInvitationEmailError) as excinfo:
        _normalize_email(value)
    assert str(excinfo.value) == "Invalid invitation email: not a valid email address."
    assert excinfo.value.reason == "not a valid email address"
    _assert_no_canary(str(excinfo.value), repr(excinfo.value))


def test_a_valid_address_is_still_normalized() -> None:
    assert _normalize_email("  Invitee-Canary-0928@Example.TEST ") == _EMAIL


def test_an_unhandled_rejection_reaches_no_sink_with_the_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sinks = unhandled_error_sinks(monkeypatch, lambda: _normalize_email(_REJECTED))
    assert sinks.status_code == 500 and sinks.body == "Internal Server Error"
    assert len(sinks.log_exceptions) == 1 and len(sinks.span_events) == 1
    assert "InvalidInvitationEmailError" in sinks.log_exceptions[0]
    _assert_no_canary(*sinks.texts())
