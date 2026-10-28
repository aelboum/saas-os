"""Ledger row 900: the redaction matches only the message these errors had
before pull request #110, never a current one."""

from __future__ import annotations

import pytest

from saas_os.core.outbox.dispatch import describe_error
from saas_os.core.webhooks.errors import (
    InvalidWebhookUrlError,
    WebhookDestinationRejectedError,
    WebhookDestinationUnresolvedError,
)
from saas_os.core.webhooks.stored_errors import LEGACY_REPLACEMENTS, REDACTED_MESSAGE

_URL = "https://u:pw-canary-0900@hooks.example.test/?t=tok-canary-0900"  # pragma: allowlist secret
_TYPES = (
    WebhookDestinationRejectedError,
    WebhookDestinationUnresolvedError,
    InvalidWebhookUrlError,
)


def _match(stored: str) -> str | None:
    return next((r for p, r in LEGACY_REPLACEMENTS.items() if stored.startswith(p)), None)


@pytest.mark.parametrize("error_type", _TYPES)
def test_the_pre_110_text_is_matched_and_keeps_its_type(error_type: type[Exception]) -> None:
    stored = f"{error_type.__name__}: Invalid webhook URL: {_URL!r} (must be http:// or https://)."
    assert _match(stored) == f"{error_type.__name__}: {REDACTED_MESSAGE}"
    assert "canary" not in REDACTED_MESSAGE


@pytest.mark.parametrize("error_type", _TYPES)
def test_a_current_message_is_never_matched(error_type: type[Exception]) -> None:
    assert _match(describe_error(error_type(_URL))) is None
    assert _match(f"{error_type.__name__}: {REDACTED_MESSAGE}") is None
