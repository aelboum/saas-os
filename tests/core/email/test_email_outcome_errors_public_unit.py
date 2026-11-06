"""The two outcome classes are part of the public email surface (issue #223).

A product that keeps to `saas_os.core.email` must be able to tell an unknown
outcome (never retry automatically unless `retry_within` says so) from an
explicit "not sent" (safe to retry) and from an ordinary provider failure.
"""

from __future__ import annotations

from datetime import timedelta

import saas_os.core.email as email
from saas_os.core.email import (
    EmailNotSentError,
    EmailOutcomeUnknownError,
    EmailProviderError,
)


def test_both_outcome_classes_are_exported_and_listed_in_all() -> None:
    assert "EmailOutcomeUnknownError" in email.__all__
    assert "EmailNotSentError" in email.__all__


def test_both_are_provider_errors_but_not_each_other() -> None:
    assert issubclass(EmailOutcomeUnknownError, EmailProviderError)
    assert issubclass(EmailNotSentError, EmailProviderError)
    assert not issubclass(EmailOutcomeUnknownError, EmailNotSentError)
    assert not issubclass(EmailNotSentError, EmailOutcomeUnknownError)


def test_unknown_outcome_exposes_phase_and_retry_within() -> None:
    never = EmailOutcomeUnknownError("send", "connection lost", phase="data")
    assert never.phase == "data"
    assert never.retry_within is None
    assert never.permanent is False

    deduplicated = EmailOutcomeUnknownError(
        "send", "response not read", phase="response", retry_within=timedelta(hours=24)
    )
    assert deduplicated.retry_within == timedelta(hours=24)


def test_a_caller_can_catch_the_specific_classes_before_the_base_class() -> None:
    def classify(exc: EmailProviderError) -> str:
        try:
            raise exc
        except EmailOutcomeUnknownError:
            return "unknown"
        except EmailNotSentError:
            return "not-sent"
        except EmailProviderError:
            return "other"

    assert classify(EmailOutcomeUnknownError("send", "x", phase="read")) == "unknown"
    assert classify(EmailNotSentError("send", "x")) == "not-sent"
    assert classify(EmailProviderError("send", "x")) == "other"
