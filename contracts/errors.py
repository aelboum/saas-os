"""Typed errors for `contracts` (docs/IMPLEMENTATION-ROADMAP.md Phase 6.1)."""

from __future__ import annotations


class ContractValidationError(ValueError):
    """Raised by `validate_contract()` when a contract fails schema
    validation. `errors` carries every individual field-level failure
    (not just the first) so a product author sees the complete list of
    problems in one pass, mirroring how a typical form-validation error
    is reported -- never a raw stack trace."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        summary = "; ".join(errors)
        super().__init__(f"Product contract validation failed: {summary}")
