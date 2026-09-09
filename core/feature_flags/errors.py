"""Typed errors for `core/feature_flags` (docs/IMPLEMENTATION-ROADMAP.md
Phase 4.2).
"""

from __future__ import annotations


class InvalidFeatureFlagKeyError(ValueError):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class DuplicateFeatureFlagKeyError(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Feature flag {key!r} already exists.")


class FeatureFlagNotFoundError(LookupError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Feature flag {key!r} not found.")
