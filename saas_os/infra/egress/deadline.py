"""A total deadline shared by every step of one operation.

A `Deadline` is computed once, when an operation starts. Every step --
DNS resolution, each connection attempt, the request, the response, and any
retry or fallback a caller adds -- receives only the *remaining* time. A retry
never gets a fresh deadline (ADR-0054 section 8a).
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Deadline:
    expires_at: float  # time.monotonic() value

    @classmethod
    def after(cls, seconds: float) -> Deadline:
        if not seconds > 0:
            raise ValueError("a deadline must be positive")
        return cls(time.monotonic() + seconds)

    def remaining(self) -> float:
        return max(0.0, self.expires_at - time.monotonic())

    @property
    def expired(self) -> bool:
        return self.remaining() <= 0.0
