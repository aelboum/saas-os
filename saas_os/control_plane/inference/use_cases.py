"""The in-process registry of application-defined use cases (approved owner
decision Q5; ADR-0055 section 4).

A use case is immutable and declared by the application at start-up. It
states a *ceiling*: the highest classification its content may carry, the
content it accepts and its size bounds. **Registration authorizes nothing**:
a request is allowed only when, in addition, the tenant has granted the use
case (and the classification) and a destination, and installation policy
allows that destination for the classification (ADR-0055 section 4, the
independent checks). The registry is per process; the criteria for moving
to a persisted registry are recorded in ADR-0055 section 4.

Registering the same definition twice is a no-op; registering a different
definition under an existing name is refused.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

from saas_os.control_plane.inference.capabilities import Capability
from saas_os.control_plane.inference.errors import UseCaseRegistrationError
from saas_os.control_plane.inference.types import CLASSIFICATIONS

USE_CASE_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}")
_MAX_PARTS = 1024
_MAX_INPUT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class UseCase:
    name: str
    max_classification: str
    part_kinds: frozenset[str] = field(default_factory=lambda: frozenset({"text"}))
    max_parts: int = 64
    max_input_bytes: int = 200_000
    required_capabilities: frozenset[Capability] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not USE_CASE_NAME.fullmatch(self.name):
            raise UseCaseRegistrationError("invalid use case name")
        if self.max_classification not in CLASSIFICATIONS:
            raise UseCaseRegistrationError("invalid max_classification")
        if not self.part_kinds or not self.part_kinds <= {"text", "image"}:
            raise UseCaseRegistrationError("invalid part_kinds")
        if isinstance(self.max_parts, bool) or not 0 < self.max_parts <= _MAX_PARTS:
            raise UseCaseRegistrationError("invalid max_parts")
        if (
            isinstance(self.max_input_bytes, bool)
            or not 0 < self.max_input_bytes <= _MAX_INPUT_BYTES
        ):
            raise UseCaseRegistrationError("invalid max_input_bytes")
        if not all(isinstance(c, Capability) for c in self.required_capabilities):
            raise UseCaseRegistrationError("invalid required_capabilities")


_lock = threading.Lock()
_registry: dict[str, UseCase] = {}


def register_use_case(use_case: UseCase) -> UseCase:
    if not isinstance(use_case, UseCase):
        raise UseCaseRegistrationError("not a UseCase")
    with _lock:
        existing = _registry.get(use_case.name)
        if existing is not None and existing != use_case:
            raise UseCaseRegistrationError(f"use case {use_case.name!r} is already registered")
        _registry[use_case.name] = use_case
    return use_case


def registered_use_case(name: str) -> UseCase | None:
    with _lock:
        return _registry.get(name)


def registered_use_cases() -> tuple[UseCase, ...]:
    with _lock:
        return tuple(sorted(_registry.values(), key=lambda u: u.name))


def _clear_registry_for_tests() -> None:
    with _lock:
        _registry.clear()
