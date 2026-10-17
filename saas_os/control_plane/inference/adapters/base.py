"""Internal adapter contract (contracts document section 2; AI-B).

Everything here is internal to `saas_os.control_plane.inference`. These are
not the consumer request and result types of the contracts document sections
3-7: those depend on the undecided public interface (ADR-0054 Q11) and do not
exist yet.

An adapter translates an already-authorized `AdapterRequest` into one provider
wire request, sends it through an `EgressClient` (the strict egress client in
production), and translates the answer. An adapter never retries, never
follows a redirect, never logs, never reads configuration, policy, tenant or
secrets storage, and never returns a credential.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import ClassVar, Literal, Protocol

from saas_os.control_plane.inference.capabilities import Capability
from saas_os.infra.egress import Deadline, EgressResponse

FinishReason = Literal["stop", "length", "tool_calls", "content_filter", "other"]
Role = Literal["user", "assistant"]


@dataclass(frozen=True)
class AdapterMessage:
    role: Role
    text: str = field(repr=False)


@dataclass(frozen=True)
class AdapterRequest:
    """A normalized, already-authorized request. It carries no tenant id, no
    classification and no policy: those are enforced before an adapter is
    reached (AI-D), and an adapter cannot weaken them."""

    messages: tuple[AdapterMessage, ...] = field(repr=False)
    max_output_tokens: int
    system: str | None = field(default=None, repr=False)
    temperature: float | None = None
    stop: tuple[str, ...] = field(default=(), repr=False)


@dataclass(frozen=True)
class ResolvedTarget:
    """Where to send the request: from configuration in a later phase (AI-C),
    supplied directly by tests in AI-B."""

    base_url: str
    model_id: str
    capabilities: frozenset[Capability]


class OpaqueCredential:
    """A provider credential that never shows itself in `repr`, `str` or
    equality. Only an adapter's header builder calls `reveal()`."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not value:
            raise ValueError("credential must not be empty")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "OpaqueCredential(<redacted>)"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return self is other

    def __hash__(self) -> int:
        return id(self)

    def __reduce__(self) -> object:
        raise TypeError("OpaqueCredential cannot be pickled")


@dataclass(frozen=True)
class AdapterUsage:
    """Usage exactly as the provider reported it; `None` when not reported.
    Never estimated by an adapter."""

    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_input_tokens: int | None = None
    cache_write_tokens: int | None = None


@dataclass(frozen=True)
class AdapterResult:
    text: str = field(repr=False)
    finish_reason: FinishReason
    usage: AdapterUsage
    model: str | None
    provider_request_id: str | None


class EgressClient(Protocol):
    """What an adapter needs from egress. `StrictEgressClient` satisfies it."""

    async def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        content: bytes,
        deadline: Deadline,
    ) -> EgressResponse: ...


class ProviderAdapter(Protocol):
    protocol: ClassVar[str]
    protocol_capabilities: ClassVar[frozenset[Capability]]

    async def complete(
        self,
        request: AdapterRequest,
        *,
        target: ResolvedTarget,
        credential: OpaqueCredential,
        egress: EgressClient,
        deadline: Deadline,
    ) -> AdapterResult: ...
