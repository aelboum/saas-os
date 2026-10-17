"""Deterministic fake provider for tests (AI-B).

`FakeAdapter` implements the adapter contract without any network access:
it returns scripted results or raises scripted errors, records what it was
asked (with the credential never stored), and checks capabilities exactly as
the real adapters do. It sends nothing anywhere.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar

from saas_os.control_plane.inference.adapters._common import require_capabilities
from saas_os.control_plane.inference.adapters.base import (
    AdapterRequest,
    AdapterResult,
    AdapterUsage,
    Capability,
    EgressClient,
    OpaqueCredential,
    ResolvedTarget,
)
from saas_os.control_plane.inference.adapters.errors import AdapterError
from saas_os.infra.egress import Deadline, EgressTimeoutError


@dataclass(frozen=True)
class FakeCall:
    request: AdapterRequest
    target: ResolvedTarget


class FakeAdapter:
    protocol: ClassVar[str] = "fake"
    protocol_capabilities: ClassVar[frozenset[Capability]] = frozenset(Capability)

    def __init__(self, script: Sequence[AdapterResult | AdapterError] | None = None) -> None:
        self._script = list(script or [])
        self.calls: list[FakeCall] = []

    async def complete(
        self,
        request: AdapterRequest,
        *,
        target: ResolvedTarget,
        credential: OpaqueCredential,
        egress: EgressClient,
        deadline: Deadline,
    ) -> AdapterResult:
        del credential, egress  # never stored, never used
        require_capabilities(request, target, self.protocol_capabilities)
        if deadline.expired:
            raise EgressTimeoutError(
                "deadline_expired", phase="total", request_may_have_been_sent=False
            )
        self.calls.append(FakeCall(request=request, target=target))
        if self._script:
            item = self._script.pop(0)
            if isinstance(item, AdapterError):
                raise item
            return item
        echoed = request.messages[-1].text
        return AdapterResult(
            text=echoed,
            finish_reason="stop",
            usage=AdapterUsage(input_tokens=len(echoed), output_tokens=len(echoed)),
            model=target.model_id,
            provider_request_id=f"fake-{len(self.calls)}",
        )
