"""Helpers shared by the protocol adapters. Internal.

Errors raised here are never chained to the exception they replace (an egress
error, a `JSONDecodeError` that keeps the whole response body as `doc`): each
is built inside the handler and raised after it, so it has no `__cause__` and
no `__context__`."""

from __future__ import annotations

import json
from collections.abc import Mapping

from saas_os.control_plane.inference.adapters.base import (
    AdapterRequest,
    Capability,
    EgressClient,
    ResolvedTarget,
)
from saas_os.control_plane.inference.adapters.errors import (
    AdapterError,
    ErrorCategory,
    error_from_egress,
)
from saas_os.infra.egress import Deadline, EgressError, EgressResponse

_MAX_RETRY_AFTER_SECONDS = 3600.0
_MAX_REQUEST_ID_LENGTH = 255


def require_capabilities(
    request: AdapterRequest,
    target: ResolvedTarget,
    protocol_capabilities: frozenset[Capability],
) -> None:
    """Refuse, before anything is sent, a request that needs a capability the
    protocol or the target model does not declare. A parameter is never sent
    in the hope that the provider accepts it."""
    available = protocol_capabilities & target.capabilities
    needed = {Capability.TEXT_INPUT, Capability.TEXT_OUTPUT}
    if request.system is not None:
        needed.add(Capability.SYSTEM_INSTRUCTIONS)
    if request.temperature is not None:
        needed.add(Capability.TEMPERATURE)
    if request.stop:
        needed.add(Capability.STOP_SEQUENCES)
    if not needed <= available:
        raise AdapterError(ErrorCategory.UNSUPPORTED_CAPABILITY, possibly_accepted=False)
    if request.max_output_tokens <= 0 or not request.messages:
        raise AdapterError(ErrorCategory.INVALID_REQUEST, possibly_accepted=False)


def join_url(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + "/" + path.lstrip("/")


async def send_json(
    egress: EgressClient,
    url: str,
    *,
    headers: Mapping[str, str],
    payload: Mapping[str, object],
    deadline: Deadline,
) -> EgressResponse:
    content = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    all_headers = {"Content-Type": "application/json", "Accept": "application/json", **headers}
    try:
        return await egress.post(url, headers=all_headers, content=content, deadline=deadline)
    except EgressError as exc:
        failure = error_from_egress(exc)
    raise failure


def request_id(response: EgressResponse, header: str) -> str | None:
    value = response.headers.get(header)
    if value is None or len(value) > _MAX_REQUEST_ID_LENGTH:
        return None
    return value


def retry_after(response: EgressResponse) -> float | None:
    raw = response.headers.get("retry-after")
    if raw is None:
        return None
    try:
        seconds = float(raw.strip())
    except ValueError:
        return None  # HTTP-date form is not interpreted
    if not 0 <= seconds <= _MAX_RETRY_AFTER_SECONDS:
        return None
    return seconds


def error_for_status(
    response: EgressResponse,
    *,
    request_id_header: str,
    not_processed_statuses: frozenset[int],
) -> AdapterError:
    """Map a non-2xx provider answer to a normalized error. The provider's
    error body is never read into the error."""
    status = response.status_code
    rid = request_id(response, request_id_header)
    if status in (401, 403):
        return AdapterError(
            ErrorCategory.PROVIDER_AUTH,
            possibly_accepted=False,
            status_code=status,
            provider_request_id=rid,
        )
    if status == 429:
        return AdapterError(
            ErrorCategory.RATE_LIMITED,
            possibly_accepted=False,
            status_code=status,
            provider_request_id=rid,
            retry_after_seconds=retry_after(response),
        )
    if status in not_processed_statuses:
        return AdapterError(
            ErrorCategory.PROVIDER_OVERLOADED,
            possibly_accepted=False,
            status_code=status,
            provider_request_id=rid,
            retry_after_seconds=retry_after(response),
        )
    if 400 <= status < 500:
        return AdapterError(
            ErrorCategory.INVALID_REQUEST,
            possibly_accepted=False,
            status_code=status,
            provider_request_id=rid,
        )
    # 5xx (or anything else unexpected) that is not declared "not processed":
    # the provider may have accepted the request.
    return AdapterError(
        ErrorCategory.PROVIDER_ERROR,
        possibly_accepted=True,
        status_code=status,
        provider_request_id=rid,
    )


def parse_json_object(response: EgressResponse, *, request_id_header: str) -> dict[str, object]:
    try:
        decoded = json.loads(response.body)
    except (ValueError, UnicodeDecodeError):
        decoded = None  # refused below, outside the handler
    if not isinstance(decoded, dict):
        raise malformed(response, request_id_header)
    return decoded


def malformed(response: EgressResponse, request_id_header: str) -> AdapterError:
    # A 2xx answer the adapter cannot interpret: the provider processed the
    # request, so it may have been billed.
    return AdapterError(
        ErrorCategory.MALFORMED_RESPONSE,
        possibly_accepted=True,
        status_code=response.status_code,
        provider_request_id=request_id(response, request_id_header),
    )


def optional_count(container: object, key: str) -> int | None:
    if not isinstance(container, dict):
        return None
    value = container.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value
