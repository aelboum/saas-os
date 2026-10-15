"""Opt-in router: inbound billing-provider events
(docs/ADR/0048-inbound-billing-provider-events.md; closes ADR-0040 gap G4).

    app.include_router(saas_os.api.v1.build_stripe_billing_events_router())

Not mounted by `build_platform_app()`. One route, for the Stripe adapter:

    POST /v1/billing/providers/stripe/events

Register that URL as a webhook endpoint in the Stripe account of the
platform tenant's merchant, and configure its signing secret as
`STRIPE_WEBHOOK_SECRET` (read through the secrets provider when the
router is built, so a missing secret fails at startup). Needs the
`saas-os[stripe]` extra (ADR-0041); building the router without it raises
`ModuleNotFoundError` with the remedy.

The route has no credential: it is a `public_route`, authenticated by the
provider's signature over the raw body. In order, before anything is
recorded:

1. a rate limit per source address (`billing-events:stripe:<address>`,
   the deployment's rate-limit settings; the address is the direct peer,
   or the trusted proxy's last `X-Forwarded-For` hop when
   `TRUST_PROXY_HEADERS` is set, as for login), failing closed with `503`.
   Per source, so that unsigned requests from elsewhere cannot use up the
   allowance of the provider's own deliveries;
2. a body cap of `MAX_EVENT_BODY_BYTES`, `413` above it;
3. signature verification over the raw bytes, Stripe's timestamp
   tolerance included. Every failure is the same `400`
   (`invalid_signature`), and nothing is recorded: an id in an unverified
   body is not trusted.

A verified event is then processed by
`saas_os.core.billing.process_provider_event()`, which deduplicates it,
resolves its subscription through SaaS OS's own reference index and
reconciles it from the provider's current state (ADR-0048). `200` for an
event processed, ignored or already done; `503` with `Retry-After` when
processing failed, so the provider redelivers. The response body is only
the ledger status. No cookie is read, so the same-origin check (ADR-0044)
has nothing to guard here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from starlette.concurrency import run_in_threadpool

from saas_os.api.auth.config import resolve_client_address, trust_proxy_headers_from_env
from saas_os.api.errors import invalid_request, rate_limited, service_unavailable
from saas_os.api.route_policy import public_route
from saas_os.core.billing import (
    BillingProvider,
    InvalidBillingPartyError,
    InvalidWebhookSignatureError,
    ProviderEventNotice,
    ProviderEventProcessingError,
    process_provider_event,
)
from saas_os.infra.ratelimit import (
    RateLimitBackendError,
    RateLimitExceededError,
    enforce_rate_limit,
    get_ratelimit_config,
)
from saas_os.infra.secrets import get_secrets_provider

STRIPE_EVENTS_PATH = "/v1/billing/providers/stripe/events"
STRIPE_WEBHOOK_SECRET_NAME = "STRIPE_WEBHOOK_SECRET"  # pragma: allowlist secret -- a name
MAX_EVENT_BODY_BYTES = 1024 * 1024

_RATE_LIMIT_KEY = "billing-events:stripe"
# Small fixed hints, never derived from the failure itself.
_BACKEND_FAILURE_RETRY_AFTER_SECONDS = 5
_PROCESSING_FAILURE_RETRY_AFTER_SECONDS = 60
_INVALID_SIGNATURE = "invalid_signature"
_POLICY_REASON = (
    "billing provider events: authenticated by the provider's signature over the raw "
    "body, not by a credential (ADR-0048)"
)


def _too_large() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Request body too large."
    )


async def _enforce_limit(request: Request) -> None:
    source = resolve_client_address(request, trust_proxy_headers=trust_proxy_headers_from_env())
    try:
        await enforce_rate_limit(f"{_RATE_LIMIT_KEY}:{source}", config=get_ratelimit_config())
    except RateLimitExceededError as exc:
        raise rate_limited(exc.retry_after_seconds) from None
    except RateLimitBackendError:
        raise service_unavailable(_BACKEND_FAILURE_RETRY_AFTER_SECONDS) from None


async def _read_capped(request: Request) -> bytes:
    """The raw body, refused above `MAX_EVENT_BODY_BYTES` -- by its declared
    length when it has one, and while reading in any case."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_EVENT_BODY_BYTES:
                raise _too_large()
        except ValueError:
            raise invalid_request("invalid_content_length") from None
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_EVENT_BODY_BYTES:
            raise _too_large()
    return bytes(body)


def _stripe_event_parser() -> Callable[[bytes, str, str], ProviderEventNotice]:
    try:
        from saas_os.core.billing.stripe_provider import parse_stripe_event
    except ModuleNotFoundError as exc:
        if exc.name != "stripe":
            raise
        # ADR-0041: fail at build time with the remedy.
        raise ModuleNotFoundError(
            "The Stripe billing events router needs the optional 'stripe' dependency: "
            'install "saas-os[stripe]".',
            name="stripe",
        ) from exc
    return parse_stripe_event


def build_stripe_billing_events_router(
    *, provider: BillingProvider | None = None, webhook_secret: str | None = None
) -> APIRouter:
    """The Stripe events router (module docstring). `provider` is the
    adapter reconciliation reads subscription state through (`None`:
    Core's default Stripe adapter, `STRIPE_API_KEY`). `webhook_secret`
    defaults to `STRIPE_WEBHOOK_SECRET` from the secrets provider; both are
    fixed when the router is built."""
    parse = _stripe_event_parser()
    secret = (
        webhook_secret
        if webhook_secret is not None
        else get_secrets_provider().get_required(STRIPE_WEBHOOK_SECRET_NAME)
    )
    if not isinstance(secret, str) or not secret.strip():
        raise ValueError("The Stripe webhook signing secret must be a non-empty string.")

    router = APIRouter(tags=["billing"])

    @router.post(
        STRIPE_EVENTS_PATH,
        dependencies=[Depends(public_route(_POLICY_REASON))],
        status_code=status.HTTP_200_OK,
    )
    async def receive_stripe_event(request: Request) -> dict[str, Any]:
        await _enforce_limit(request)
        body = await _read_capped(request)
        signature = request.headers.get("stripe-signature")
        if not signature:
            raise invalid_request(_INVALID_SIGNATURE)
        try:
            notice = parse(body, signature, secret)
        except InvalidWebhookSignatureError:
            raise invalid_request(_INVALID_SIGNATURE) from None
        try:
            result = await run_in_threadpool(process_provider_event, notice, provider=provider)
        except InvalidBillingPartyError:
            # A verified event Core cannot record (an id beyond the
            # ledger's bounds): refused before anything was written.
            raise invalid_request("invalid_event") from None
        except ProviderEventProcessingError:
            raise service_unavailable(_PROCESSING_FAILURE_RETRY_AFTER_SECONDS) from None
        return {"status": result.status.value}

    return router
