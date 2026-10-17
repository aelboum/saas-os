"""Platform administration of the AI inference configuration (ADR-0054 AI-C).

Every mutation is a platform operation (ADR-0045): the caller must hold the
operation's platform permission, the change and its platform audit row commit
in one transaction (`run_platform_change`), and a refusal is recorded as a
`denied` row. Reads use the oversight path (`run_oversight_read`). Rows are
never deleted; providers, models and aliases are disabled, trust entries are
revoked.

Credentials: a provider stores a secret *name* (`credential_ref`), never a
value. The name must be one the deployment provisioned for AI provider use
(`AI_PROVIDER_CREDENTIALS`, `..inference.credentials`) and must resolve
through `SecretsProvider` when it is set or its binding is confirmed (the
value is checked for presence and discarded). The credential is bound to one
origin (`scheme://host:port`); changing the provider's endpoint origin or its
credential name clears the binding, and the provider is unusable until a
second operation confirms the binding (ADR-0054 section 6).
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from urllib.parse import urlsplit

from saas_os.control_plane.inference.capabilities import Capability
from saas_os.control_plane.inference.config.errors import (
    AIConfigurationError,
    AIConfigurationNotFoundError,
)
from saas_os.control_plane.inference.config.models import (
    AIAlias,
    AIDestinationPolicy,
    AIEndpointTrust,
    AIModel,
    AIModelPrice,
    AIProvider,
    Classification,
    ModelLifecycle,
    Protocol,
    ProviderStatus,
)
from saas_os.control_plane.inference.credentials import (
    SECRET_NAME,
    AICredentialProvisioningError,
    provisioned_credential_names,
)
from saas_os.core.platform_authority import (
    OversightOutcome,
    PlatformChange,
    run_oversight_read,
    run_platform_change,
)
from saas_os.core.platform_authority.operations import (
    AI_CONFIG_READ,
    AI_ENDPOINT_TRUST_CONFIGURE,
    AI_POLICY_CONFIGURE,
    AI_PROVIDER_CONFIGURE,
)
from saas_os.infra.db import Session, select
from saas_os.infra.egress import NEVER_TRUSTABLE_NETWORKS, is_non_public_address
from saas_os.infra.secrets import get_secrets_provider

_KEY = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_ALIAS = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}")
_SECRET_NAME = SECRET_NAME
_HOST = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")
_MAX_CANDIDATES = 8
_MAX_TRUST_DAYS = 366

_NEVER_TRUSTED = NEVER_TRUSTABLE_NETWORKS

_TARGET_PROVIDER = "ai_provider"
_TARGET_MODEL = "ai_model"
_TARGET_ALIAS = "ai_alias"
_TARGET_TRUST = "ai_endpoint_trust"
_TARGET_POLICY = "ai_destination_policy"
_TARGET_CONFIG = "ai_configuration"


# --- views (never contain a credential value) ----------------------------------


@dataclass(frozen=True)
class ProviderView:
    id: uuid.UUID
    key: str
    protocol: str
    base_url: str
    credential_ref: str
    credential_bound: bool
    status: str
    data_handling: dict
    version: int


@dataclass(frozen=True)
class ModelView:
    id: uuid.UUID
    provider_key: str
    model_id: str
    capabilities: tuple[str, ...]
    max_output_tokens: int
    context_window_tokens: int | None
    lifecycle: str
    retire_after: datetime | None
    version: int


@dataclass(frozen=True)
class AliasView:
    alias: str
    candidates: tuple[uuid.UUID, ...]
    status: str
    version: int


@dataclass(frozen=True)
class TrustEntryView:
    id: uuid.UUID
    host: str
    port: int
    networks: tuple[str, ...]
    expires_at: datetime
    revoked: bool


@dataclass(frozen=True)
class DestinationPolicyView:
    provider_key: str
    classification: str
    allowed: bool


@dataclass(frozen=True)
class ModelPriceView:
    provider_key: str
    model_id: str
    pricing_version: str
    currency: str
    input_per_million: Decimal
    output_per_million: Decimal
    cached_input_per_million: Decimal | None
    effective_from: datetime


@dataclass(frozen=True)
class AIConfigurationView:
    providers: tuple[ProviderView, ...]
    models: tuple[ModelView, ...]
    aliases: tuple[AliasView, ...]
    trust_entries: tuple[TrustEntryView, ...]
    destination_policy: tuple[DestinationPolicyView, ...]
    prices: tuple[ModelPriceView, ...] = ()


def _provider_view(row: AIProvider) -> ProviderView:
    return ProviderView(
        id=row.id,
        key=row.key,
        protocol=row.protocol,
        base_url=row.base_url,
        credential_ref=row.credential_ref,
        credential_bound=row.credential_origin is not None
        and row.credential_origin == endpoint_origin(row.base_url),
        status=row.status,
        data_handling=dict(row.data_handling),
        version=row.version,
    )


# --- validation ------------------------------------------------------------------


def endpoint_origin(base_url: str) -> str:
    """`https://host:port` of a validated base URL."""
    parts = urlsplit(base_url)
    port = parts.port if parts.port is not None else 443
    return f"{parts.scheme}://{parts.hostname}:{port}"


def _validate_key(key: str) -> None:
    if not isinstance(key, str) or not _KEY.fullmatch(key):
        raise AIConfigurationError("invalid_provider_key")


def _validate_base_url(base_url: str) -> None:
    if not isinstance(base_url, str) or not base_url.isascii() or len(base_url) > 2048:
        raise AIConfigurationError("invalid_base_url")
    try:
        parts = urlsplit(base_url)
        port = parts.port
    except ValueError as exc:
        raise AIConfigurationError("invalid_base_url") from exc
    if parts.scheme != "https":
        raise AIConfigurationError("base_url_must_be_https")
    if parts.username is not None or "@" in parts.netloc:
        raise AIConfigurationError("base_url_userinfo_not_allowed")
    if parts.query or parts.fragment:
        raise AIConfigurationError("base_url_query_not_allowed")
    host = parts.hostname
    if not host:
        raise AIConfigurationError("invalid_base_url")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and is_non_public_address(literal):
        raise AIConfigurationError("base_url_non_public_literal")
    if literal is None and not _HOST.fullmatch(host):
        raise AIConfigurationError("invalid_base_url")
    if port is not None and not 0 < port < 65536:
        raise AIConfigurationError("invalid_base_url")


def _validate_credential_ref(credential_ref: str) -> None:
    if not isinstance(credential_ref, str) or not _SECRET_NAME.fullmatch(credential_ref):
        raise AIConfigurationError("invalid_credential_ref")
    # Only a name the deployment provisioned for AI use is eligible
    # (`..inference.credentials`); a name that merely resolves is not.
    try:
        provisioned = provisioned_credential_names()
    except AICredentialProvisioningError as exc:
        raise AIConfigurationError("credential_provisioning_invalid") from exc
    if credential_ref not in provisioned:
        raise AIConfigurationError("credential_ref_not_provisioned")
    # Presence only: the value is never returned, logged or audited.
    if not get_secrets_provider().get(credential_ref):
        raise AIConfigurationError("credential_ref_unresolved")


def _validate_capabilities(capabilities: Sequence[str]) -> list[str]:
    known = {c.value for c in Capability}
    values = sorted(set(capabilities))
    if not values or any(value not in known for value in values):
        raise AIConfigurationError("invalid_capabilities")
    return values


def _provider(session: Session, key: str) -> AIProvider:
    row = session.execute(
        select(AIProvider).where(AIProvider.key == key).with_for_update()
    ).scalar_one_or_none()
    if row is None:
        raise AIConfigurationNotFoundError("provider")
    return row


def _model(session: Session, provider: AIProvider, model_id: str) -> AIModel:
    row = session.execute(
        select(AIModel)
        .where(AIModel.provider_id == provider.id, AIModel.model_id == model_id)
        .with_for_update()
    ).scalar_one_or_none()
    if row is None:
        raise AIConfigurationNotFoundError("model")
    return row


# --- providers ---------------------------------------------------------------------


def create_provider(
    *,
    key: str,
    protocol: str,
    base_url: str,
    credential_ref: str,
    caller: object,
    reason: str,
) -> ProviderView:
    """Create a provider, active and bound to its own endpoint's origin."""
    _validate_key(key)
    if protocol not in {p.value for p in Protocol}:
        raise AIConfigurationError("invalid_protocol")
    _validate_base_url(base_url)
    _validate_credential_ref(credential_ref)

    def change(session: Session) -> PlatformChange:
        exists = session.execute(select(AIProvider.id).where(AIProvider.key == key)).first()
        if exists is not None:
            raise AIConfigurationError("provider_exists")
        row = AIProvider(
            key=key,
            protocol=protocol,
            base_url=base_url,
            credential_ref=credential_ref,
            credential_origin=endpoint_origin(base_url),
            status=ProviderStatus.ACTIVE.value,
            data_handling={},
            version=1,
        )
        session.add(row)
        session.flush()
        return PlatformChange(
            _provider_view(row),
            target_id=str(row.id),
            metadata={
                "change": "create_provider",
                "key": key,
                "protocol": protocol,
                "credential_ref": credential_ref,
            },
        )

    return run_platform_change(
        caller=caller,
        operation=AI_PROVIDER_CONFIGURE,
        target_type=_TARGET_PROVIDER,
        change=change,
        reason=reason,
    )


def update_provider_endpoint(
    *, key: str, base_url: str, caller: object, reason: str
) -> ProviderView:
    """Change a provider's base URL. If the origin changes, the credential
    binding is cleared: the provider cannot be used until
    `confirm_provider_binding` binds the credential to the new origin."""
    _validate_key(key)
    _validate_base_url(base_url)

    def change(session: Session) -> PlatformChange:
        row = _provider(session, key)
        origin_changed = endpoint_origin(row.base_url) != endpoint_origin(base_url)
        row.base_url = base_url
        if origin_changed:
            row.credential_origin = None
        row.version += 1
        session.flush()
        return PlatformChange(
            _provider_view(row),
            target_id=str(row.id),
            metadata={
                "change": "update_provider_endpoint",
                "key": key,
                "binding_cleared": origin_changed,
            },
        )

    return run_platform_change(
        caller=caller,
        operation=AI_PROVIDER_CONFIGURE,
        target_type=_TARGET_PROVIDER,
        change=change,
        reason=reason,
    )


def confirm_provider_binding(*, key: str, caller: object, reason: str) -> ProviderView:
    """Bind the provider's credential to its current endpoint origin. The
    credential name is checked again: a name no longer provisioned for AI
    use, or no longer resolving, cannot be bound."""
    _validate_key(key)

    def change(session: Session) -> PlatformChange:
        row = _provider(session, key)
        _validate_credential_ref(row.credential_ref)
        row.credential_origin = endpoint_origin(row.base_url)
        row.version += 1
        session.flush()
        return PlatformChange(
            _provider_view(row),
            target_id=str(row.id),
            metadata={
                "change": "confirm_provider_binding",
                "key": key,
                "credential_ref": row.credential_ref,
                "origin": row.credential_origin,
            },
        )

    return run_platform_change(
        caller=caller,
        operation=AI_PROVIDER_CONFIGURE,
        target_type=_TARGET_PROVIDER,
        change=change,
        reason=reason,
    )


def set_provider_credential_ref(
    *, key: str, credential_ref: str, caller: object, reason: str
) -> ProviderView:
    """Point the provider at another provisioned secret name. A different
    name clears the binding, exactly like an origin change: the provider
    cannot be used until `confirm_provider_binding` binds the new credential
    to its origin in a second audited operation."""
    _validate_key(key)
    _validate_credential_ref(credential_ref)

    def change(session: Session) -> PlatformChange:
        row = _provider(session, key)
        previous = row.credential_ref
        name_changed = previous != credential_ref
        row.credential_ref = credential_ref
        if name_changed:
            row.credential_origin = None
        row.version += 1
        session.flush()
        return PlatformChange(
            _provider_view(row),
            target_id=str(row.id),
            metadata={
                "change": "set_provider_credential_ref",
                "key": key,
                "previous_credential_ref": previous,
                "credential_ref": credential_ref,
                "binding_cleared": name_changed,
            },
        )

    return run_platform_change(
        caller=caller,
        operation=AI_PROVIDER_CONFIGURE,
        target_type=_TARGET_PROVIDER,
        change=change,
        reason=reason,
    )


def set_provider_status(*, key: str, status: str, caller: object, reason: str) -> ProviderView:
    _validate_key(key)
    if status not in {s.value for s in ProviderStatus}:
        raise AIConfigurationError("invalid_status")

    def change(session: Session) -> PlatformChange:
        row = _provider(session, key)
        row.status = status
        row.version += 1
        session.flush()
        return PlatformChange(
            _provider_view(row),
            target_id=str(row.id),
            metadata={"change": "set_provider_status", "key": key, "status": status},
        )

    return run_platform_change(
        caller=caller,
        operation=AI_PROVIDER_CONFIGURE,
        target_type=_TARGET_PROVIDER,
        change=change,
        reason=reason,
    )


def set_provider_data_handling(
    *,
    key: str,
    residency: Sequence[str],
    retention_days: int | None,
    training_use: bool,
    caller: object,
    reason: str,
) -> ProviderView:
    """Record the operator's *declarations* about the provider's data handling
    (residency tags, retention in days, whether data may be used for
    training). They are declarations, not verified facts (ADR-0055)."""
    _validate_key(key)
    tags = sorted(set(residency))
    if any(not isinstance(tag, str) or not _KEY.fullmatch(tag) for tag in tags):
        raise AIConfigurationError("invalid_residency")
    if retention_days is not None and (
        isinstance(retention_days, bool) or not 0 <= retention_days <= 3650
    ):
        raise AIConfigurationError("invalid_retention_days")
    declared = {
        "residency": tags,
        "retention_days": retention_days,
        "training_use": bool(training_use),
    }

    def change(session: Session) -> PlatformChange:
        row = _provider(session, key)
        row.data_handling = declared
        row.version += 1
        session.flush()
        return PlatformChange(
            _provider_view(row),
            target_id=str(row.id),
            metadata={"change": "set_provider_data_handling", "key": key, **declared},
        )

    return run_platform_change(
        caller=caller,
        operation=AI_PROVIDER_CONFIGURE,
        target_type=_TARGET_PROVIDER,
        change=change,
        reason=reason,
    )


# --- models and aliases ------------------------------------------------------------


def _model_view(row: AIModel, provider_key: str) -> ModelView:
    return ModelView(
        id=row.id,
        provider_key=provider_key,
        model_id=row.model_id,
        capabilities=tuple(row.capabilities),
        max_output_tokens=row.max_output_tokens,
        context_window_tokens=row.context_window_tokens,
        lifecycle=row.lifecycle,
        retire_after=row.retire_after,
        version=row.version,
    )


def create_model(
    *,
    provider_key: str,
    model_id: str,
    capabilities: Sequence[str],
    max_output_tokens: int,
    context_window_tokens: int | None = None,
    caller: object,
    reason: str,
) -> ModelView:
    _validate_key(provider_key)
    if not isinstance(model_id, str) or not 0 < len(model_id) <= 200 or not model_id.isascii():
        raise AIConfigurationError("invalid_model_id")
    values = _validate_capabilities(capabilities)
    if isinstance(max_output_tokens, bool) or not 0 < max_output_tokens <= 1_000_000:
        raise AIConfigurationError("invalid_max_output_tokens")
    if context_window_tokens is not None and not 0 < context_window_tokens <= 10_000_000:
        raise AIConfigurationError("invalid_context_window_tokens")

    def change(session: Session) -> PlatformChange:
        provider = _provider(session, provider_key)
        exists = session.execute(
            select(AIModel.id).where(
                AIModel.provider_id == provider.id, AIModel.model_id == model_id
            )
        ).first()
        if exists is not None:
            raise AIConfigurationError("model_exists")
        row = AIModel(
            provider_id=provider.id,
            model_id=model_id,
            capabilities=values,
            max_output_tokens=max_output_tokens,
            context_window_tokens=context_window_tokens,
            lifecycle=ModelLifecycle.ACTIVE.value,
            version=1,
        )
        session.add(row)
        session.flush()
        return PlatformChange(
            _model_view(row, provider.key),
            target_id=str(row.id),
            metadata={"change": "create_model", "provider": provider_key, "model": model_id},
        )

    return run_platform_change(
        caller=caller,
        operation=AI_PROVIDER_CONFIGURE,
        target_type=_TARGET_MODEL,
        change=change,
        reason=reason,
    )


def set_model_lifecycle(
    *,
    provider_key: str,
    model_id: str,
    lifecycle: str,
    retire_after: datetime | None = None,
    caller: object,
    reason: str,
) -> ModelView:
    _validate_key(provider_key)
    if lifecycle not in {m.value for m in ModelLifecycle}:
        raise AIConfigurationError("invalid_lifecycle")
    if retire_after is not None and retire_after.tzinfo is None:
        raise AIConfigurationError("retire_after_must_be_aware")

    def change(session: Session) -> PlatformChange:
        provider = _provider(session, provider_key)
        row = _model(session, provider, model_id)
        row.lifecycle = lifecycle
        row.retire_after = retire_after
        row.version += 1
        session.flush()
        return PlatformChange(
            _model_view(row, provider.key),
            target_id=str(row.id),
            metadata={
                "change": "set_model_lifecycle",
                "provider": provider_key,
                "model": model_id,
                "lifecycle": lifecycle,
            },
        )

    return run_platform_change(
        caller=caller,
        operation=AI_PROVIDER_CONFIGURE,
        target_type=_TARGET_MODEL,
        change=change,
        reason=reason,
    )


def set_alias(
    *,
    alias: str,
    candidates: Sequence[tuple[str, str]],
    status: str = ProviderStatus.ACTIVE.value,
    caller: object,
    reason: str,
) -> AliasView:
    """Create or replace an alias: an ordered list of (provider key, model id)
    candidates, each tried at most once in order (ADR-0054 section 8)."""
    if not isinstance(alias, str) or not _ALIAS.fullmatch(alias):
        raise AIConfigurationError("invalid_alias")
    if status not in {s.value for s in ProviderStatus}:
        raise AIConfigurationError("invalid_status")
    pairs = list(candidates)
    if not 0 < len(pairs) <= _MAX_CANDIDATES or len(set(pairs)) != len(pairs):
        raise AIConfigurationError("invalid_alias_candidates")

    def change(session: Session) -> PlatformChange:
        ids: list[str] = []
        for provider_key, model_id in pairs:
            provider = _provider(session, provider_key)
            ids.append(str(_model(session, provider, model_id).id))
        row = session.execute(
            select(AIAlias).where(AIAlias.alias == alias).with_for_update()
        ).scalar_one_or_none()
        if row is None:
            row = AIAlias(alias=alias, candidates=ids, status=status, version=1)
            session.add(row)
        else:
            row.candidates = ids
            row.status = status
            row.version += 1
        session.flush()
        view = AliasView(
            alias=row.alias,
            candidates=tuple(uuid.UUID(i) for i in row.candidates),
            status=row.status,
            version=row.version,
        )
        return PlatformChange(
            view,
            target_id=str(row.id),
            metadata={"change": "set_alias", "alias": alias, "candidates": len(ids)},
        )

    return run_platform_change(
        caller=caller,
        operation=AI_PROVIDER_CONFIGURE,
        target_type=_TARGET_ALIAS,
        change=change,
        reason=reason,
    )


# --- endpoint trust ----------------------------------------------------------------


def _validate_trust_networks(networks: Sequence[str]) -> list[str]:
    parsed: list[str] = []
    if not 0 < len(networks) <= 16:
        raise AIConfigurationError("invalid_networks")
    for raw in networks:
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as exc:
            raise AIConfigurationError("invalid_networks") from exc
        same_family = [b for b in _NEVER_TRUSTED if b.version == network.version]
        if any(network.overlaps(blocked) for blocked in same_family):  # type: ignore[arg-type]
            raise AIConfigurationError("network_never_trusted")
        if not is_non_public_address(network.network_address):
            # Public destinations need no trust entry; trust is for private ones only.
            raise AIConfigurationError("network_is_public")
        parsed.append(str(network))
    return parsed


def create_trust_entry(
    *,
    host: str,
    port: int,
    networks: Sequence[str],
    expires_at: datetime,
    caller: object,
    reason: str,
) -> TrustEntryView:
    """Trust one exact host and port to resolve into the given private
    networks (ADR-0054 D9; threat model 3.10). Loopback, link-local,
    metadata, multicast and unspecified ranges can never be trusted."""
    if not isinstance(host, str) or not host.isascii() or not _HOST.fullmatch(host.lower()):
        raise AIConfigurationError("invalid_host")
    if isinstance(port, bool) or not 0 < port < 65536:
        raise AIConfigurationError("invalid_port")
    parsed = _validate_trust_networks(networks)
    if expires_at.tzinfo is None:
        raise AIConfigurationError("expires_at_must_be_aware")
    now = datetime.now(UTC)
    if not now < expires_at or (expires_at - now).days > _MAX_TRUST_DAYS:
        raise AIConfigurationError("invalid_expiry")

    def change(session: Session) -> PlatformChange:
        live = session.execute(
            select(AIEndpointTrust.id).where(
                AIEndpointTrust.host == host.lower(),
                AIEndpointTrust.port == port,
                AIEndpointTrust.revoked_at.is_(None),
            )
        ).first()
        if live is not None:
            raise AIConfigurationError("trust_entry_exists")
        row = AIEndpointTrust(
            host=host.lower(), port=port, networks=parsed, reason=reason, expires_at=expires_at
        )
        session.add(row)
        session.flush()
        view = TrustEntryView(row.id, row.host, row.port, tuple(parsed), expires_at, False)
        return PlatformChange(
            view,
            target_id=str(row.id),
            metadata={"change": "create_trust_entry", "host": row.host, "port": port},
        )

    return run_platform_change(
        caller=caller,
        operation=AI_ENDPOINT_TRUST_CONFIGURE,
        target_type=_TARGET_TRUST,
        change=change,
        reason=reason,
    )


def revoke_trust_entry(*, entry_id: uuid.UUID, caller: object, reason: str) -> TrustEntryView:
    def change(session: Session) -> PlatformChange:
        row = session.execute(
            select(AIEndpointTrust).where(AIEndpointTrust.id == entry_id).with_for_update()
        ).scalar_one_or_none()
        if row is None:
            raise AIConfigurationNotFoundError("trust_entry")
        if row.revoked_at is None:
            row.revoked_at = datetime.now(UTC)
        session.flush()
        view = TrustEntryView(row.id, row.host, row.port, tuple(row.networks), row.expires_at, True)
        return PlatformChange(
            view, target_id=str(row.id), metadata={"change": "revoke_trust_entry"}
        )

    return run_platform_change(
        caller=caller,
        operation=AI_ENDPOINT_TRUST_CONFIGURE,
        target_type=_TARGET_TRUST,
        change=change,
        reason=reason,
    )


# --- destination policy ------------------------------------------------------------


def set_destination_policy(
    *,
    provider_key: str,
    classification: str,
    allowed: bool,
    caller: object,
    reason: str,
) -> DestinationPolicyView:
    """Make a provider eligible (or not) for one data classification,
    installation-wide. Absent means not eligible (deny by default)."""
    _validate_key(provider_key)
    if classification not in {c.value for c in Classification}:
        raise AIConfigurationError("invalid_classification")

    def change(session: Session) -> PlatformChange:
        provider = _provider(session, provider_key)
        row = session.execute(
            select(AIDestinationPolicy)
            .where(
                AIDestinationPolicy.provider_id == provider.id,
                AIDestinationPolicy.classification == classification,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if row is None:
            row = AIDestinationPolicy(
                provider_id=provider.id,
                classification=classification,
                allowed=bool(allowed),
                reason=reason,
            )
            session.add(row)
        else:
            row.allowed = bool(allowed)
            row.reason = reason
        session.flush()
        return PlatformChange(
            DestinationPolicyView(provider.key, classification, bool(allowed)),
            target_id=str(row.id),
            metadata={
                "change": "set_destination_policy",
                "provider": provider_key,
                "classification": classification,
                "allowed": bool(allowed),
            },
        )

    return run_platform_change(
        caller=caller,
        operation=AI_POLICY_CONFIGURE,
        target_type=_TARGET_POLICY,
        change=change,
        reason=reason,
    )


# --- prices (AI-F) ----------------------------------------------------------------

_PRICING_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_CURRENCY = re.compile(r"[A-Z]{3}")
_MAX_RATE = Decimal("1000000")


def _rate(value: Decimal | None, *, optional: bool = False) -> Decimal | None:
    if value is None and optional:
        return None
    if not isinstance(value, Decimal) or not value.is_finite() or not 0 <= value <= _MAX_RATE:
        raise AIConfigurationError("invalid_rate")
    if value.as_tuple().exponent < -8:  # type: ignore[operator]
        raise AIConfigurationError("invalid_rate")
    return value


def set_model_price(
    *,
    provider_key: str,
    model_id: str,
    pricing_version: str,
    currency: str,
    input_per_million: Decimal,
    output_per_million: Decimal,
    cached_input_per_million: Decimal | None = None,
    effective_from: datetime,
    caller: object,
    reason: str,
) -> ModelPriceView:
    """Add an immutable price version of a model (rates per million tokens,
    `Decimal` only). An existing version is never rewritten: a price change
    is a new version. Authority: `platform.ai_provider:manage`."""
    _validate_key(provider_key)
    if not isinstance(pricing_version, str) or not _PRICING_VERSION.fullmatch(pricing_version):
        raise AIConfigurationError("invalid_pricing_version")
    if not isinstance(currency, str) or not _CURRENCY.fullmatch(currency):
        raise AIConfigurationError("invalid_currency")
    rates = (
        _rate(input_per_million),
        _rate(output_per_million),
        _rate(cached_input_per_million, optional=True),
    )
    if not isinstance(effective_from, datetime) or effective_from.tzinfo is None:
        raise AIConfigurationError("effective_from_must_be_aware")

    def change(session: Session) -> PlatformChange:
        provider = _provider(session, provider_key)
        model = _model(session, provider, model_id)
        exists = session.execute(
            select(AIModelPrice.id).where(
                AIModelPrice.model_ref == model.id,
                AIModelPrice.pricing_version == pricing_version,
            )
        ).first()
        if exists is not None:
            raise AIConfigurationError("pricing_version_exists")
        row = AIModelPrice(
            model_ref=model.id,
            pricing_version=pricing_version,
            currency=currency,
            input_per_million=rates[0],
            output_per_million=rates[1],
            cached_input_per_million=rates[2],
            effective_from=effective_from,
        )
        session.add(row)
        session.flush()
        view = ModelPriceView(
            provider.key,
            model.model_id,
            pricing_version,
            currency,
            rates[0],  # type: ignore[arg-type]
            rates[1],  # type: ignore[arg-type]
            rates[2],
            effective_from,
        )
        return PlatformChange(
            view,
            target_id=str(row.id),
            metadata={
                "change": "set_model_price",
                "provider": provider.key,
                "model": model.model_id,
                "pricing_version": pricing_version,
                "currency": currency,
            },
        )

    return run_platform_change(
        caller=caller,
        operation=AI_PROVIDER_CONFIGURE,
        target_type=_TARGET_MODEL,
        change=change,
        reason=reason,
    )


# --- oversight read -----------------------------------------------------------------


def _read_configuration(session: Session) -> AIConfigurationView:
    providers = session.execute(select(AIProvider).order_by(AIProvider.key)).scalars().all()
    keys = {row.id: row.key for row in providers}
    models = session.execute(select(AIModel).order_by(AIModel.model_id)).scalars().all()
    aliases = session.execute(select(AIAlias).order_by(AIAlias.alias)).scalars().all()
    trust = session.execute(select(AIEndpointTrust).order_by(AIEndpointTrust.host)).scalars().all()
    policy = session.execute(select(AIDestinationPolicy)).scalars().all()
    model_keys = {row.id: (keys[row.provider_id], row.model_id) for row in models}
    prices = (
        session.execute(select(AIModelPrice).order_by(AIModelPrice.effective_from, AIModelPrice.id))
        .scalars()
        .all()
    )
    return AIConfigurationView(
        providers=tuple(_provider_view(row) for row in providers),
        models=tuple(_model_view(row, keys[row.provider_id]) for row in models),
        aliases=tuple(
            AliasView(
                row.alias, tuple(uuid.UUID(i) for i in row.candidates), row.status, row.version
            )
            for row in aliases
        ),
        trust_entries=tuple(
            TrustEntryView(
                row.id,
                row.host,
                row.port,
                tuple(row.networks),
                row.expires_at,
                row.revoked_at is not None,
            )
            for row in trust
        ),
        destination_policy=tuple(
            DestinationPolicyView(keys[row.provider_id], row.classification, row.allowed)
            for row in policy
        ),
        prices=tuple(
            ModelPriceView(
                *model_keys[row.model_ref],
                row.pricing_version,
                row.currency,
                row.input_per_million,
                row.output_per_million,
                row.cached_input_per_million,
                row.effective_from,
            )
            for row in prices
        ),
    )


def read_ai_configuration(*, caller: object) -> AIConfigurationView:
    """The whole AI configuration, without any credential value. Authority:
    `platform.ai_config:read`; audited as an oversight read (attempt and
    completion rows)."""

    def read(session: Session) -> OversightOutcome:
        view = _read_configuration(session)
        returned = len(view.providers) + len(view.models) + len(view.aliases)
        return OversightOutcome(value=view, returned=returned)

    return run_oversight_read(
        caller=caller, operation=AI_CONFIG_READ, target_type=_TARGET_CONFIG, read=read
    )
