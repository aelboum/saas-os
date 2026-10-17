"""`saas-os-operator ai-*` -- the AI inference configuration commands
(ADR-0054 D4, Phase AI-C).

The AI configuration has no HTTP route. Each command is one call to the
configuration operations (`saas_os.control_plane.inference.config.service`)
with `UserCaller(<operator>)`; Core decides: the operation's platform
permission (`platform.ai_provider:manage`, `platform.ai_endpoint_trust:manage`,
`platform.ai_policy:manage`, or `platform.ai_config:read` for `ai-show`), the
change and its platform audit row in one transaction, and a `denied` row on
refusal.

    saas-os-operator ai-show --operator <user id>
    saas-os-operator ai-provider-create --key openai --protocol openai_chat_completions \\
        --base-url https://api.openai.com/v1 --credential-ref OPENAI_API_KEY \\
        --operator <user id> --reason "TICKET-3: enable OpenAI"
    saas-os-operator ai-model-create --provider openai --model gpt-4o-mini \\
        --capability text_input --capability text_output --max-output-tokens 4096 ...
    saas-os-operator ai-alias-set --alias default-chat --candidate openai:gpt-4o-mini ...
    saas-os-operator ai-destination-policy --provider openai --classification tenant_data \\
        --allowed yes ...
    saas-os-operator ai-trust-create --host llm.internal.example --port 443 \\
        --network 10.20.0.0/16 --expires-at 2027-01-01T00:00:00+00:00 ...

`--credential-ref` names a secret (resolved through `SecretsProvider`); a
credential value is never accepted on the command line. Changing a provider's
endpoint to another origin clears its credential binding until
`ai-provider-confirm-binding` is run. Tenant AI policy is not set here: it is
the tenant's own decision (`ai.policy:manage`).

Never imports a provider adapter (import-linter).
"""

from __future__ import annotations

import argparse
import uuid
from collections.abc import Callable
from datetime import datetime

from saas_os.control_plane.inference.config import service as ai_config
from saas_os.core.authority import UserCaller

_YES_NO = {"yes": True, "no": False}
_MAX_REASON = 500


class AICommandInputError(ValueError):
    """An argument is missing, malformed or inconsistent (exit code 2)."""


def _uuid(raw: str, *, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except (ValueError, AttributeError, TypeError):
        raise AICommandInputError(f"{field} must be a UUID.") from None


def _operator(args: argparse.Namespace) -> UserCaller:
    return UserCaller(_uuid(args.operator, field="--operator"))


def _reason(args: argparse.Namespace) -> str:
    reason = args.reason.strip() if isinstance(args.reason, str) else ""
    if not reason:
        raise AICommandInputError("--reason is required and must not be empty.")
    if len(reason) > _MAX_REASON:
        raise AICommandInputError(f"--reason exceeds {_MAX_REASON} characters.")
    return reason


def _aware(raw: str | None, *, field: str) -> datetime | None:
    if raw is None:
        return None
    try:
        value = datetime.fromisoformat(raw)
    except ValueError:
        raise AICommandInputError(f"{field} must be an ISO-8601 timestamp.") from None
    if value.tzinfo is None:
        raise AICommandInputError(f"{field} must include a UTC offset.")
    return value


def show(args: argparse.Namespace) -> object:
    return ai_config.read_ai_configuration(caller=_operator(args))


def provider_create(args: argparse.Namespace) -> object:
    return ai_config.create_provider(
        key=args.key,
        protocol=args.protocol,
        base_url=args.base_url,
        credential_ref=args.credential_ref,
        caller=_operator(args),
        reason=_reason(args),
    )


def provider_endpoint(args: argparse.Namespace) -> object:
    return ai_config.update_provider_endpoint(
        key=args.key, base_url=args.base_url, caller=_operator(args), reason=_reason(args)
    )


def provider_confirm_binding(args: argparse.Namespace) -> object:
    return ai_config.confirm_provider_binding(
        key=args.key, caller=_operator(args), reason=_reason(args)
    )


def provider_credential(args: argparse.Namespace) -> object:
    return ai_config.set_provider_credential_ref(
        key=args.key,
        credential_ref=args.credential_ref,
        caller=_operator(args),
        reason=_reason(args),
    )


def provider_status(args: argparse.Namespace) -> object:
    return ai_config.set_provider_status(
        key=args.key, status=args.status, caller=_operator(args), reason=_reason(args)
    )


def provider_data_handling(args: argparse.Namespace) -> object:
    return ai_config.set_provider_data_handling(
        key=args.key,
        residency=args.residency or (),
        retention_days=args.retention_days,
        training_use=_YES_NO[args.training_use],
        caller=_operator(args),
        reason=_reason(args),
    )


def model_create(args: argparse.Namespace) -> object:
    return ai_config.create_model(
        provider_key=args.provider,
        model_id=args.model,
        capabilities=args.capability or (),
        max_output_tokens=args.max_output_tokens,
        context_window_tokens=args.context_window_tokens,
        caller=_operator(args),
        reason=_reason(args),
    )


def model_lifecycle(args: argparse.Namespace) -> object:
    return ai_config.set_model_lifecycle(
        provider_key=args.provider,
        model_id=args.model,
        lifecycle=args.lifecycle,
        retire_after=_aware(args.retire_after, field="--retire-after"),
        caller=_operator(args),
        reason=_reason(args),
    )


def alias_set(args: argparse.Namespace) -> object:
    candidates: list[tuple[str, str]] = []
    for raw in args.candidate or ():
        provider, sep, model = raw.partition(":")
        if not sep or not provider or not model:
            raise AICommandInputError("--candidate must be 'provider:model'.")
        candidates.append((provider, model))
    return ai_config.set_alias(
        alias=args.alias,
        candidates=candidates,
        status=args.status,
        caller=_operator(args),
        reason=_reason(args),
    )


def trust_create(args: argparse.Namespace) -> object:
    expires_at = _aware(args.expires_at, field="--expires-at")
    if expires_at is None:
        raise AICommandInputError("--expires-at is required.")
    return ai_config.create_trust_entry(
        host=args.host,
        port=args.port,
        networks=args.network or (),
        expires_at=expires_at,
        caller=_operator(args),
        reason=_reason(args),
    )


def trust_revoke(args: argparse.Namespace) -> object:
    return ai_config.revoke_trust_entry(
        entry_id=_uuid(args.entry, field="--entry"), caller=_operator(args), reason=_reason(args)
    )


def destination_policy(args: argparse.Namespace) -> object:
    return ai_config.set_destination_policy(
        provider_key=args.provider,
        classification=args.classification,
        allowed=_YES_NO[args.allowed],
        caller=_operator(args),
        reason=_reason(args),
    )


AI_COMMANDS: dict[str, Callable[[argparse.Namespace], object]] = {
    "ai-show": show,
    "ai-provider-create": provider_create,
    "ai-provider-endpoint": provider_endpoint,
    "ai-provider-confirm-binding": provider_confirm_binding,
    "ai-provider-credential": provider_credential,
    "ai-provider-status": provider_status,
    "ai-provider-data-handling": provider_data_handling,
    "ai-model-create": model_create,
    "ai-model-lifecycle": model_lifecycle,
    "ai-alias-set": alias_set,
    "ai-trust-create": trust_create,
    "ai-trust-revoke": trust_revoke,
    "ai-destination-policy": destination_policy,
}


def add_ai_parsers(
    add_parser: Callable[..., argparse.ArgumentParser],
    common: Callable[[argparse.ArgumentParser], None],
) -> None:
    """Add the `ai-*` subcommands through the subparsers' `add_parser`."""

    def command(name: str, help_text: str, *, reason: bool = True) -> argparse.ArgumentParser:
        # No abbreviations: `--credential` must never be read as `--credential-ref`.
        p = add_parser(name, help=help_text, allow_abbrev=False)
        p.add_argument("--operator", required=True, help="the platform operator's user id")
        if reason:
            p.add_argument("--reason", required=True)
        common(p)
        return p

    command("ai-show", "show the AI configuration (no credential values)", reason=False)

    p = command("ai-provider-create", "configure an AI provider")
    p.add_argument("--key", required=True)
    p.add_argument("--protocol", required=True)
    p.add_argument("--base-url", required=True)
    p.add_argument("--credential-ref", required=True, help="the name of a secret, not its value")

    p = command("ai-provider-endpoint", "change a provider's base URL")
    p.add_argument("--key", required=True)
    p.add_argument("--base-url", required=True)

    p = command("ai-provider-confirm-binding", "bind the credential to the current endpoint")
    p.add_argument("--key", required=True)

    p = command("ai-provider-credential", "point a provider at another secret name")
    p.add_argument("--key", required=True)
    p.add_argument("--credential-ref", required=True)

    p = command("ai-provider-status", "enable or disable a provider")
    p.add_argument("--key", required=True)
    p.add_argument("--status", required=True, choices=("active", "disabled"))

    p = command("ai-provider-data-handling", "record the provider's data-handling declarations")
    p.add_argument("--key", required=True)
    p.add_argument("--residency", action="append")
    p.add_argument("--retention-days", type=int)
    p.add_argument("--training-use", required=True, choices=tuple(_YES_NO))

    p = command("ai-model-create", "add a model to a provider")
    p.add_argument("--provider", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--capability", action="append")
    p.add_argument("--max-output-tokens", required=True, type=int)
    p.add_argument("--context-window-tokens", type=int)

    p = command("ai-model-lifecycle", "deprecate, disable or reactivate a model")
    p.add_argument("--provider", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--lifecycle", required=True, choices=("active", "deprecated", "disabled"))
    p.add_argument("--retire-after")

    p = command("ai-alias-set", "create or replace an alias")
    p.add_argument("--alias", required=True)
    p.add_argument("--candidate", action="append", help="provider:model, in fallback order")
    p.add_argument("--status", default="active", choices=("active", "disabled"))

    p = command("ai-trust-create", "trust one private endpoint (exact host and port)")
    p.add_argument("--host", required=True)
    p.add_argument("--port", required=True, type=int)
    p.add_argument("--network", action="append", help="a private CIDR the host may resolve into")
    p.add_argument("--expires-at", required=True)

    p = command("ai-trust-revoke", "revoke a private-endpoint trust entry")
    p.add_argument("--entry", required=True)

    p = command("ai-destination-policy", "allow or refuse a provider for a classification")
    p.add_argument("--provider", required=True)
    p.add_argument("--classification", required=True, choices=("none", "tenant_data", "sensitive"))
    p.add_argument("--allowed", required=True, choices=tuple(_YES_NO))
