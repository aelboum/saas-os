"""Which secrets an AI provider may use (ADR-0054 section 6).

A provider row stores a secret *name* (`credential_ref`). The secrets
provider (`saas_os.infra.secrets`) resolves every secret of the
installation from one place: in production the whole process environment,
in development the environment and the `.env` file. It therefore holds the
database URLs, the Redis URL, payment, e-mail, backup and signing secrets
alongside any AI provider key, and a name that merely resolves says nothing
about what the secret is for.

The deployment therefore provisions AI provider credentials explicitly:
`AI_PROVIDER_CREDENTIALS` lists, comma-separated, the secret names an AI
provider may reference. Only a listed name is eligible. The list is set by
whoever controls the deployment's environment, the same party that
provisions the secrets themselves (ADR-0045 tier 0). A platform operator
holding `platform.ai_provider:manage` can choose among the listed names and
nothing else, so managing AI providers grants no access to the
installation's other secrets.

The list is an explicit enumeration, not a naming convention: no prefix or
pattern makes a name eligible. It is checked when a provider's
`credential_ref` is set or a binding is confirmed, and again every time a
credential is resolved for a call, so a name removed from the list stops
being usable without any change to the provider row. Everything that is not
the one valid case fails closed: an unset or empty list provisions nothing,
and a malformed entry invalidates the whole list.

Plain environment configuration, read the way the other AI tunables are
(`egress_config.py`, `accounting.py`). The list holds names, never values.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping

from saas_os.infra.secrets import SecretsProvider, get_secrets_provider

PROVISIONING_VARIABLE = "AI_PROVIDER_CREDENTIALS"

SECRET_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,199}")


class AICredentialProvisioningError(ValueError):
    """`AI_PROVIDER_CREDENTIALS` is malformed. Its message names the
    variable, never a secret value."""

    def __init__(self) -> None:
        super().__init__(f"{PROVISIONING_VARIABLE} is malformed")


def provisioned_credential_names(env: Mapping[str, str] | None = None) -> frozenset[str]:
    """The secret names provisioned for AI provider use. Unset or empty
    provisions nothing. Any entry that is not a secret name raises
    `AICredentialProvisioningError`: a malformed list is never partly
    applied."""
    source = os.environ if env is None else env
    raw = source.get(PROVISIONING_VARIABLE, "")
    if not raw.strip():
        return frozenset()
    names = [entry.strip() for entry in raw.split(",")]
    if any(not SECRET_NAME.fullmatch(name) for name in names):
        raise AICredentialProvisioningError()
    return frozenset(names)


def is_provisioned(name: str, env: Mapping[str, str] | None = None) -> bool:
    """Whether `name` may be referenced by an AI provider. A malformed list
    provisions nothing."""
    try:
        return name in provisioned_credential_names(env)
    except AICredentialProvisioningError:
        return False


def resolve_ai_credential(
    name: str,
    *,
    secrets: Callable[[], SecretsProvider] | None = None,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """The value of the provisioned AI credential `name`, or `None` if the
    name is not provisioned, the list is malformed, or the secret does not
    resolve. The secrets provider is never asked for a name that is not
    provisioned."""
    if not isinstance(name, str) or not SECRET_NAME.fullmatch(name):
        return None
    if not is_provisioned(name, env):
        return None
    value = (secrets or get_secrets_provider)().get(name)
    return value or None
