"""`saas_os/infra/secrets` -- the `SecretsProvider` abstraction (docs/IMPLEMENTATION-
ROADMAP.md Phase 2.3; docs/ADR/0012-secrets-management.md; docs/SECURITY.md
section 4).

The reusable, provider-agnostic secrets access boundary: application code
depends on `SecretsProvider` (and this factory) only, never on where a
secret's value actually comes from.

    application code
        -> SecretsProvider (this module's public surface)
            -> current approved provider (EnvFileSecretsProvider in
               development, EnvironmentSecretsProvider in Docker/host
               production -- saas_os/infra/secrets/providers.py, selected by
               saas_os/infra/secrets/config.py)
                -> runtime-injected secret

This is the only public import surface for this module -- concrete
provider classes live in `saas_os/infra/secrets/providers.py` and are not meant
to be imported directly by any other module, including other `infra`
subpackages (`saas_os/infra/db`, `saas_os/infra/observability`). Enforced by pyproject.toml's
"Only saas_os/infra/secrets may import its own concrete provider implementations"
import-linter contract, proven non-vacuous in
`tests/architecture/test_layer_boundaries.py`.

`saas_os/infra/secrets` does not import `core`, `products`, or `control_plane`,
and does not import any AI/LLM framework -- same boundary rules as every
other `infra` subpackage (docs/ARCHITECTURE.md section 2).

Usage:

    from saas_os.infra.secrets import get_secrets_provider

    provider = get_secrets_provider()
    api_key = provider.get_required("SOME_API_KEY")
    optional = provider.get("SOME_OPTIONAL_VALUE")  # None if unset
"""

from saas_os.infra.secrets.config import get_secrets_provider
from saas_os.infra.secrets.provider import (
    SecretNotFoundError,
    SecretsConfigurationError,
    SecretsProvider,
)

__all__ = [
    "SecretsProvider",
    "SecretNotFoundError",
    "SecretsConfigurationError",
    "get_secrets_provider",
]
