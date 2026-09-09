"""`SecretsProvider` interface (docs/IMPLEMENTATION-ROADMAP.md Phase 2.3,
docs/ADR/0012-secrets-management.md).

The public shape every secret consumer depends on:

    SecretsProvider
    ├── get(name)          -- optional retrieval, returns None if absent
    └── get_required(name) -- fails fast with SecretNotFoundError if absent
                               or empty (never silently returns "")

Concrete implementations live in `infra/secrets/providers.py` and are not
part of the public API -- only this module, `infra/secrets/config.py`
(the selection factory), and `infra/secrets/__init__.py` (the public
re-exports) are meant to be imported by consumers. See
`infra/secrets/__init__.py` for the intended import surface and
pyproject.toml's "Only infra/secrets may import its own concrete provider
implementations" contract for the enforced boundary.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class SecretNotFoundError(LookupError):
    """Raised by `get_required()` when a required secret is absent or empty.

    Carries only the secret's *name* -- never a value (docs/SECURITY.md:
    no secret value may appear in an exception message).
    """

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(
            f"Required secret {name!r} is not set. Configure it via the "
            f"active SecretsProvider (docs/ADR/0012-secrets-management.md)."
        )


class SecretsConfigurationError(ValueError):
    """Raised when `SecretsProvider` selection/configuration is invalid
    (e.g. an unrecognized `ENVIRONMENT`, or a Docker secrets-file mount
    that cannot be read). Never includes a secret value.
    """


class SecretsProvider(ABC):
    """Provider-agnostic secret retrieval. Application/platform code
    depends on this interface only -- never on a concrete implementation
    or on where a secret's value actually comes from.
    """

    @abstractmethod
    def get(self, name: str) -> str | None:
        """Return the named secret's value, or None if it is not set.

        Optional retrieval: an absent secret is not an error here -- the
        caller decides whether that's acceptable.
        """
        raise NotImplementedError

    def get_required(self, name: str) -> str:
        """Return the named secret's value, failing fast if it is absent
        or empty. A required secret that resolves to an empty string is
        treated the same as a missing one -- never silently converted to
        `""` (docs/IMPLEMENTATION-ROADMAP.md Phase 2.3).
        """
        value = self.get(name)
        if not value:
            raise SecretNotFoundError(name)
        return value

    def __repr__(self) -> str:
        # Base fallback for any implementation that doesn't override this.
        # Concrete providers override to add non-secret metadata (e.g. a
        # file path) -- never a resolved value (docs/SECURITY.md: no
        # secret value in repr()).
        return f"{type(self).__name__}()"
