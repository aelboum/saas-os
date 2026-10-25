"""Deployment-level email provider selection (ADR-0057).

`EMAIL_PROVIDER` names one entry of a fixed, built-in map maintained by
SaaS-OS. There is no runtime plugin registry and no setter: a consuming
product cannot replace the process-wide selection (ADR-0057; the security
concern `docs/architecture/PROVIDER-EXTENSIBILITY-REVIEW.md` section 4 raised
about process-global overrides). A product that sends its own mail through
another provider keeps passing `provider=` to `send_email()`, which this
module never affects.

Unset `EMAIL_PROVIDER` selects `smtp`, exactly as before ADR-0057, so a
deployment that only sets `SMTP_*` behaves unchanged.

**Adding a provider** is a SaaS-OS change: implement `EmailProvider` in its
own module under `saas_os/core/email` (a vendor SDK, if any, behind an
optional extra, docs/ADR/0041-dependency-and-packaging-modularity.md),
add its name to `config.EMAIL_PROVIDER_NAMES` and its factory to
`_PROVIDER_FACTORIES` below, and cover it with the same configuration,
failure-classification and redaction tests the SMTP adapter has.

Selection constructs a provider per call, as `send_email()`'s default did
before ADR-0057: construction reads configuration and credentials but makes
no network call.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType

from saas_os.core.email.config import (
    EMAIL_PROVIDER_NAMES,
    get_email_default_sender,
    get_email_provider_name,
)
from saas_os.core.email.errors import EmailConfigurationError
from saas_os.core.email.provider import EmailProvider
from saas_os.core.email.resend_provider import ResendEmailProvider
from saas_os.core.email.smtp_provider import MailpitEmailProvider, SmtpEmailProvider

_DEFAULT_PROVIDER_NAME = "smtp"

# Read-only: the map itself cannot be mutated through this module.
_PROVIDER_FACTORIES: Mapping[str, Callable[[], EmailProvider]] = MappingProxyType(
    {
        "smtp": SmtpEmailProvider,
        "mailpit": MailpitEmailProvider,
        "resend": ResendEmailProvider,
    }
)

if set(_PROVIDER_FACTORIES) != set(EMAIL_PROVIDER_NAMES):  # pragma: no cover -- import-time guard
    raise RuntimeError("EMAIL_PROVIDER_NAMES and the provider factory map disagree.")


def get_email_provider() -> EmailProvider:
    """Construct the deployment's configured provider. Raises
    `EmailConfigurationError` for an unknown `EMAIL_PROVIDER`, missing or
    invalid settings or credentials (for example a missing
    `RESEND_API_KEY`), or a provider refused in this environment (Mailpit
    outside development/test)."""
    name = get_email_provider_name() or _DEFAULT_PROVIDER_NAME
    return _PROVIDER_FACTORIES[name]()


def validate_email_configuration() -> str | None:
    """Startup check for an explicitly configured provider. When
    `EMAIL_PROVIDER` is set, constructs the provider (configuration,
    credentials, the production guards -- no network call) and requires
    `EMAIL_DEFAULT_SENDER`; any problem raises `EmailConfigurationError`, so
    the process fails to start instead of dead-lettering mail later.
    When it is unset, email stays optional exactly as before ADR-0057 and
    nothing is checked. Returns the validated provider name, or `None`."""
    name = get_email_provider_name()
    if name is None:
        return None
    get_email_provider()
    if get_email_default_sender() is None:
        raise EmailConfigurationError(
            f"EMAIL_PROVIDER={name!r} is set but EMAIL_DEFAULT_SENDER is not."
        )
    return name
