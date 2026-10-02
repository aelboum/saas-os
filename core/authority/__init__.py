"""`core/authority` -- the explicit, typed caller every authority-changing
Core operation requires (Foundation Authority & Evidence;
docs/ADR/0031-foundation-authority-and-evidence.md).

A permission-changing Core function never discovers *who* is calling it
from ambient state (no request context, no global, no `None` meaning
"system"): its caller is a required argument of one of exactly three
types, each naming an authority source SaaS OS actually has:

    UserCaller            a `core.identity` User acting as themselves.
    ServiceAccountCaller  a `core.identity` ServiceAccount, named together
                          with its own fixed tenant.
    SystemCaller          explicit platform authority for one named
                          purpose (`SystemAuthority`) -- tenant
                          provisioning or tenant purge -- never a generic
                          "trusted" flag. Accepted only by the operations
                          that declare that purpose.

This package is pure data: it imports nothing from FastAPI, the API layer
or any other Core module, so every Core module (and `core.audit_log`,
which records the caller as audit evidence) can depend on it. Resolving an
HTTP request to a caller is the API layer's job (`api/authority.py`).
"""

from core.authority.caller import (
    Caller,
    CallerTypeError,
    PrincipalCaller,
    ServiceAccountCaller,
    SystemAuthority,
    SystemCaller,
    UserCaller,
    require_caller,
)

__all__ = [
    "Caller",
    "PrincipalCaller",
    "UserCaller",
    "ServiceAccountCaller",
    "SystemCaller",
    "SystemAuthority",
    "CallerTypeError",
    "require_caller",
]
