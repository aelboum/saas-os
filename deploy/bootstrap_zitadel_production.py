"""Production entrypoint for the same ZITADEL bootstrap mechanism Phase 1
uses locally (`local-dev/bootstrap_zitadel.py`, ADR-0023 Phase 1) -- reused,
never duplicated: this file imports and calls that module's own functions
directly, verbatim, with no copy of its logic.

Why this thin wrapper exists at all, rather than pointing
`docker-compose.prod.yml`'s `zitadel-bootstrap` service straight at
`local-dev/bootstrap_zitadel.py`: that module's own docstring states
"Docker Compose tooling for the local development topology only ... carries
no production role", which the task explicitly says not to edit "merely to
support production" -- leaving it as production's own entrypoint would make
its self-description actively wrong for an operator debugging a production
bootstrap failure. The module's *logic* has no such limitation: its only
dev-branded identifier, `ORG_NAME = "saas-os-local"`, is unused dead code
(never referenced anywhere in the module -- the real org name is set once,
at ZITADEL's own first-instance setup, via `ZITADEL_FIRSTINSTANCE_ORG_NAME`
on the `zitadel` service itself, not by this script), so no override is
needed here either.

Configuration (docker-compose.prod.yml's `zitadel-bootstrap` service,
ADR-0023 Phase 3):

- `ZITADEL_INTERNAL_URL` -- `https://<IDENTITY_PUBLIC_DOMAIN>`, reached via
  the `zitadel` service's own network alias on `identity-edge` (never
  hairpinning through Caddy -- see that service's own comments).
- `PUBLIC_APP_ORIGIN` -- `https://<PUBLIC_DOMAIN>`, the browser-visible
  application origin. The callback registered with ZITADEL is derived from
  it (`<origin>/auth/callback`, ADR-0024) by the same helper the backend
  uses, so the registered redirect URI and the one sent in the token
  exchange cannot drift.
- `OIDC_REDIRECT_URI` -- optional, and normally unset in production. It
  stays the escape hatch for a callback that is genuinely not on the
  application origin; set together with `PUBLIC_APP_ORIGIN` to a value that
  disagrees, it fails closed rather than silently taking precedence.
- `SSL_CERT_FILE` -- trusts the self-signed certificate ZITADEL terminates
  its own TLS with for that direct connection (verified empirically against
  the pinned v4.19.0 image: both `httpx` and `urllib.request`'s default
  verification already honor this standard environment variable, so no
  `saas_os/core/identity`/`local-dev` code needed any change for this to work).

ADR-0025 §1a adds the Login V2 base URI, derived here from the identity
deployment profile and passed on as `ZITADEL_LOGIN_V2_BASE_URI`:

- `IDENTITY_PROFILE=fresh` -- always
  `https://<PUBLIC_DOMAIN>/ui/v2/login` (IDENTITY_PUBLIC_DOMAIN must equal
  PUBLIC_DOMAIN, the same rule deploy/check-identity-profile.sh enforces).
- `IDENTITY_PROFILE=existing` (the default) -- the application's login
  version is left untouched unless the operator opts in with
  `ZITADEL_LOGIN_V2_ENABLED=true`, which sets
  `https://<IDENTITY_PUBLIC_DOMAIN>/ui/v2/login`: Login V2 on the existing
  identity domain, so the issuer and WebAuthn/U2F RP ID stay unchanged.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType

_LOCAL_DEV_SCRIPT = Path("/local-dev/bootstrap_zitadel.py")


_LOGIN_V2_PATH = "/ui/v2/login"


def login_v2_base_uri(environ: Mapping[str, str]) -> str | None:
    """The application's Login V2 base URI for this deployment profile, or
    None to leave the application's login version as it is (ADR-0025 §1a).
    Raises ValueError on an inconsistent profile rather than guessing."""
    profile = environ.get("IDENTITY_PROFILE", "").strip() or "existing"
    public_domain = environ.get("PUBLIC_DOMAIN", "").strip()
    identity_domain = environ.get("IDENTITY_PUBLIC_DOMAIN", "").strip()
    if not public_domain or not identity_domain:
        raise ValueError("PUBLIC_DOMAIN and IDENTITY_PUBLIC_DOMAIN must both be set")
    if profile == "fresh":
        if identity_domain != public_domain:
            raise ValueError(
                "IDENTITY_PROFILE=fresh requires IDENTITY_PUBLIC_DOMAIN to equal PUBLIC_DOMAIN"
            )
        return f"https://{public_domain}{_LOGIN_V2_PATH}"
    if profile == "existing":
        if identity_domain == public_domain:
            raise ValueError(
                "IDENTITY_PROFILE=existing requires IDENTITY_PUBLIC_DOMAIN to differ from "
                "PUBLIC_DOMAIN"
            )
        enabled = environ.get("ZITADEL_LOGIN_V2_ENABLED", "").strip().lower()
        if enabled == "true":
            return f"https://{identity_domain}{_LOGIN_V2_PATH}"
        if enabled in ("", "false"):
            return None
        raise ValueError("ZITADEL_LOGIN_V2_ENABLED must be 'true' or 'false'")
    raise ValueError(f"IDENTITY_PROFILE must be 'fresh' or 'existing', got {profile!r}")


_DEFAULT_PAT_PATH = "/bootstrap/bootstrap.pat"


def bootstrap_token_revoked(environ: Mapping[str, str]) -> bool:
    """True when the bootstrap token file exists and is empty: the operator
    revoked the token and emptied the file (docs/RUNBOOKS.md, "Bootstrap
    token"), so there is nothing to provision with and nothing to do. A
    missing file is not revocation: the provisioning step reports it."""
    path = Path(environ.get("ZITADEL_BOOTSTRAP_PAT_PATH") or _DEFAULT_PAT_PATH)
    try:
        return path.is_file() and not path.read_text(encoding="utf-8").strip()
    except OSError:
        return False


def _load_local_dev_bootstrap() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bootstrap_zitadel", _LOCAL_DEV_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {_LOCAL_DEV_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    if bootstrap_token_revoked(os.environ):
        print(
            "bootstrap token revoked (empty token file): nothing to provision. "
            "To run the bootstrap again, issue a short-lived token "
            "(docs/RUNBOOKS.md, Bootstrap token)."
        )
        raise SystemExit(0)
    if not _LOCAL_DEV_SCRIPT.exists():
        print(
            f"FATAL: {_LOCAL_DEV_SCRIPT} not found -- docker-compose.prod.yml's "
            "`zitadel-bootstrap` service must bind-mount local-dev/bootstrap_zitadel.py "
            "at this exact path (mirroring how docker-compose.yml already does for local dev).",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        base_uri = login_v2_base_uri(os.environ)
    except ValueError as exc:
        print(
            f"FATAL: {exc} (docs/ADR/0025-same-origin-zitadel-login-v2-topology.md §1a)",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    if base_uri is not None:
        os.environ["ZITADEL_LOGIN_V2_BASE_URI"] = base_uri
    _load_local_dev_bootstrap().main()
