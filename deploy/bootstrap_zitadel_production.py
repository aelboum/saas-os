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
- `OIDC_REDIRECT_URI` -- SaaS-OS's own production callback, unchanged.
- `SSL_CERT_FILE` -- trusts the self-signed certificate ZITADEL terminates
  its own TLS with for that direct connection (verified empirically against
  the pinned v4.19.0 image: both `httpx` and `urllib.request`'s default
  verification already honor this standard environment variable, so no
  `core/identity`/`local-dev` code needed any change for this to work).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

_LOCAL_DEV_SCRIPT = Path("/local-dev/bootstrap_zitadel.py")


def _load_local_dev_bootstrap() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bootstrap_zitadel", _LOCAL_DEV_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {_LOCAL_DEV_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    if not _LOCAL_DEV_SCRIPT.exists():
        print(
            f"FATAL: {_LOCAL_DEV_SCRIPT} not found -- docker-compose.prod.yml's "
            "`zitadel-bootstrap` service must bind-mount local-dev/bootstrap_zitadel.py "
            "at this exact path (mirroring how docker-compose.yml already does for local dev).",
            file=sys.stderr,
        )
        raise SystemExit(1)
    _load_local_dev_bootstrap().main()
