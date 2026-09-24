"""Compatibility entrypoint for the local ZITADEL bootstrap (ADR-0023 Phase 1).

The implementation now lives in the installed `saas-os` package, at
`infra.local_identity.zitadel_bootstrap` (console script
`saas-os-local-identity`), so consuming projects can run it from their
SaaS-OS dependency instead of copying this file -- see
docs/LOCAL-IDENTITY.md.

This path is kept because deploy/bootstrap_zitadel_production.py loads it
by file path and calls `main()`. It contains no logic of its own; behavior
with no extra configuration is unchanged (project `saas-os`, application
`saas-os-backend`, redirect URI from `OIDC_REDIRECT_URI`).
"""

from __future__ import annotations

from infra.local_identity.zitadel_bootstrap import main

__all__ = ["main"]

if __name__ == "__main__":
    main()
