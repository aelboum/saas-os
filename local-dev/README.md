# local-dev/

Local Docker Compose tooling, not part of the `saas-os` package (no `core/`,
`infra/`, `api/`, `control-plane/` import boundaries apply here). Never
imported by application code.

- `bootstrap_zitadel.py` -- idempotent local-only bootstrap of the SaaS-OS
  OIDC application in the self-hosted local ZITADEL instance
  (`docker-compose.yml`'s `zitadel-bootstrap` service). See
  `docs/LOCAL-IDENTITY.md`.
