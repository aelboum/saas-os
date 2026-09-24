# local-dev/

Local Docker Compose tooling, not part of the `saas-os` package (no `core/`,
`infra/`, `api/`, `control-plane/` import boundaries apply here). Never
imported by application code.

- `bootstrap_zitadel.py` -- compatibility entrypoint for the local ZITADEL
  bootstrap. The implementation lives in the package
  (`infra/local_identity/zitadel_bootstrap.py`, console script
  `saas-os-local-identity`) so downstream products can run it from their
  installed SaaS-OS dependency; this file only delegates to it, and is
  kept because `deploy/bootstrap_zitadel_production.py` loads it by path.
  See `docs/LOCAL-IDENTITY.md`.
