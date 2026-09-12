# Reference consumer (ADR-0018)

This is the reference consumer `docs/ADR/0018-reference-consumer-validation-fixture.md`
describes: an internal architecture-validation fixture, not a shipped
part of the `saas-os` package and not a real product. It proves, against
a real disposable PostgreSQL database and a real (non-editable) `saas-os`
wheel install, that:

- `saas-os` can be consumed as an installed package dependency
  (ADR-0015) -- `reference_consumer/` imports `core`, `infra`, `api`,
  `control_plane` only the ordinary way (`import core.tenancy`, `from
  api.platform import build_platform_app`, ...), never via a
  repository-relative `sys.path` hack, and is excluded from
  `pyproject.toml`'s `[tool.setuptools] packages` /
  `[tool.importlinter] root_packages` (it is not itself a SaaS OS
  package).
- It owns its own application entrypoint (`reference_consumer/app.py`,
  built on `api.platform.build_platform_app()` -- ADR-0017), its own
  migrations (`reference_consumer/migrations/`, a separate Alembic
  environment/version table from SaaS OS's own -- ADR-0016), and its own
  API route (`reference_consumer/routes.py`) and AI Control Plane tool
  (`reference_consumer/tools.py`), registered against its own
  `core.rbac` permission.

Exercised by `tests/test_reference_consumer_integration.py` (marked
`integration`): that test builds a real wheel, installs it into an
isolated venv, copies this directory's `reference_consumer/` package
into a scratch directory outside the repository (so nothing here can
resolve via the repository's own source tree even by accident), and runs
the fixture's own migration + app + tool flow entirely from there.

## Phase I scenarios (`reference_consumer/scenarios.py`)

Architecture research: universal multi-tenant tenancy, Phase I --
"Reference Consumer Extension". `scenarios.py` is additional, ordinary
consumer business logic (still illustrative, still non-production, still
independent from Core -- it calls only `core.tenancy`/`core.rbac`/
`core.identity`/`core.api_keys`/`core.billing`/`core.usage`, the
installed package's own published API) demonstrating that a real product
built on SaaS OS can correctly compose:

- B2B hierarchical tenancy, B2C personal tenancy, and B2B2C-style customer
  tenancy/membership -- all using `Tenant`/`TenantMembership` alone, never
  a second isolation abstraction;
- scoped roles (SELF/SUBTREE), delegation (with revocation and
  anti-redelegation), and explicit deny -- all through the existing
  `core.rbac.can()` chokepoint, never a second authorization engine;
- tenant-bound service accounts and hardened API keys;
- membership lifecycle (suspend/revoke) and the invitation lifecycle
  (accept, one-time, replay-resistant);
- hierarchy-aware billing-owner resolution and usage aggregation
  (Phase H), and the explicit support-access workflow (Phase F).

`tests/test_reference_consumer_scenarios_integration.py` (in the SaaS OS
repository, not shipped) is what actually asserts this behavior, imported
directly from the repository's own working tree for fast iteration --
deliberately separate from, and never a replacement for, the real-wheel/
isolated-venv packaging proof above.

## `pyproject.toml`

`pyproject.toml` in this directory is illustrative, matching the shape a
real consuming project's own manifest would have (ADR-0015 rule 7: a
pinned Git/VCS dependency). It is not itself used to `pip install` this
fixture -- no released `saas-os` tag/commit exists yet for it to pin to.
The integration test instead installs the wheel this same repository
builds from its own working tree, which is the same code a real pin
would resolve to.
