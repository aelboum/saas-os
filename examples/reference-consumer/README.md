# Reference consumer (ADR-0018)

This is the reference consumer `docs/ADR/0018-reference-consumer-validation-fixture.md`
describes: an internal architecture-validation fixture, not a shipped
part of the `saas-os` package and not a real product. It proves, against
a real disposable PostgreSQL database and a real (non-editable) `saas-os`
wheel install, that:

- `saas-os` can be consumed as an installed package dependency
  (ADR-0015) -- `reference_consumer/` imports `core`, `infra`, `api`,
  `control_plane` only the ordinary way (`import saas_os.core.tenancy`, `from
  saas_os.api.platform import build_platform_app`, ...), never via a
  repository-relative `sys.path` hack, and is excluded from
  `pyproject.toml`'s `[tool.setuptools] packages` /
  `[tool.importlinter] root_packages` (it is not itself a SaaS OS
  package).
- It owns its own application entrypoint (`reference_consumer/app.py`,
  built on `saas_os.api.platform.build_platform_app()` -- ADR-0017), its own
  migrations (`reference_consumer/migrations/`, a separate Alembic
  environment/version table from SaaS OS's own -- ADR-0016), and its own
  API route (`reference_consumer/routes.py`) and AI Control Plane tool
  (`reference_consumer/tools.py`), registered against its own
  `saas_os.core.rbac` permission.

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
independent from Core -- it calls only `saas_os.core.tenancy`/`saas_os.core.rbac`/
`saas_os.core.identity`/`saas_os.core.api_keys`/`saas_os.core.billing`/`saas_os.core.usage`, the
installed package's own published API) demonstrating that a real product
built on SaaS OS can correctly compose:

- B2B hierarchical tenancy, B2C personal tenancy, and B2B2C-style customer
  tenancy/membership -- all using `Tenant`/`TenantMembership` alone, never
  a second isolation abstraction;
- scoped roles (SELF/SUBTREE), delegation (with revocation and
  anti-redelegation), and explicit deny -- all through the existing
  `saas_os.core.rbac.can()` chokepoint, never a second authorization engine;
- tenant-bound service accounts and hardened API keys;
- membership lifecycle (suspend/revoke) and the invitation lifecycle
  (accept, one-time, replay-resistant);
- hierarchy-aware billing-owner resolution and usage aggregation (the
  legacy `inherits_billing` mechanism, retired forward by the 2026-10-02
  amendment to docs/ADR/0029-commercial-parties-and-billing-relationships.md),
  and the explicit support-access workflow (Phase F).

`tests/test_reference_consumer_scenarios_integration.py` (in the SaaS OS
repository, not shipped) is what actually asserts this behavior, imported
directly from the repository's own working tree for fast iteration --
deliberately separate from, and never a replacement for, the real-wheel/
isolated-venv packaging proof above.

## `pyproject.toml`

`pyproject.toml` in this directory has the shape a real consuming
project's own manifest has (ADR-0015 rules 7-8): one pinned Git/VCS
dependency on an exact 40-character commit SHA, which
`tests/test_consumer_pins_unit.py` enforces.

The pin is `26ec1de`, `main` after pull request #40, whose Stripe
adapter can create a subscription for a payer without a payment method
(pending until paid). It is later than `93b8002` (#38): billing-provider
events (ADR-0048), multi-factor login for platform operators (ADR-0049)
and the `saas-os-operator` commands (ADR-0050); than `6a71d70` (#31), which lets a route accept an API key (ADR-0047), than `9fd35b3` (#27),
which adds accepting an invitation over HTTP (ADR-0046), and than
`8b5e458`, the first published commit where `purge_tenant` takes a required caller (#24) and where only
a user linked to an external identity can be enrolled as a platform
operator (#25); this fixture's operator scenario enrolls such a user. Its
code passes the required `caller` that tenant lifecycle and feature-flag
functions take since ADR-0045 Phase C; it also imports the `saas_os` import root (ADR-0038). A manifest cannot name the commit it is part
of, so the pin always trails this directory by at least one commit.

Two different proofs exist, and they are not interchangeable:

- **Working-tree wheel install** (`tests/test_reference_consumer_integration.py`):
  a wheel built from the current working tree, installed into an isolated
  virtual environment, with this fixture copied outside the repository.
  It runs in CI and proves the code as it is now.
- **Pinned-SHA install** (docs/P-ROADMAP.md, P2): `pip install` of exactly
  the pinned `git+https` reference into a clean virtual environment. It
  was last run on 2026-10-15 against `26ec1de` (`docs/P-ROADMAP.md`,
  "Example pins moved to `26ec1de`"), and before that against `93b8002`, `6a71d70`, `9fd35b3`,
  `8b5e458` and `3677c86` (2026-10-14) and `58d134f` (2026-10-12): this fixture, copied outside the
  repository, ran its end-to-end driver (both migration histories, the
  tool, the route) on that install against a disposable PostgreSQL and
  Redis. It needs network access and repository read access, so it is a
  recorded manual proof, not a CI job; repeat it when the pin moves.
