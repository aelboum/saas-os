# ADR-0018: Reference consumer as an architecture validation fixture

Status: Accepted
Date: 2026-09-10
Supersedes / Superseded by: —

## Context

ADR-0015, ADR-0016, and ADR-0017 record a distribution model, a migration model, and an API/application boundary that no real consuming project has ever exercised — every conclusion in `docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` is, by that document's own admission (§16 Risks), "untested against an actual second codebase." `docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` §9/§13/§14 identified the same need from two directions — a repository-boundary question ("what does `products/` become") and a testing-strategy question ("is one real consumer project useful as a compatibility fixture") — and converged on one answer: a minimal, non-shipped reference consumer, living in this repository's own development/test tooling, exercised by this repository's own CI, and never distributed as part of the `saas-os` package.

This is not a new architectural layer and not a revival of `products/`'s original in-repo-product premise (ADR-0015 rule 12 forbids that outright). It is a test fixture, analogous to how `tests/architecture/` already proves the internal layer-boundary rules are non-vacuous by temporarily violating them and confirming the violation is caught (`docs/IMPLEMENTATION-ROADMAP.md` Phase 1.3's own recorded practice) — here applied to the cross-repository consumption model rather than an internal import rule.

## Options Considered

### Option A — No reference consumer; trust the architecture documents alone until the first real project is built
- Advantages: no fixture to build or maintain
- Disadvantages: ADR-0015/0016/0017's conclusions would remain entirely theoretical until a real, business-critical project is the first to discover any friction — the exact scenario this investigation exists to avoid, given that a distribution or migration mistake discovered inside a real project is far more expensive to correct than one discovered inside a disposable internal fixture

### Option B — A minimal, non-shipped reference consumer maintained as this repository's own internal validation fixture, exercised in this repository's own CI
- Advantages: proves the package-consumption model, the two-environment migration model, and the API/application boundary actually work end-to-end, before any real project depends on them; costs are bounded (one small fixture, not a product) and contained entirely within this repository's own development tooling; directly answers `docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` §14's testing-strategy question
- Disadvantages: ongoing maintenance cost (the fixture must be kept in sync with `saas-os`'s own evolving surface); risk of scope creep into an accidental real product if not clearly bounded

### Option C — Treat one of the real future projects (e.g., the first one actually built) as the de facto reference/compatibility project
- Advantages: no separate fixture to build
- Disadvantages: makes a real, business-critical project responsible for surfacing platform-level defects before its own users notice them; couples a real project's release schedule to SaaS OS's own validation needs, contradicting ADR-0015's "own release schedule" guarantee

## Recommendation

Option B.

## Decision

**Accepted.** A minimal reference consumer will be created as an architecture validation fixture. It is **not created by this ADR** — this ADR records the decision that it should exist and what it must prove; building it is deferred, explicit future work (see `docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` §18's proposed next-phase ordering, which places it after `products/`'s removal from the shipped package and before any real consuming project is attempted).

When built, the reference consumer must prove, end-to-end:

- SaaS OS can be consumed as an external package dependency, per ADR-0015 (a pinned Git/VCS reference, resolved the same way a real consuming project would resolve it).
- The consumer is genuinely independent of the SaaS OS repository — its own directory tree, excluded from `[tool.setuptools] packages`/`root_packages` so it is never part of what a real consumer installs.
- The consumer owns its own application entrypoint, per ADR-0017 — it does not import `api.main:app` as its own application; it builds its own and mounts SaaS OS's reusable ingress components into it.
- The consumer owns its own, project-specific migrations, separate from SaaS OS's.
- SaaS OS's migrations and the consumer's own migrations can each run independently, per ADR-0016's two-environment model, both against one shared, disposable PostgreSQL database.
- The consumer can register and invoke at least one of its own AI Control Plane tools, exercising the per-project, in-process governance model (`docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` §11), against its own RBAC-registered permission.
- No business-domain product logic is added to SaaS OS itself in the process of building or exercising this fixture.

The reference consumer is a validation fixture, not a product and not a new architectural layer. It must never be allowed to grow into a real Recharge, MarocAssist, LPG Level Sensing, or AuraVox implementation, and it carries no business/commercial purpose of its own.

## Rejected Alternatives

- **No reference consumer (Option A)**: rejected — leaves ADR-0015/0016/0017 entirely unverified until a real, consequential project is the first to find any gap.
- **Using a real future project as the de facto fixture (Option C)**: rejected — couples a real project's schedule and stability to SaaS OS's own validation needs, contradicting the "own release schedule" guarantee ADR-0015 already establishes.

## What Would Be Difficult to Change Later

If the first real consuming project is built before this fixture exists and before ADR-0015/0016/0017's mechanisms are proven against it, any gap the real project discovers becomes a production-facing problem for that project rather than a fixture-only finding — the cost asymmetry this ADR exists to avoid. Building the fixture first is comparatively cheap to reverse (it is disposable, internal-only tooling); discovering a distribution or migration defect inside a live project's database is not.

## What Is Deliberately Not Decided Here

- The reference consumer is **not created by this ADR**. No directory, code, migration, or CI job for it exists yet.
- Its exact location, name, and structure are not fixed here (the distribution investigation's working name, `examples/reference-consumer/`, is illustrative, not binding).
- Whether it is retired once several real consuming projects exist (making it redundant as a compatibility signal) or kept indefinitely is not decided.
- Cross-version compatibility testing (multiple SaaS OS major versions tested against the fixture simultaneously) is explicitly out of scope until at least one real consuming project exists — building that matrix speculatively, against a fixture with no real second consumer yet, risks exactly the "generic-but-useless abstraction" risk `docs/ARCHITECTURE-DISCOVERY.md` §23 already warns this codebase about.

## Related

`docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` §9/§13/§14/§18 (evidence base and proposed next-phase ordering); ADR-0015 (distribution and consumer boundary — what the fixture proves); ADR-0016 (independent database migration histories — what the fixture proves); ADR-0017 (API/application boundary — what the fixture proves); `docs/IMPLEMENTATION-ROADMAP.md` Phase 1.3 (the existing internal precedent of proving a boundary rule non-vacuous by testing it directly, applied here across a repository boundary instead of an import boundary).

## Implementation Note (packaging implementation phase)

The fixture described above is now built, at `examples/reference-consumer/` (the investigation's own illustrative working name, kept as the actual location). This section records what it proves and how; it does not change the Decision above.

- **Consumes `saas-os` as an installed package.** `tests/test_reference_consumer_integration.py` builds a real wheel, installs it into an isolated venv, then copies `reference_consumer/` to a scratch directory *outside* this repository before ever importing it — so nothing in the fixture's own code can resolve `core`/`infra`/`api`/`control_plane` via this repository's source tree, even by accident. `reference_consumer/`'s own code contains no `sys.path` manipulation of any kind.
- **Excluded from the shipped package**: `examples/` is outside every path `pyproject.toml`'s explicit `packages` list and `[tool.importlinter] root_packages` name — no exclusion rule was even needed, a side effect of Task 1's explicit-enumeration packaging fix (ADR-0015's Implementation Note).
- **Owns its own application entrypoint**: `reference_consumer/app.py::create_app()` calls `api.platform.build_platform_app()` (ADR-0017) and mounts its own route; it never imports `api.main:app`.
- **Owns its own, separate migrations**: `reference_consumer/migrations/` — its own Alembic environment, its own default-named `alembic_version` table, a real foreign key from its own `reference_consumer.widgets` table into SaaS-OS-owned `core.tenants`. Verified end-to-end against one disposable PostgreSQL database: SaaS OS's migrations apply first (`alembic_version_saas_os` advances, `core`/`control_plane`/`self_learning` schemas exist), then the fixture's own migrations apply (`alembic_version` advances, `reference_consumer` schema exists) — both independently, per ADR-0016.
- **Registers and invokes its own AI Control Plane tool** (`reference_consumer/tools.py::build_check_widget_status_tool`, tier 0) against its own `core.rbac`-registered permission (`reference_consumer.widgets:read`) — a real tenant, user, role, and permission are created, the tool is invoked through `control_plane.orchestration.invoke_tool()`, and the RBAC gate is exercised for real, not stubbed.
- **No business-domain product logic was added to SaaS OS itself** — every fixture-specific file lives under `examples/reference-consumer/`, never under `core/`, `infra/`, `control-plane/`, or `api/`.
- Wired into `scripts/check-migrations.sh` (extended per `docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` §13's own recommendation), so the two-environment ordering is proven end-to-end on every run of that gate, not only SaaS OS's own migrations in isolation.
