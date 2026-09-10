# ADR-0015: SaaS OS distribution and independent-consumer boundary

Status: Accepted
Date: 2026-09-10
Supersedes / Superseded by: —

## Context

`docs/ARCHITECTURE-DISCOVERY.md` §20 states the platform's founding principle plainly: *"Dograh is a consumer of this platform, not part of it."* `docs/ARCHITECTURE.md` §3 and §9, and `docs/IMPLEMENTATION-ROADMAP.md`'s final phase, were nonetheless written around a `products/<name>/` directory living physically inside this same repository, built and released together with `core/`, `infra/`, and `control-plane/`. Those two framings were never reconciled before implementation started (`products/` exists today as an empty root package alongside `core`/`infra`/`control_plane` in both `pyproject.toml`'s `[tool.setuptools] packages` and its `[tool.importlinter] root_packages`).

`docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` ("SaaS OS — Distribution & Consumer Architecture Investigation") is the evidence base for this ADR. It found that this repository is already partially set up as an installable Python package by construction, not by decision — `pyproject.toml` already declares `name = "saas-os"`, `version = "0.1.0"`, and a real `setuptools` package list — and evaluated eight candidate consumption models (versioned package, Git/VCS dependency, template alone, template+package, monorepo, submodule, shared network service, and others) against a target of roughly 5–20 independent, separately-deployed consuming projects over multiple years.

This decision must be recorded before a second real project (Recharge, MarocAssist, LPG Level Sensing, AuraVox, or any other) is started against this platform, for the same reason ADR-0001/ADR-0003 recorded the in-repo layer boundaries before any Core code existed: a distribution model adopted implicitly, one ad hoc project at a time, is far harder to correct once several projects already depend on whatever pattern the first one happened to use.

## Options Considered

### Option A — Monorepo: consuming projects' business logic lives inside `saas-os` (the current, undecided-by-default state)
- Advantages: no distribution mechanism needs to be built; a project's code and SaaS OS's code are always in lockstep
- Disadvantages: directly contradicts `docs/ARCHITECTURE-DISCOVERY.md` §20's own founding principle; forces every consuming project onto one shared repository, CI pipeline, and release train; the investigation scored this lowest on isolation and on manageability at 5–20 projects of any of the options evaluated

### Option B — Versioned Python package, consumed via a private package index
- Advantages: the standard, well-understood mechanism for this exact problem; clean semantic versioning; best long-term ergonomics once adopted
- Disadvantages: requires standing up and operating index infrastructure (hosting, auth, a publish step) before any real consumer exists to justify it — a cost with no current evidence of need

### Option C — Versioned Python package, consumed via a pinned Git/VCS dependency (no registry)
- Advantages: zero new infrastructure — `pip`'s native `git+https://...@<ref>` dependency syntax works today against this repository's existing GitHub hosting and access control; a project's manifest can later be repointed at a real index with a one-line change, with no code impact; matches this repository's own established pattern of deferring infrastructure until evidence demands it (ADR-0007's deferred workflow engine, ADR-0010's deferred Kubernetes, ADR-0012's deferred Vault)
- Disadvantages: weaker provenance than a real index unless pinned to an exact commit SHA rather than a mutable tag; less polished dependency-resolution UX than a real index at higher consumer counts

### Option D — Project template/scaffold only, with SaaS OS's source copied into each new project at creation time, no ongoing dependency
- Advantages: simplest possible starting point for exactly one project
- Disadvantages: no update mechanism — a security fix to `core.identity` would require manual, per-project, file-by-file reapplication across every consumer; fails the "evolve independently over many years and many projects" requirement outright

### Option E — Git submodule
- Advantages: keeps a pinned reference to SaaS OS inside a consuming project's own repository tree
- Disadvantages: adds submodule-specific operational friction (detached-HEAD handling, `git submodule update --init` steps every clone/CI run must remember) with no capability advantage over a normal pinned package dependency (Option C)

### Option F — Centrally hosted SaaS OS runtime; consuming projects call it over a network API instead of importing code
- Advantages: would allow a single running instance to serve every project without per-project deployment
- Disadvantages: requires building capability that does not exist anywhere in this codebase today — every `core.*`/`control_plane.*` capability is an in-process Python function call, with no serialization boundary, no cross-project network-authorization model, and no multi-tenant-across-projects request routing; reintroduces a shared-runtime security boundary this repository's tenant-isolation model (ADR-0002) was built specifically to avoid needing; nothing in the investigation's requirements demonstrates this is necessary

## Recommendation

Option C now (pinned Git/VCS dependency, exact commit SHA preferred over a mutable tag), with Option B (a private package index) as an explicitly anticipated *later* evolution, adopted only once real multi-project friction justifies the added infrastructure — not on a fixed schedule. Options A, D, E, and F are rejected outright.

## Decision

**Accepted.** The following are now binding:

1. SaaS OS (`core/`, `infra/`, `control-plane/`, `contracts/`, and the reusable parts of `api/` — see ADR-0017) is a reusable, business-domain-agnostic SaaS foundation.
2. Independent SaaS projects (Recharge, MarocAssist, LPG Level Sensing, AuraVox, and any future project) live in their own, separate repositories — never inside this one.
3. Each consuming project owns, independently: its own repository, its own physical database, its own deployment, its own secrets/configuration, and all of its own business-domain code.
4. A consuming project depends on SaaS OS. This is the only permitted direction.
5. SaaS OS must never depend on a consuming project, in any form, at any time. No project's name, code, or business concept may appear inside this repository.
6. SaaS OS is distributed as a versioned Python package (`saas-os`, per `pyproject.toml`'s existing `name`/`version` fields).
7. Initial consumption uses a pinned Git/VCS dependency (`saas-os @ git+https://...@<ref>`). A private package index is **not** adopted by this decision — see "What Is Deliberately Not Decided Here."
8. Where practical, consuming projects pin an exact commit SHA rather than a mutable tag, for reproducibility and to reduce tag-mutation supply-chain risk.
9. Project scaffolding (the deployable shell: Dockerfile, CI workflow skeleton, Alembic environment wiring, an application-composition-root starting point per ADR-0017) is a separate concern from runtime package distribution. A scaffold, if and when built, is copied once into a new project; it is never an ongoing dependency the way the package is.
10. Everything a scaffold provides becomes the consuming project's own file, owned and modified by that project from the moment it is copied — SaaS OS has no further claim on it and does not track or version it.
11. `products/` is not part of the conceptual SaaS OS consumer architecture. It does not represent how a consuming project relates to this platform.
12. Real business-domain projects (Recharge, MarocAssist, LPG Level Sensing, AuraVox, or any other) must never be added to this repository, under `products/`, under any other name, or in any other location.

```
Independent SaaS Project  ──depends on (versioned package)──▶  saas-os
saas-os                   ──X──▶  any consuming project          FORBIDDEN, always
```

## Rejected Alternatives

- **Monorepo (Option A)**: rejected — the state the repository was drifting toward by default, directly contradicted by this platform's own founding principle (`docs/ARCHITECTURE-DISCOVERY.md` §20).
- **Template/scaffold alone, no package (Option D)**: rejected — no upgrade path; fails at any consumer count beyond one.
- **Git submodule (Option E)**: rejected — strictly more operational friction than Option C for no additional capability.
- **Centralized network service (Option F)**: rejected for now — no code path in this repository exposes Core capability over a network boundary today, and nothing in the investigation's requirements demonstrated a need to build one. Not permanently foreclosed; would require its own future ADR if concrete evidence emerges.

## What Would Be Difficult to Change Later

Once a real consuming project is built against a chosen distribution mechanism, changing that mechanism (e.g., moving from a Git/VCS dependency to a private index, or discovering that a network-service model was actually needed) requires that project to change how it declares and fetches its dependency — a real but bounded migration, not a rewrite, provided the package's *import surface* (`core.*`, `infra.*`, `control_plane.*`, `contracts.*`) stays stable across that change. What is genuinely hard to walk back is rule 5 (no SaaS-OS-to-project dependency): the moment SaaS OS's own code references a specific consuming project — even once, even temporarily — untangling that reference from every consumer that came to depend on its presence is materially harder than never introducing it. This is the same one-way-door reasoning already recorded for ADR-0002's tenant-isolation boundary and ADR-0004's tool-mediated-access boundary.

## What Is Deliberately Not Decided Here

Consistent with the investigation this ADR is based on, the following remain open and must not be inferred as decided:

- Whether or when to adopt a private package index (`docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` §7/§17) — no registry has been adopted, and none should be inferred from this ADR.
- The exact scaffold implementation and its repository location (a plain template repository vs. a CLI generator) — not designed by this ADR.
- Any major-version support-window policy (how many old majors SaaS OS commits to keeping patchable) — unaddressed.
- Whether `infra/db/backup` ships as part of the consumer-facing package or remains platform-team-only tooling — unaddressed.
- No code, package build, publish pipeline, or release tag is created by this ADR.

## Related

`docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` (full investigation and evidence base for this decision); `docs/ARCHITECTURE-DISCOVERY.md` §20 (the founding principle this ADR restores as binding); `docs/ARCHITECTURE.md` §3/§9 (the in-repo `products/` framing this ADR supersedes in principle — now edited to match, see Implementation Note below); ADR-0001 (layered architecture — the layer boundaries this ADR extends across a repository boundary rather than only a package boundary); ADR-0003 (monorepo with enforced module boundaries — scoped to *this* repository's own internal layers, unaffected by this ADR); ADR-0016 (independent database migration histories — the migration-mechanics consequence of this ADR); ADR-0017 (SaaS OS API/application boundary); ADR-0018 (reference consumer validation fixture).

## Implementation Note (packaging implementation phase)

This section records how rule 6 ("distributed as a versioned Python package") was actually implemented; it does not change the Decision above.

- **Packaging defect found and fixed.** `pyproject.toml`'s `[tool.setuptools] packages` previously listed only six top-level names (`core`, `infra`, `control_plane`, `products`, `contracts`, `api`) — a real, non-editable wheel built from that config silently excluded every nested subpackage (`core.tenancy`, `infra.db`, `control_plane.orchestration`, etc.). `pip install -e .` never surfaced this (an editable install exposes the whole source tree regardless of `packages`). Fixed with an explicit, fully-enumerated `packages` list (one entry per real package directory) rather than `find:`/`find_namespace:` automatic discovery — deliberate: an explicit list is fully auditable and cannot silently pick up an unrelated top-level directory (`tests/`, `examples/reference-consumer/`) the way a repo-root scan could. `tests/test_wheel_contents.py` (marked `packaging`) is the regression test: it builds a real wheel, inspects its contents, and installs it into an isolated non-editable venv.
- **`products/` and rule 11/12.** `products/` is excluded from the shipped `packages` list (this rule, fully implemented). It remains an `[tool.importlinter] root_packages` entry, however — a deviation from `docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` §18's "remove from root_packages" bullet, discovered empirically: import-linter's `forbidden_modules` entries name `products` directly and require it to be an inspectable root package (`lint-imports` errors with "Module 'products' does not exist" otherwise). `root_packages` is internal dev/CI lint configuration only, never itself shipped in the wheel, so this does not reintroduce `products/` into the distributed package — see `pyproject.toml`'s own comment at that line for the full reasoning.
- **`docs/ARCHITECTURE.md` §3/§9 updated** to state plainly that `products/` is not shipped and not where a real product lives, and that database ownership (§5) is per-project (ADR-0016), closing the gap this ADR's own "Related" section originally flagged as unaddressed follow-up work.
- **Console-script/migration-runner naming** (`saas-os-migrate`, `infra.db.migration_runner.run_core_migrations()`) is recorded under ADR-0016's own Implementation Note, since it is that ADR's "What Is Deliberately Not Decided Here" item this phase resolved.
