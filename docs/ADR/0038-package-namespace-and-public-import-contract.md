# ADR-0038: Package namespace and public import contract

Status: Accepted (2026-10-11) and implemented
Date: 2026-10-11
Supersedes / Superseded by: —

## Context

ADR-0015 distributes SaaS OS as one Python distribution, `saas-os`, and names its import surface as `core.*`, `infra.*`, `control_plane.*`, `contracts.*` and the reusable parts of `api.*`. The same ADR records that this import surface is the one thing that must stay stable once a consumer exists.

The distribution installs five unrelated-looking top-level packages. From a clean install of commit `4fccc93` (`pip install "saas-os @ git+https://github.com/aelboum/saas-os@4fccc93..."`, docs/P-ROADMAP.md P2), `saas_os-0.1.0.dist-info/top_level.txt` reads:

```
api
contracts
control_plane
core
infra
```

Four of those names are among the most common directory names in application code. The collision is not theoretical. In that same clean environment, a project directory containing its own empty `api/__init__.py`:

```
$ python -c "import api.platform"
ModuleNotFoundError: No module named 'api.platform'
$ python -c "import api; print(api.__file__)"
<project>/api/__init__.py
```

The project's `api` package shadows SaaS OS's, so `build_platform_app` and the whole ingress chain become unimportable. There are three distinct failure modes:

1. **Source shadowing** (shown above): a consumer package named `api`, `core`, `infra` or `contracts` on `sys.path` ahead of `site-packages` hides the SaaS OS package of that name. The symptom is an import error for a SaaS OS submodule, far from the cause.
2. **Installed-file overwrite**: if any other distribution in the consumer's environment also installs a top-level `core`, `api`, `infra` or `contracts`, `pip` writes both into the same `site-packages` directory. Files of one silently replace files of the other, with no error at install time.
3. **Partial shadowing of security code**: mode 1 or 2 can leave some SaaS OS modules importable and others replaced. `core.rbac` or `api.dependencies` resolving to a different file than the one that was audited is a security defect, not only an inconvenience.

The reference consumer and the consumer scaffold avoid all three only by convention: their package is named `reference_consumer` / `my_product`. Nothing enforces that convention on a real product.

No consumer exists today (ADR-0015 rule 12; docs/P-ROADMAP.md). That is the cheapest this decision will ever be: ADR-0015 itself classifies the import surface as hard to change after the first consumer.

Size of a rename, measured on `4fccc93`:

| What | Count |
|---|---|
| `import`/`from` statements naming a shipped root (`core` 1460, `infra` 1258, `control_plane` 333, `api` 120, `contracts` 9) | about 3,180 |
| String literals naming a module path (monkeypatch targets, entry points) | about 800 |
| Console scripts whose target module path changes (script names do not) | 4 |
| import-linter contracts naming roots | 13 |
| Path globs in `infra/update/policy.py` | all |

What a rename does **not** touch: PostgreSQL schema names (`core`, `control_plane`, `self_learning` are database schemas, independent of Python package names), Alembic revision identifiers and version tables, arq job names (a handler's bare `__name__`, not a module path), permission strings, audit event names.

What it does touch at runtime:

- **Queued jobs.** arq serializes job arguments with `pickle`, and `infra.jobs.payload.TenantJobPayload` is pickled by its module path. A job enqueued before the rename cannot be unpickled after it.
- **Logger names** (`api.worker`, `core.billing.service`, …) appear in every log line and in any alert rule keyed on them.
- **Process commands**: `python -m api.server` and `python -m api.worker` in `Dockerfile` and the Compose files, and the operator command `python -m api.tenant_bootstrap` in `docs/RUNBOOKS.md`.

## Options Considered

### Option A — Keep the five top-level names; document them as reserved

Add a "reserved top-level names" section to the consumer guide and a startup or scaffold check that fails when a consumer package uses one.

- Advantages: no code change; nothing breaks; no migration.
- Disadvantages: failure modes 2 and 3 remain, because a check in the consumer's own code cannot see a third-party distribution overwriting files in `site-packages`. The names stay generic forever, and the cost of changing them grows with every consumer. The import statements in a product (`from core.rbac import can`) do not say which platform they come from.
- Compatibility: full.

### Option B — One root package, `saas_os`, hard cut with no compatibility shim

`saas_os.core`, `saas_os.infra`, `saas_os.api`, `saas_os.contracts`, `saas_os.control_plane`. The distribution installs exactly one top-level name, matching its distribution name. The old names stop existing in the same change.

- Advantages: removes all three failure modes, since one unique top-level name cannot be shadowed by an application directory by accident. The import surface names the platform. `top_level.txt` becomes one line, which a test can pin. It resolves the `control-plane/` versus `control_plane` directory mismatch as a side effect.
- Disadvantages: a mechanical change of about 4,000 references in one commit, large to review even though a codemod produces it. Every document that cites a path changes or goes stale. In-flight queued jobs do not survive it. It breaks any consumer pinned to an older SHA — today, none.
- Compatibility: none with the old names, by design.

### Option C — `saas_os` root plus compatibility shims for the old names

As B, and the distribution also keeps thin `core`, `infra`, `api`, `contracts`, `control_plane` packages that re-export from `saas_os.*` and emit a deprecation warning, for a stated window.

- Advantages: a consumer written against the old names keeps working during the window.
- Disadvantages: while the shims are installed, the distribution still owns the five generic names, so every failure mode remains for the whole window — the shim defeats the purpose it accompanies. A shim also makes two import paths resolve to one module object only if written carefully; done carelessly it creates two copies of module-level state (the job-kind registry, the purge-participant registry, cached configuration, SQLAlchemy metadata), which is a correctness hazard in exactly the security-relevant registries. There is no consumer to benefit.
- Compatibility: full during the window, at the cost above.

### Option D — Prefixed top-level names (`saasos_core`, `saasos_infra`, …)

Keep five top-level packages, rename each with a prefix.

- Advantages: unique names; a smaller conceptual change than nesting.
- Disadvantages: the same edit volume as B for a weaker result — still five top-level names owned by one distribution, and not the idiomatic shape (one distribution, one import root).
- Compatibility: none with the old names.

## Recommendation

**Option B, executed before the first real consumer pins a SHA.**

The deciding fact is that the number of consumers is zero. Option C's only benefit is protecting existing consumers, and there are none, while its cost is keeping the defect alive. Option A leaves a silent-overwrite path into authorization code. Option D pays B's price for less.

Recommended sub-decisions, each of which is part of what needs approval:

1. **Root name**: `saas_os` (the distribution name with the hyphen normalized).
2. **Compatibility policy**: no shim. The rename lands as one change. The reference consumer, the scaffold and their pins move in the same change or the one immediately after.
3. **Physical layout**: move the packages under one `saas_os/` directory at the repository root (`saas_os/core`, `saas_os/infra`, …), not a `package-dir` mapping over the current directories. With a mapping, the repository root would still expose top-level `core` to any process started from it, and tests could keep passing through the old names. A physical move makes the old names impossible to import in development too.
4. **`control_plane`**: becomes `saas_os.control_plane`; the `control-plane/control_plane/` double directory and its `package-dir` entry disappear. `docs/ARCHITECTURE.md` §3 fixes the hyphenated directory name today, so this needs that section amended.
5. **`api/` split** (ADR-0017's deferred item): not decided here. `saas_os.api` keeps its current contents. Deciding the library/application split in the same change would mix a mechanical rename with a design change.

## Migration plan (if Option B is approved)

Each step ends with the full validation suite green before the next begins.

1. **Freeze.** No other change in flight on the branch. Record the pre-rename SHA as the rollback point.
2. **Move and rewrite, one commit.** `git mv` the five packages under `saas_os/`. Rewrite imports with a syntax-aware codemod (not text substitution): `import X`, `from X import`, and `from X.y import` for the five roots. Rewrite module-path string literals: monkeypatch targets, `[project.scripts]` targets, `python -m` commands in `Dockerfile`, Compose files, CI and scripts.
3. **Packaging.** `[tool.setuptools] packages` becomes the explicit `saas_os.*` list (the explicit-list rule and its reasons stay). `package-data` keys move to `saas_os.infra.db` and `saas_os.infra.edge`. `tests/test_wheel_contents.py` additionally asserts that `top_level.txt` is exactly `saas_os`.
4. **Boundary enforcement, verified non-vacuous.** Rewrite the 13 import-linter contracts and `root_packages` to `saas_os.core` etc. Re-run the existing negative controls in `tests/architecture/test_layer_boundaries.py` (they append a forbidden import and expect `lint-imports` to fail). A contract that names a module that no longer exists matches nothing and passes silently; these controls are what proves that did not happen. Update the scanned roots in `tests/architecture/test_tenant_session_boundary.py` and `tests/architecture/test_route_policy.py`, with the same negative-control check.
5. **Update tooling.** Rewrite the path globs in `infra/update/policy.py` and bump its policy version. A consumer on an old SHA evaluating the rename candidate sees unknown paths and gets `REVIEW_REQUIRED`, which is the correct fail-closed answer.
6. **Fixtures and scaffold.** Rewrite imports in `examples/reference-consumer/` and `examples/consumer-scaffold/`; re-run both end-to-end tests from an isolated venv.
7. **Documentation.** `README.md`, `docs/CONSUMER-GUIDE.md`, `docs/ARCHITECTURE.md` §3, and current operational documents. Accepted ADRs are historical records: each gets a one-line note that paths predate ADR-0038, not a rewrite.
8. **Deployment note.** Drain the job queue before deploying the renamed worker (or accept that jobs enqueued before the deploy dead-letter on unpickle). Update alert rules keyed on logger names.
9. **Publish the first post-rename SHA** as the baseline that consumers pin.

## Rollback strategy

- **Before any consumer pins a post-rename SHA**: revert the rename commit. Nothing persisted depends on the new names except jobs enqueued after the deploy, which need the same drain in reverse.
- **After a consumer pins a post-rename SHA**: forward-only. Reverting would break that consumer the way the rename would have broken an earlier one. This is why the recommendation is to do it now.
- **Database**: no rollback step. No schema, table, revision or stored value changes.

## Decision

**Accepted by the repository owner on 2026-10-11: Option B.** `saas_os` is the canonical and only public Python import root, as a hard cut with no compatibility alias.

1. **Root name**: `saas_os`.
2. **Compatibility policy**: none. The former top-level names (`api`, `contracts`, `control_plane`, `core`, `infra`) no longer exist; no shim package re-exports them.
3. **Physical layout**: the five packages live under one `saas_os/` directory at the repository root. There is no `package-dir` mapping.
4. **`control_plane`**: `saas_os.control_plane`. The `control-plane/control_plane/` double directory is gone.
5. **`api/` split** (ADR-0017's deferred item): still not decided; `saas_os.api` keeps its contents.
6. **Queued jobs and alert rules**: the owner did not report a deployment with jobs in a queue or alert rules on logger names; the implementation assumes none. Migration step 8 still applies to any deployment that has them.

External product repositories and their dependency pins are not modified by this decision or its implementation.

## What Would Be Difficult to Change Later

The import root is the most-repeated string in every consumer's code. After the first consumer pins a SHA, changing it means a coordinated change in every consumer repository, or a shim window that reintroduces the collision this ADR exists to remove. Choosing Option A is therefore also a one-way door in practice: it is reversible only until a product exists.

## Related

ADR-0015 (distribution and consumer boundary; names the import surface and its stability requirement); ADR-0017 (API/application boundary; its deferred `api/` split is deliberately not decided here); ADR-0003 (module boundaries, enforced by the import-linter contracts step 4 rewrites); ADR-0022 and ADR-0030 (architecture scans whose roots step 4 updates); `docs/AUTO-UPDATE-CLI.md` (path-based update policy, step 5); `docs/P-ROADMAP.md` P1.

## Implementation Note (2026-10-11)

Records how the Decision was carried out; it does not change it. Paths and module names in the Context and Options sections above describe the layout before this change.

- **Inventory before the move.** A syntax-aware codemod (an AST pass for imports and for bare `core.x.y` usages after a plain `import core.x`, with string literals rewritten only where they resolve to a real module) reported what it deliberately left alone: 550 dotted strings that are database or audit identifiers (`core.tenants.id`, `api.access_denied`), 454 bare strings such as `schema="core"`, 60 package-or-table ambiguities (`core.audit_log`, `core.api_keys`, `core.feature_flags`, `core.notifications`, all table references), and 197 f-strings (SQL). None of those were changed.
- **What moved.** `core/`, `infra/`, `api/`, `contracts/` and `control-plane/control_plane/` → `saas_os/…`, plus a new `saas_os/__init__.py`. Roughly 600 Python files and 70 configuration, script and living-documentation files were rewritten. Files were moved with the filesystem, not `git mv`, because staging was not authorized; Git will detect the renames at commit time.
- **Not renamed, on purpose.** PostgreSQL schema names (`core`, `control_plane`, `self_learning`), Alembic revision identifiers and version tables, arq job names, permission resources (`control_plane.self_learning.adaptation`), tool keys, the advisory-lock key `core.tenancy.hierarchy`, audit event names, and the two import-linter contract labels that mention `infra/db` and `infra/secrets`. No migration was added and no stored value changes.
- **Packaging.** `[tool.setuptools] packages` is the explicit `saas_os.*` list (47 entries); `package-dir` is removed; `package-data` keys and the four console-script targets moved (script names unchanged). `Dockerfile` copies `saas_os/` and runs `python -m saas_os.api.server`; Compose, CI, `alembic.ini` and the check scripts follow.
- **Boundary enforcement, verified non-vacuous.** The 13 import-linter contracts and `root_packages = ["saas_os", "products"]` were rewritten. The negative controls in `tests/architecture/test_layer_boundaries.py` first failed after the rename — they injected the old import names, which no contract matched any more, exactly the silent failure mode predicted above. They now inject `saas_os.*` imports and each contract is seen to break. `tests/architecture/test_tenant_session_boundary.py`, `test_route_policy.py`, `test_authority_contract.py` scan the new roots. Two control-plane tests that asserted "module X is not imported" by a `startswith("core.rbac.")` prefix were updated the same way, for the same reason.
- **Regression tests.** `tests/architecture/test_namespace_contract.py` (hermetic): no former top-level directory, no import of a former root in any form (with its own non-vacuity control), every shipped package under `saas_os`, no `package-dir`, console scripts under `saas_os`, and every first-party module named by an import-linter contract exists. `tests/test_wheel_contents.py`: a built wheel's top-level names are exactly `{saas_os}`.
- **Update policy.** `saas_os/infra/update/policy.py` globs moved under `saas_os/`; `POLICY_VERSION` is `3`. A path in the old layout classifies as `unknown`, so a consumer evaluating a pre-rename candidate with the new policy gets REVIEW_REQUIRED (tested).
- **A defect the rename exposed.** A stale, ignored `build/` directory at the repository root made `pip wheel` ship the old top-level packages next to `saas_os`. The wheel top-level-name test caught it; the directory was removed. A clean checkout never has it.
- **Consumer impact.** Any consumer pinned to a pre-rename SHA keeps working until it moves its pin; moving it requires rewriting its imports to `saas_os.*`. No such consumer is known. The two example manifests in this repository still pin `4fccc93`, a pre-rename commit: they are stale until this change is published (docs/P-ROADMAP.md, P2).
- **Rollback.** Before publication: restore the pre-rename tree (a snapshot was taken outside the repository before the codemod ran) or discard the working-tree change. After a consumer pins a post-rename SHA: forward-only, as stated above.
- **`.secrets.baseline`.** Its entries are keyed by file path. Every reviewed finding in a moved file now sits at a path the baseline does not list, so the secrets gate will report those findings as new until the baseline is regenerated and re-audited. That file is the owner's uncommitted work and was not touched; regenerating it is a required owner action before `scripts/check-security.sh` can pass.
