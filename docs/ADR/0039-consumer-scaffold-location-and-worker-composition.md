# ADR-0039: Consumer scaffold location and worker composition

Status: Accepted and implemented — confirmed by the repository owner on 2026-10-11 (the optional `extra_functions` / `extra_cron_jobs` seam is retained)
Date: 2026-10-11
Supersedes / Superseded by: —

## Context

ADR-0015 rule 9 separates project scaffolding from package distribution and rule 10 says a scaffold is copied once and then belongs to the consumer. Under "What Is Deliberately Not Decided Here" it leaves open "the exact scaffold implementation and its repository location (a plain template repository vs. a CLI generator)".

Until now a new product had only `examples/reference-consumer/` to start from. That fixture is a validation harness (ADR-0018): it proves boundaries with a single read route and is not shaped as a starting point. It has no migration entry step, no permission registration step, no job and no worker.

Writing the scaffold exposed a second gap. `python -m api.worker` builds its worker from `registered_job_functions()`, a fixed list of platform jobs. A product with one job of its own had to re-implement the whole entrypoint — startup order, the fail-closed database-role guard, the health probe — to add it. `build_platform_app()` solved the same problem for the HTTP process (ADR-0017); nothing solved it for the worker.

## Options Considered

### Scaffold location

#### Option A — A directory in this repository, `examples/consumer-scaffold/`, not shipped
- Advantages: tested by this repository's own CI against the same commit it is copied from, so it cannot drift from the platform; no new repository, generator or release process; the same exclusion from the wheel and from import-linter that `examples/reference-consumer/` already has.
- Disadvantages: a consumer copies a directory by hand and renames one string; no interactive prompts.

#### Option B — A separate template repository
- Advantages: `Use this template` on the hosting provider; clean history for the new project.
- Disadvantages: a second repository to keep in step with every platform change, with no test in this repository able to fail when it falls behind.

#### Option C — A generator command in the package (`saas-os-new-project`)
- Advantages: renaming and pin selection are automated.
- Disadvantages: template files become package data and a new console script becomes public contract, for a task performed once per product.

### Worker composition

#### Option X — Document "write your own worker entrypoint"
- Advantages: no code change.
- Disadvantages: every product copies security-relevant startup code (the role guard, the fail-closed startup order) and owns keeping it correct.

#### Option Y — Optional `extra_functions` / `extra_cron_jobs` parameters on `api.worker.build_production_worker()` and `api.worker.main()`
- Advantages: one entrypoint for every product; additive, so `python -m api.worker` and every existing caller are unchanged; the dependency direction holds (the product imports `api.worker`, `api` imports no product).
- Disadvantages: arq keys functions by name, so an extra could replace a platform job unless that is refused explicitly.

## Recommendation

Option A and Option Y.

## Decision

1. **The scaffold is `examples/consumer-scaffold/`.** It is not in `[tool.setuptools] packages`, not in `[tool.importlinter] root_packages`, and never imported by SaaS OS. It is a copy-once starting point (ADR-0015 rules 9–10), validated end to end by `tests/test_consumer_scaffold_integration.py` from an isolated install outside the repository. Options B and C stay open; nothing here prevents either later, and either would be generated from this directory.
2. **`examples/reference-consumer/` keeps its ADR-0018 role** as the architecture-validation fixture. The two are not merged: the fixture exists to prove boundaries and may grow adversarial scenarios; the scaffold exists to be copied and stays minimal.
3. **`saas_os.api.worker.build_production_worker()` and `saas_os.api.worker.main()` accept `extra_functions` and `extra_cron_jobs`.** Both default to empty. An extra is refused, with `JobsConfigurationError` at startup, when:
   - it is not an arq `Function` built by `saas_os.infra.jobs.register_tenant_job` / `register_system_job`, or a `CronJob` built from one by `system_cron`. The check is `saas_os.infra.jobs.queue.is_registered_job`, which compares the identity of the wrapped coroutine, not the name: a raw arq function reusing a registered name is refused, because it would run without the typed-context check, retry policy and dead-letter wrapper of ADR-0030;
   - its name equals a platform job's or platform cron job's name, or any other extra's. Jobs and cron jobs share one name space, as they do inside arq, so a scheduled job is passed as a cron job only.
   The role guard still runs before the worker is built. This guard protects against mistakes in a product's own worker module; it is not a privilege boundary, since that module runs in the product's own process.
4. **`docs/CONSUMER-GUIDE.md` is the integration guide.** Its marked code samples are verified against the scaffold by `tests/test_consumer_scaffold_unit.py`.

## What Would Be Difficult to Change Later

Little. The scaffold is not a dependency of anything; moving or replacing it affects no consumer that already copied it. The two keyword parameters on `api.worker` become public contract once a product's worker module calls them; removing them later would break that module, so they should be treated like `build_platform_app`'s signature.

## Related

ADR-0015 (rules 9–10 and the open scaffold item this resolves in its narrowest form); ADR-0017 (`build_platform_app`, the HTTP-side precedent for the worker seam); ADR-0018 (reference consumer); ADR-0030 (typed jobs, the reason unregistered extras are refused); ADR-0038 (a namespace change would rewrite the scaffold's imports); `docs/CONSUMER-GUIDE.md`; `docs/P-ROADMAP.md` P3.
