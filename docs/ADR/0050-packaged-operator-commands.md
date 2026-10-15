# ADR-0050: Packaged operator commands

Status: Accepted (2026-10-15) and implemented — the repository owner authorized the recommended production hardening of the deferred ADR-0045 items.
Date: 2026-10-15
Supersedes / Superseded by: — (decides ADR-0045's deferred "packaged operator commands for purge, erasure, move and delete")
Related: ADR-0045 (platform authority; sections 6, 7 and 12), RA-12-3 (identity erasure behind an import fence), PRIV-03 (tenant purge).

## Context

Four platform operations are never routes: marking a tenant deleted, moving a tenant, purging a deleted tenant, and erasing a user's identity data. ADR-0045 gave each a Core function with a required caller and audit evidence, and left them as Python calls an operator makes by hand. Where a packaged command lives was a layering question: `saas_os.api` is forbidden to import the erasure module, and Infrastructure may not import Core.

## Decision

1. **A new top-level package, `saas_os.ops`, holds operator entry points.** It may import Core and Infrastructure. Nothing imports it: a new import-linter contract forbids `saas_os.ops` to the API, Core, Infrastructure, Contracts, the AI Control Plane and products, so no request path can reach the purge authority or erasure through it.
2. **One console script, `saas-os-operator`, with four subcommands**, each exactly one Core call with the caller Core requires:
   - `delete-tenant`: `transition_tenant_status(..., DELETED, caller=UserCaller(<operator>))` — `platform.tenant:delete`.
   - `move-tenant`: `move_tenant(..., caller=UserCaller(<operator>))` — `platform.tenant:move`.
   - `purge-tenant`: `purge_tenant(..., caller=SystemCaller(TENANT_PURGE), actor_user_id=<actor>)`.
   - `erase-user`: `erase_user_identity(<user>, <tenants>, actor_user_id=<actor>)`.
   The command decides nothing; Core authorizes and audits.
3. **Guards.** `delete-tenant`, `purge-tenant` and `erase-user` require `--confirm` repeating the target's id. `ENVIRONMENT=production` requires `--confirm-production`. The command runs as the restricted application role (`validate_application_role`).
4. **Product data in a purge.** A purge removes product rows only through participants registered in the purging process. `purge-tenant` requires `--setup module:function` (called first, for example the product's `create_app`) or an explicit `--no-product-participants`, and refuses without one of them.
5. **Output.** One JSON object with the Core result; on failure, only the exception's type. Exit codes 0, 1 (refused or failed), 2 (usage).

## Consequences

- Operators no longer write Python to run these operations, and every run goes through the same authorization and evidence as before.
- It is not a security boundary against the person running it: whoever can run it holds the application role's credentials (tier 0, as for the platform bootstrap command).
- Operator identity for `delete-tenant` and `move-tenant` is a user id given on the command line; Core checks that this user is an active operator with the permission. SaaS OS cannot know who is at the keyboard; `--reason` should carry the ticket reference.

## Implementation

`saas_os/ops/operator_cli.py`; `pyproject.toml` (package, `saas-os-operator` script, contract "Operator commands are imported by nothing"); `tests/architecture/test_authority_contract.py` (the reviewed `SystemCaller` site); `tests/ops/test_operator_cli_unit.py` (each command's exact Core call, every input guard, production confirmation, error output); `tests/core/platform_authority/test_operator_cli_integration.py` (delete then purge, a refused operator, an open tenant not purged, move, erase, an enrolled operator not erased); `docs/RUNBOOKS.md`, "Operator commands".
