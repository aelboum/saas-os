# ADR-0051: Audit table immutability

Status: Accepted (2026-10-15) — the repository owner authorized the recommended production hardening of the deferred ADR-0045 items. Partly implemented: see "Not decided here".
Date: 2026-10-15
Supersedes / Superseded by: — (decides ADR-0045's deferred "trigger-based immutability and tamper evidence for the audit tables")
Related: ADR-0031 (same-transaction audit), ADR-0045 (platform audit; section 9), `2e7cb8c64903` and `c4a9e1f07b52` (the privilege revocations).

## Context

`core.audit_log` and `core.platform_audit_log` are evidence. The migrations that create them revoke `UPDATE` and `DELETE` from the application role, and the schema's default privileges never grant `TRUNCATE`, so the running application can only append. ADR-0045 deferred two further controls: a trigger refusing `UPDATE` and `DELETE` for every role, and tamper evidence.

Facts:

- The roles that can change these rows anyway are the table owner (the migrations role) and superusers. Either can drop or disable a trigger, so a trigger does not bind them; it only stops accidents made with them.
- This repository's own integration tests remove their audit rows with the migrations role (more than 300 cleanup statements). A trigger for every role would need a bypass for them, and any bypass a test can use, an owner can use.
- Tamper evidence against an owner needs a copy outside the database the owner controls: an external, append-only log store, or digests anchored outside it.

## Decision

1. **The runtime role stays append-only, and that is tested.** `tests/infra/db/test_audit_tables_append_only_integration.py` asks PostgreSQL which privileges the application role holds on both tables — exactly `SELECT` and `INSERT` — and tries `UPDATE`, `DELETE` and `TRUNCATE` as that role, each refused. A migration that granted one of them back now fails the suite.
2. **No trigger.** It would not bind the roles it is meant for, and it would need a bypass that defeats it.
3. **Tamper evidence is a deployment control.** Retain database backups (already required, `docs/BACKUP-RESTORE.md`) and restrict the migrations role and superuser access to tier-0 holders (`docs/RUNBOOKS.md`, "Who holds what"). Detecting a change made by such a holder needs an external copy, which is not built here.

## Not decided here

- An external, append-only copy of audit records (shipping each committed row to a log store, or periodic digests of settled windows recorded outside the database). It needs the deployment's log infrastructure, which ADR-0009 leaves to the operator. Recorded in the roadmap ledger.
