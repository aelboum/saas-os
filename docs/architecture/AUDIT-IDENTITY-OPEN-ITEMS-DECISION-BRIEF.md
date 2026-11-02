# Audit identity retention: decision brief for open items O2, O4, O8, O9, O10 and O11

**Status: Decision brief; nothing decided; nothing implemented.** Date: 2026-11-02. This brief informs owner decisions on six open items of `docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md` (the proposal, section 10). Each item's question is taken from its definition there; nothing below is inferred from the numbering, and every recommendation is a proposal for the owner, labelled as such. No schema, code, grant or runtime behaviour changes with this document. SQL mentioned here has not been run against PostgreSQL.

Context the items share: the owner decided D1–D8 and O1 on 2026-11-02 (proposal, sections 4.1 and 6). PR #198 (`feat/permission-grant-migrations`, not merged) contains `docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md`, an authenticated retention API for the permission grant ledger: routes for holds, a deletion request, an approval and an execution authorisation on the platform-admin router, with ledger deletion disabled until it is built. That API is **approved for further design only, not for implementation** (owner, 2026-11-02). PR #198's decision 13 is **decided: option A** (owner, 2026-11-02, recorded on PR #198 at `cca1a83`): eligibility to approve or authorise execution comes only from an out-of-band, independent approver eligibility register. Each entry rests on an out-of-band verification that the person is a distinct natural person and on the authorisation of a designated organisation representative other than the platform owner; the register is append-only and reviewable; eligibility is checked at approval time (and, in PR #198's design, again at execution authorisation and execution); accounts with blank provenance and break-glass or bootstrap accounts are not automatically eligible. Its strength is procedural (PR #198, section 4.5). Read on PR #198's branch at `cca1a83`. Where this brief depends on that design, it says so; it assumes no other decision of PR #198.

Facts verified on this branch (`feat/system-actor-step1`):

- Platform permissions: 24 values in `PlatformPermission` (`saas_os/core/platform_authority/permissions.py`), mirrored by the database CHECK `ck_platform_grants_permission` (`saas_os/infra/db/migrations/versions/c4a9e1f07b52_create_platform_authority_tables.py`); `BOOTSTRAP_PERMISSIONS` and the empty `NOT_GRANTED_AT_BOOTSTRAP` in `saas_os/api/platform_bootstrap.py`. PR #198 adds four, to 28.
- The only authenticated operator channel is the platform-admin router (`saas_os/api/platform_admin/router.py`) behind `require_platform_permission` (`saas_os/api/dependencies.py`). Operator commands take declared ids (`saas_os/ops/operator_cli.py`).
- No `SECURITY DEFINER` and no `BYPASSRLS` anywhere (stated in `saas_os/core/audit_digest/service.py`, `saas_os/core/usage/service.py` and migration `5964e254eeb6`). One precedent for a second database role: the platform-configuration role of ADR-0056 (`platform_config_session_scope`, chosen in `saas_os/core/platform_authority/transactions.py:_open` for `PLATFORM_CONFIGURATION_OPERATIONS`), guarded by `tests/architecture/test_platform_config_boundary.py`.

## O2. Classification of operator-enrollment and enrolled-operator erasure targets

**Definition (proposal, section 10):** "Confirm that operator-enrollment targets and the refused-erasure target of an enrolled operator count as operators' own identities (out of scope under D6)."

**Design question.** D6 puts target users of platform audit records in the first scope and leaves operators' own identities out. Two kinds of platform row name a person who is, or is about to become, an operator. Are their user ids "operators' own identities" (kept raw, under the separate operator-retention policy) or "target users" (replaced by references in P1)?

**Existing constraints.**
- `enroll_operator` (`saas_os/core/platform_authority/service.py`) runs through `_run(OPERATOR_ENROLL, caller, target_type=_TARGET_USER, target_id=str(user_id), ...)`, which writes the attempt and refusal rows with the user id as target. The success row from `enroll_in_transaction` has `target_type = 'operator'` (`_TARGET_OPERATOR`, the operator id) and metadata `{"user_id": ...}`.
- The refused erasure of an enrolled operator (`remove_identity_links_unless_enrolled_operator`, `saas_os/core/identity/user_authority.py`; `EnrolledOperatorErasureError`) writes a platform row with `target_type = 'user'`.
- `core.platform_operators` itself stores the operator's `user_id`; a reference in the audit row does not hide who an operator is from anyone who can read that table.

**Options.**
- **A. All out of scope** (the proposal's reading). Simple; matches "operators' own identities". A refused or failed enrollment of someone who never became an operator keeps that person's raw id indefinitely.
- **B. All in scope.** Every `target_type = 'user'` row gets a reference. Little privacy gain for actual operators (their id is in `core.platform_operators` and in the success row's metadata), and it pulls operator identity into the target-user mechanism D6 kept apart.
- **C. Split by outcome.** Rows about a person who **is** an operator (successful enrollment, the refused erasure of an enrolled operator) are out of scope; rows whose target never became an operator (refused or failed enrollment attempts) are in scope as target users.

**Security and privacy.** A keeps an ordinary user's id in failed-enrollment rows; B weakens the accountability record of operator lifecycle without real privacy gain; C protects the non-operator while keeping operator accountability intact.

**Recommendation (proposal):** C. It follows D6's purpose (protect target users, keep operator accountability) rather than the row's `target_type`.

**Migration and compatibility.** None until P1. Under C, the P1 call sites for `platform_audit_subject_ref` include the enrollment attempt and refusal paths when the outcome is not success; `list_platform_audit(target_type="user", ...)` stops finding those rows once they carry `user_subject`.

**Tests and evidence.** A unit test that enumerates every platform operation and the target type it records, pinned so a new operation must be classified; integration tests for a refused enrollment (reference recorded) and for a successful enrollment and an enrolled-operator erasure refusal (raw id recorded, as the separate operator policy requires).

## O4. Permission for the lookup routes

**Definition (proposal, section 10):** "Permission for the lookup routes. Options: (i) `platform.user:read` ...; (ii) `platform.audit:read` ...; (iii) a dedicated permission such as `platform.audit_subject:resolve`, withheld at bootstrap like PR #198's hold permission."

**Design question.** Which platform permission must an authenticated operator hold to resolve a reference to a user, or list a user's references (proposal, section 4.5; D3)?

**Existing constraints.** `PlatformPermission` and `ck_platform_grants_permission` must agree, so a new permission needs a migration that rewrites the CHECK. Bootstrap grants every permission in `BOOTSTRAP_PERMISSIONS` to the first owner unless it is in `NOT_GRANTED_AT_BOOTSTRAP`. `platform.user:read` (`PlatformPermission.USER_READ`) already authorises `resolve_user` (`saas_os/core/identity/user_authority.py`); `platform.audit:read` authorises `list_platform_audit` (`saas_os/core/platform_authority/oversight.py`). In the retention work the owner has stated a preference against new runtime permissions (PR #198, rule 4: "no new permission"; the vocabulary stays at 28 there, and its approval chain reuses `platform.security_retention:report` with eligibility coming from the register, not from a permission). Whether that preference extends to this mechanism is not recorded.

**Options.**
- **(i) `platform.user:read`.** No new permission. Whoever can look users up can re-identify every audit reference, so the mechanism adds an audit trail but no separation.
- **(ii) `platform.audit:read`.** No new permission. Whoever can read platform audit can also re-identify it, which makes references nearly pointless for that audience; for tenant scope it extends platform audit authority into tenant data, which ADR-0045 keeps apart.
- **(iii) A dedicated permission** (for example `platform.audit_subject:resolve`), in `NOT_GRANTED_AT_BOOTSTRAP`, granted only out of band. Least privilege; re-identification becomes a separately granted, separately audited capability.
- **(iv) No new permission; eligibility from the register.** Use an existing permission (for example PR #198's `platform.security_retention:report`, or `platform.audit:read`) **and** require an active entry in PR #198's approver eligibility register (decision 13, option A, decided), checked at lookup time, exactly as PR #198 separates approval from its permission. Trade-off: no permission is added and re-identification is limited to independently verified persons, with the register's review and append-only history; but the gate is procedural (out-of-band verification, representative, custodian), the lookup then depends on PR #198's register being implemented (not yet approved for implementation), and the register's purpose (approving deletions) is widened to re-identification, which its designation and review procedures would have to cover.

**Security and privacy.** With (i) or (ii) the bootstrap owner and every reader can re-identify. With (iii) re-identification needs a deliberate grant, and every grant has its own platform audit row. Distinct accounts are still not distinct humans (PR #198, threat T4a).

**Recommendation (proposal):** (iii), withheld at bootstrap, because a separately granted capability is the simplest way for references to protect against the people who can already read audit records. **This recommendation conflicts with the owner's stated preference against new runtime permissions in the retention work** (above). If that preference applies here, (iv) is the alternative that respects it: it gives comparable or stronger person-level control through the decided register, at the cost of a procedural gate, a dependency on PR #198's unimplemented register, and a widened register purpose. (i) and (ii) respect the preference but give no separation. The owner decides; this brief does not.

**Migration and compatibility.** (iii): one enum value, a migration rewriting `ck_platform_grants_permission` (an `ALTER TABLE ... DROP/ADD CONSTRAINT` on `core.platform_grants`, lock level to review), the public API snapshot (`tests/architecture/public_api_snapshot.txt`), bootstrap tests and the ADR-0045 permission table. If PR #198 merges first, its migration order applies. (iv): no permission migration; depends on PR #198's register table and its eligibility check. (i) and (ii): no migration.

**Tests and evidence.** Route tests: refused without the permission (refusal row recorded), allowed with it; bootstrap test that the owner does not receive it; grant test through `recover --grant`; negative control: route declared with the wrong permission makes the refusal test fail.

## O8. Entry point for hold placement and release

**Definition (proposal, section 10):** "Entry point for hold placement and release: operator command (declared operator) or the authenticated API (PR #198's proposal)."

**Design question.** Are audit-identity legal holds (proposal, section 4.9) placed and released through an operator command with a declared operator id, through the authenticated platform-admin API, or both?

**Existing constraints.** There is no hold concept on this branch. Operator commands take a declared `--operator` (`saas_os/ops/operator_cli.py`). A person-scoped hold names references, which only the authenticated list route can return (proposal, section 4.5), so placing one already requires the API. PR #198's design (decision 3) proposes keeping a command for placing ledger holds and retiring the command for releasing them.

**Options.**
- **A. Operator command only.** Available without HTTP; the operator is declared, so a release cannot be attributed and O9's rule cannot be checked.
- **B. Authenticated API only.** Releases are attributable; no emergency path when HTTP is down or not enabled (`PLATFORM_ADMIN_HTTP_ENABLED`).
- **C. API for both, plus a command that can only place holds.** Placing a hold errs towards retention and is safe under a declared id; releasing is the step that can lead to deletion and is API only.

**Security and privacy.** Releases are the dangerous direction (they make identification removable); placements are conservative. C keeps every release authenticated. A release recorded under a declared id should block expiry in its scope, as PR #198's decision 2 option A proposes for the ledger.

**Recommendation (proposal):** C, aligned with PR #198's decision 3, and with any declared-id release (if a release command ever exists) blocking expiry for its scope.

**Dependencies.** PR #198's authenticated retention API (approved for further design only, not implementation, at `cca1a83`); hold routes here would follow its route, schema and refusal conventions. Releases there are authenticated, and approvals after a release require register-eligible persons (decision 13, option A, decided). O4 or a hold-specific permission (PR #198 uses `platform.security_retention_hold:manage`; reusing it here is a further option for the owner).

**Migration and compatibility.** The hold tables of proposal section 4.9 (new, additive) and new routes in the ADR-0045 route table. No existing behaviour changes.

**Tests and evidence.** Route tests for place, release and list with session identity only (no identity field in bodies, extra fields refused); the one-way release trigger; command test that it can place but has no release subcommand; negative control: an unauthenticated release path makes the attribution test fail.

## O9. Separation of duties for the expiry command

**Definition (proposal, section 10):** "Whether PR #198's separation-of-duties rule (a hold releaser must not authorise deletion alone) applies to this expiry; if yes, `--apply` stays disabled until an authenticated approval exists."

**Design question.** D7 decided a migrations-role command with dry run and explicit confirmation. Must deletion of audit identity links also satisfy the owner's rule from PR #198, which needs authenticated, person-distinct request, approval and execution authorisation?

**Existing constraints.** The expiry command's `--operator` would be declared (proposal, section 4.10). PR #198 disabled ledger deletion (`_DELETION_ENABLED = False`, `LedgerDeletionDisabledError`, on that branch) because the rule cannot be checked over declared ids. Link deletion is irreversible: a deleted link cannot be restored except from a backup.

**Options.**
- **A. Apply the rule.** The command's `--apply` stays disabled until the authenticated request, approval and execution authorisation exist for this mechanism (reusing PR #198's design and tables, generalised, or parallel ones). Under decision 13, option A (decided), the approver and the execution authoriser must each hold an active entry in the approver eligibility register and be different verified persons. Dry run and report job work from P2.
- **B. Do not apply it.** D7 as written: a person with the migrations credential confirms rows, digest and hold set. Anyone holding that credential can release a hold (if releases are not API only, O8) and delete alone.
- **C. Apply it only where a hold was released in scope.** Scopes with no released hold may be expired by the D7 command; scopes with a release need the authenticated approval. Smaller, but adds a second path to test and reason about.

**Security and privacy.** A gives the strongest control over irreversible removal but delays it; B removes identification on time but lets one credential holder override a released hold's intent; C confines the gap to scopes with no hold history.

**Timing.** The first link can expire no earlier than two years and two days after P1 ships (proposal, section 4.8), so A's delay has at least two years to be closed.

**Recommendation (proposal):** A, consistent with PR #198 and because removal of identification cannot be undone; build the approval, and reuse the decided eligibility register, once for both mechanisms. A needs at least two independently verified natural persons enrolled in the register before any link can be deleted. Until it exists, links are retained beyond two years, which errs towards retention and must be stated in the privacy notice.

**Dependencies.** PR #198's authenticated retention API (approved for further design only, not implementation) and its approver eligibility register (decision 13, option A, decided), both read at `cca1a83`; O8 (authenticated releases are what the rule compares).

**Migration and compatibility.** Under A: approval and authorisation tables and the eligibility register (PR #198, sections 4.5 and 5.5, or generalised equivalents) and a gate constant in the expiry module like `_DELETION_ENABLED`. Under B: none beyond the proposal.

**Tests and evidence.** Under A: the gate refuses `--apply` before connecting; with the approval built, refusal when the approver released a hold in scope, when approval and execution are by the same account, and on expired or consumed approvals; negative controls removing each rule. Under B: confirmation-mismatch refusals.

## O10. Lifetime of erasure markers

**Definition (proposal, section 10):** "Whether erasure markers expire after two years (a later record about the user then gets a live link, section 4.8) or are kept as long as `core.users.id` exists (the marker then holds a user id indefinitely)."

**Design question.** `core.audit_subject_erasures` and `core.platform_audit_subject_erasures` store the erased user's id so that later audit writes issue unlinkable references (proposal, sections 4.4 and 4.6). Do markers expire two years after `erased_at` (once no held live link remains), or live as long as the user row?

**Existing constraints.** `erase_user_identity()` (`saas_os/core/identity/erasure.py`) keeps `core.users.id` forever and leaves audit rows unchanged; the erasure audit rows already carry `resource_id = str(user_id)` and are `SECURITY_RETAIN`. A `core.users` row can still be the target of platform operations after erasure.

**Options.**
- **A. Expire after two years** (the proposal's design). After expiry, a new audit record about the user gets a live link; it identifies only that new record, which has its own two years. Old references stay unresolvable.
- **B. Keep as long as `core.users.id` exists.** Every later record about an erased user stays unlinkable. The marker itself is a raw user id kept indefinitely, next to erasure audit rows that already hold the same id.
- **C. Replace the marker by an "erased" state on `core.users`.** No separate id store; but it changes the identity schema and every reader of `core.users`, beyond this mechanism's scope.

**Security and privacy.** A stores the id for a bounded time and lets future records be identified normally, which is consistent with treating them as new records. B prevents any new identification of an erased user, at the cost of an indefinite identifier in one more table (the erasure audit rows already keep it indefinitely under D5 and the O1 exception). C is the cleanest model but the largest change.

**Recommendation (proposal):** A, with the consequence stated in the privacy notice. A later audit record after two years is a new act with its own retention, and A adds no indefinite identifier.

**Migration and compatibility.** A and B: none beyond the marker tables. C: an identity schema change and a separate decision.

**Tests and evidence.** Under A: after marker expiry, a write creates a live link, and old references stay unresolvable; a held live link prevents marker expiry. Under B: no write ever creates a live link after erasure.

## O11. Database enforcement of resolution

**Definition (proposal, section 10):** "Whether resolution must be enforced by the database rather than by the API and code discipline: a separate role owning the link tables, or a `SECURITY DEFINER` lookup function. Both depart from the current single-application-role, no-`SECURITY DEFINER` model and need an ADR."

**Design question.** The application role has `SELECT` on the link tables (proposal, section 4.3), so any application-role code can resolve a reference in a tenant-bound session. Must the database prevent that?

**Existing constraints.**
- Get-or-create must run in the audit write's own transaction (ADR-0031; proposal, section 4.7), on the application role's connection. A separate role means a separate connection and therefore cannot take part in that transaction.
- No `SECURITY DEFINER` exists in the codebase; the ADR-0056 platform-configuration role is the one precedent for a second role, with its own session factory and an architecture test.
- Application-role code can already read `core.users`, every `actor_user_id` (O1 exception) and the raw ids listed as outstanding risk in proposal section 4.1. Any database boundary on links protects only references, not those.
- Whether `INSERT ... ON CONFLICT DO NOTHING RETURNING` works without `SELECT` on the table is a PostgreSQL privilege question that has not been checked.

**Options.**
- **A. API and code discipline** (the proposal's design), plus an architecture test that only the get-or-create, lookup, erasure and expiry modules import the link-table models or name the tables, in the style of `tests/architecture/test_tenant_session_boundary.py`.
- **B. `SECURITY DEFINER` get-or-create function** executable by the application role, returning only the reference, with no `SELECT` granted on the link tables; resolution through a separate lookup role used only by the API path (its own session factory, like ADR-0056). Get-or-create stays in the audit transaction; resolution evidence uses the attempt-row pattern across two connections.
- **C. Separate role only, no definer function.** Not compatible with ADR-0031 for get-or-create (different connection), so it fails the same-transaction requirement.

**Security and privacy.** A leaves resolution open to compromised or careless application code, which however already has access to many raw ids. B closes resolution to application code but adds a definer function (search path pinning, owner privileges, RLS under `FORCE` for the owner), a role and a connection pool, and needs an ADR amending the no-`SECURITY DEFINER` stance. C is not viable.

**Recommendation (proposal):** A for P1 and P2, with the architecture test and the residual risk recorded; reconsider B before P3 (tenant scope), when references would protect the largest data set, and only once the raw ids of proposal section 4.1 are reduced enough for a database boundary to matter.

**Migration and compatibility.** A: grants as in proposal section 4.3; one architecture test. B: a function and role migration, a new role in the deployment's database setup scripts (like `saas_os/infra/db/init/02-create-platform-config-role.sh`), new configuration for its URL, and an ADR.

**Tests and evidence.** A: the architecture test with a negative control (a module outside the allowlist that names the table fails it). B: privilege tests that the application role cannot `SELECT` the link tables, that the definer function sets `search_path` and respects RLS, and that the lookup role cannot write audit rows.

## Dependencies at a glance

| Item | Depends on |
|---|---|
| O2 | D6; nothing external |
| O4 | ADR-0045 permission table; PR #198 migration order if it merges first; for option (iv), PR #198's eligibility register (decision 13, option A, decided) |
| O8 | PR #198's authenticated retention API (approved for further design only); O4 or a hold permission |
| O9 | PR #198's approval design and its eligibility register (decision 13, option A, decided); O8 |
| O10 | None external |
| O11 | ADR-0031 and ADR-0056 precedent; an ADR if option B |
