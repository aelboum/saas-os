# Raw user identifiers stored by SaaS OS: inventory and phased privacy remediation

**Status: Inventory and remediation design. Everything is a proposal, except phase P6.1 (the `invited_email` erasure step, OP-6), which is implemented (2026-11-04, owner authorisation "Apply invited_email erasure fix"; section 6.1). The remaining phases in section 9 are proposals; each needs separate implementation approval, and the later phases need owner decisions that have not been taken.** The inventory was verified against the code of branch `feat/system-actor-step1` at `1e9e215`. The last code change on that branch is `e148526`; everything after it is documentation. The classifications follow the owner's decisions OD-1, OD-2 and OD-3 of 2026-11-03 (final closure); section 2 lists what they changed. Owner decisions referred to here are recorded in `docs/architecture/AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md` (the decision record), and the reference mechanism is designed in `docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md` (the proposal). Date: 2026-11-03.

## 1. Scope and method

**What counts.** A *raw user identifier* is a `core.users.id` value stored in PostgreSQL in clear, as a column value, a JSON value or a string. Stored beside it are direct identifiers of a person: e-mail addresses and an external identity's `(issuer, subject)`. These are listed too. Some ids are *indirect*: an operator id or an operator's session id resolves to a user through a table that the same readers can join. Indirect ids are listed and marked as such. Membership, API-key, service-account and grant ids are not listed: they name records, not people, although some of those records name a user in turn.

**Where it was searched** (branch `feat/system-actor-step1`, `saas_os/` only):

- **ORM models.** Every `Mapped[...]` column whose name contains `user_id`, `principal_id`, `email`, `subject`, `issuer`, `operator_id`, `by_user` or `actor`.
- **Migrations.** Every `sa.Column` with such a name, and every foreign key to `core.users.id`: 36 foreign-key columns, 2 of them in the audit tables.
- **Audit writers.** An AST scan of `saas_os/` (outside the migrations) for calls to the audit writers found 78 tenant-writer calls and 51 platform-writer calls, wrappers included:
  - tenant: `record`, `record_audit_event` (the alias of `record`), `record_in_transaction`, `record_system_action_in_transaction`;
  - platform: `record_platform_event_in_transaction`, `record_platform_refusal`, `recording_platform_refusal`, `record_oversight_attempt`, `record_operator_session_issued_in_transaction`, `record_platform`.

  Each call's `actor_user_id`, `caller`, `resource_id`, `target_type`, `target_id` and literal metadata keys were inspected. Metadata built elsewhere was followed to its builder: `_owner_metadata`, `record_platform_key_revocations`, `audit_note`, `_page_metadata`, and the purge's `attribution`.
- **String searches.** Dictionary keys containing `user`, `principal`, `operator`, `actor`, `email`, `subject`, `requester`, `requested_by`, `approver`, `proposer`, `owner`, `_by`, `recipient`, `inviter`, `delegat`, `enrolled`, `granted`, `revoked` or `initiat`, and every `str(<...user_id...>)` conversion.
- **Outbox producers.** Every `append_event` producer: notifications, billing projections, usage and webhooks. Every platform `target_type` value.

**How digest coverage was established.** From the code, not assumed. ADR-0053 digests serialize exactly the columns listed in `AUDIT_LOG_COLUMNS` and `PLATFORM_AUDIT_LOG_COLUMNS` (`saas_os/core/audit_digest/service.py:71-101`), reading `metadata` as its stored text (`_selected`, `:205`). No other table is digested (`saas_os/core/platform_authority/digest_source.py` reads only `core.platform_audit_log`). A field "in the digest" therefore cannot be changed in place without the verifier reporting `audit_log_changed`. That is why D5 keeps existing rows unchanged.

**Not covered here.**
- Product tables and product metadata or payload keys: Core cannot detect a user id in them (O5, decided 2026-11-03: product responsibility).
- Tables added by PR #198 and by the retention-API and register PR stacked on it: they are not on this branch.
- Data outside PostgreSQL, which section 7 lists without counting.

**Roles used below.**
- **Actor**: who performed the recorded act.
- **Initiator**: who originally requested an act that something else performed.
- **Target**: whom the act was about.
- **Resource owner**: whose resource the act touched.
- **Related party**: a person named for evidence, such as the proposer in an approval row.
- **Operator self**: an operator's own identity (D6).
- **Contact or identity data**: an e-mail address, or an external `(issuer, subject)`.

**Policy references.**
- The owner's policy of 2026-11-02 (two years from creation, legal hold, controlled removal) covers **completed audit records**: the `initiated_by` user id "and analogous user ids in audit metadata".
- D2 and O1 gate only `initiated_by`. D6 puts only the target users of platform audit records into the first phase.
- No retention requirement has been decided for the outbox or the operational tables. `docs/DATA-ARCHITECTURE.md` section 8 defers formal retention until a compliance target is chosen.

## 2. Summary

| Category | Entries | Direct user ids | Indirect | Contact or identity data | Free text | Not enumerable |
|---|---|---|---|---|---|---|
| Tenant audit, `core.audit_log` (section 3) | 7 | 6 (TA-1 to TA-6) | – | – | – | 1 (TA-7, product keys) |
| Platform audit, `core.platform_audit_log` (section 4) | 10 | 6 (PA-1 to PA-6; PA-6 has no Core writer) | 3 (PA-7 to PA-9) | – | 1 (PA-10) | – |
| Outbox, `core.outbox_events` (section 5) | 5 | 3 (OB-1 to OB-3) | – | 1 (OB-4, encrypted) | – | 1 (OB-5, product payloads) |
| Operational tables (section 6) | 39 | 36 | – | 3 (OP-3, OP-5, OP-6) | – | – |
| **Total** | **61** | **51** | **3** | **4** | **1** | **2** |

OP-3 (`subject`) is counted under contact or identity data together with its `issuer`, which is not separately numbered. Of the 61 entries:
- **Decided scope (4 entries, one of them in part):** TA-3 (gated by D2, then tenant references in P3); PA-2 (D6, P1, every user target, operators included, OD-2); PA-3 (D6, P1: the user behind the target operator, OD-2); and TA-5's platform-marked rows (OD-3: tenant references, with the tenant tables). PA-6 is covered by the D2 gate extension in PR #201.
- **Temporary exception:** TA-1 and PA-1, actors (O1). Under OD-1, the exclusion of operators' own identities covers an actor who is an actual operator; a declared actor id is still the O1 exception, but not an operator identity.
- **Excluded by D6 as operator self (actor role, OD-1 and OD-2):** PA-4, PA-8's `operator_id` and PA-9.
- **Targets that are not user ids (OD-2):** PA-7 and PA-8's `previous_operator_id`. They identify the target operator only through `core.platform_operators.user_id` (OP-19), so they stop identifying the person only when OP-19 does (P6).
- **Not yet decided:** every other entry is an outstanding risk or outside the audit policy, and needs a decision before it can be remediated (section 9).

**What OD-1 to OD-3 changed (2026-11-03, final closure).**

| Field | Before | After |
|---|---|---|
| PA-2 rows whose target is an enrolled or revoked operator (`user_authority.py:299` erasure refusal, a refused enrolment naming the caller, user operations on an operator) | Raw (operator target, O2) | Platform reference, `target_type = 'user_subject'` (OD-2) |
| PA-3 `metadata["user_id"]` of operator events | Operator self, excluded (D6) | Target user: platform reference under `user_subject_ref`, P1 (OD-2) |
| PA-7 `target_id` with `target_type = 'platform_operator'`; PA-8 `previous_operator_id` | Operator self, excluded (D6) | Target, indirect (OD-2); not a user id, so kept; linkable through OP-19 |
| PA-1 rows and PA-5 with a declared, unauthenticated actor | Operator self, or "depends on whether the runner is an operator" | Not an actual operator (OD-1): an actor id under the O1 exception (PA-1) or an outstanding actor risk (PA-5), P5 |
| TA-5 platform-marked rows | Open (OD-3) | Target-user reference treatment: tenant reference `owner_user_subject_ref` with the tenant tables (OD-3) |
| PA-4, PA-8 `operator_id`, PA-9 | Operator self | Unchanged: they name the acting operator (actor role) |

## 3. Tenant audit records (`core.audit_log`)

Common to every field in this section:

- **Read access.** Tenant row-level security with `FORCE` (`2e7cb8c64903`). Any application-role code in a session bound to the tenant can read the rows: `saas_os.core.audit_log.list()` and `get()` (public API for products, `saas_os/core/audit_log/service.py:575-633`; `list()` filters on `actor_user_id`), and the AI Control Plane modules that read audit. SaaS OS has no HTTP route that returns tenant audit rows; products may expose them.
- **Other copies.** The table owner (the migrations role) and superusers can change rows; ADR-0051 decision 2 sets no trigger. Backups hold every row (`BACKUP_RETENTION_COUNT`, default 7).
- **Writes.** The application role cannot update or delete rows (`REVOKE UPDATE, DELETE`, `2e7cb8c64903`).
- **Retention.** `SECURITY_RETAIN` (`saas_os/core/tenancy/retention.py:76`). There is no time-based expiry. Tenant purge and `erase_user_identity()` never change audit rows.
- **Digest.** All of `actor_user_id`, `resource_id` and `metadata` (as stored text) are in `AUDIT_LOG_COLUMNS`.
- **Requirement.** The owner's two-year policy applies to user identification in these records. The existing rows are the D5 legacy exception and are never rewritten in this phase.

### TA-1 `core.audit_log.actor_user_id` (column)

- **Writers.** `record()` (`saas_os/core/audit_log/service.py:214`, explicit `actor_user_id`) and `record_in_transaction()` (`:315`, through `_caller_actor`, `:396-399`, for a `UserCaller`); the row is built in `_validated_entry` (`:558`). These are reached by every tenant writer call made for a person.
  - **Declared ids.** Some ids are declared on a command line, not authenticated: `erase-user --actor` (`saas_os/core/identity/erasure.py:218`, `:241`, `:260`) and `purge-tenant --actor` (`saas_os/core/tenancy/service.py:1100`).
  - **Operator ids.** Platform operations write rows in the tenant's trail naming the **operator** as actor: `record_platform_key_revocations` (`saas_os/core/api_keys/service.py:860`), outbox replay (`saas_os/core/outbox/replay.py:167`), feature-flag overrides (`saas_os/core/feature_flags/service.py:384`, `:457`) and lifecycle rows (`saas_os/core/tenancy/authority.py:216`). Under OD-1 such an actor is an actual operator when the operation was authenticated (a platform-admin route), and not when the id was declared on a command line.
- **Purpose and role.** Actor; on platform-marked rows, the operator acting in the tenant (operator self).
- **Constraints.** FK to `core.users`. `ck_audit_log_actor_type_user_id_pairing` (`saas_os/core/audit_log/models.py:181-189`) requires the column for `actor_type = 'user'`. Indexed by `ix_audit_log_tenant_actor`.
- **Decision.** O1: a temporary exception. **D2 gate: no**, because it records who performed the act, not who requested it. Refusing it would leave user actions unaudited (ADR-0031), and the CHECK requires it.
- **Migration strategy (phase P5).** A new nullable `actor_subject_ref` column; the pairing CHECK relaxed to accept a user actor with a reference instead of an id; the FK and the column kept for legacy rows; an index on `(tenant_id, actor_subject_ref)`.
  - **Digest.** The new column is a digest format change: `RECORD_FORMAT` v2, and a verifier that reads v1 windows unchanged.
  - **Operator actors.** On platform-marked rows the actor is an operator (D6), and operators need their own policy first.
- **Compatibility.** `list(actor_user_id=...)` and every product reader of the column change meaning. This is a public-contract change for products, and the digest format change needs an amendment of ADR-0053.

### TA-2 `core.audit_log.resource_id` when `resource_type = 'user'`

- **Writers.** `saas_os/core/identity/erasure.py:218` (`identity.erasure_outbox_initiators_erased`, `resource_id` at `:224`), `:241` (`identity.erasure_membership_removed`, `:247`) and `:260` (`:266`). `_RESOURCE_TYPE = "user"` (`:135`). These are the only tenant writers with `resource_type = 'user'`.
- **Purpose and role.** Target: the person who was erased. The row is the evidence that this person's membership, keys, notifications and stored initiators were erased in the tenant.
- **Decision.** None. This is an outstanding risk: it is not a target in a *platform* record (D6), and O1 names only `actor_user_id`. **D2 gate: no**, because it is the subject of the erasure, not an initiator, and refusing it would make the erasure unauditable.
- **Note.** D8 keeps erasure evidence to counts precisely because this row names the user.
- **Migration strategy (phase P4; owner decision needed).**
  - (a) Keep it raw as erasure evidence (a documented exception).
  - (b) A tenant reference that is unlinked at once. The row would then no longer prove who was erased, and the case file would have to keep the reference.
  - (c) A keyed hash whose key is kept only in the case file: verifiable by whoever holds the case file, and meaningless otherwise.
  - Recommendation: (a), until the owner decides how erasure proof should work.
- **Compatibility.** Readers of erasure rows, and the runbook's evidence steps (`docs/RUNBOOKS.md`, erase-user).

### TA-3 `core.audit_log.metadata["initiated_by"]` = `{"type": "user", "user_id": ...}`

- **Writers.** `_attribution()` (`saas_os/core/audit_log/service.py:122-140`) through `Initiator.as_metadata()` (`saas_os/core/authority/attribution.py:241`), called by `record_in_transaction()` (for a `SystemCaller` only) and `record_system_action_in_transaction()` (`:411`). No Core path passes a user initiator: one reaches a row only when a product or a test passes `Initiator.user(...)` or the user initiator of `context.initiated_by`.
- **Purpose and role.** Initiator.
- **Decision.** D2 and O1. On this branch the shape is still accepted. PR #201 gates it, and #196 is never merged without #201 (owner, 2026-11-03). Tenant references replace it in P3.
- **D2 gate: yes.** This is the field D2 names.
- **Migration strategy.** P0: no schema change, only the refusal (PR #201). P3: the new shape `{"type": "user", "subject_ref": ...}` and an expression index (proposal, sections 4.4 and 4.8). Legacy rows are the D5 exception.
- **Compatibility.** Consumers must pass `initiated_by=None` for a user initiator while the gate stands (PR #201's guide). `Initiator.from_metadata()` reads both shapes after P3.

### TA-4 `core.audit_log.metadata["user_id"]` (`membership.create`)

- **Writer.** `create_membership` → `record_in_transaction` at `saas_os/core/identity/service.py:385`, key at `:392`.
- **Purpose and role.** Target: the user who received the membership. `resource_id` is the membership id.
- **Decision.** None; an outstanding risk. **D2 gate: no**, because it names whom the act was about, not who requested it. Refusing it would refuse every membership creation.
- **Migration strategy (phase P4; owner decision needed).**
  - (a) A tenant reference under a new key (`user_subject_ref`) after P3.
  - (b) Omit the key: the membership id identifies the user through `core.tenant_memberships` while the membership exists. After erasure deletes the membership, the row would no longer say whose membership it was.
- **Compatibility.** A metadata key change for products that read `membership.create` rows.

### TA-5 `core.audit_log.metadata["owner_user_id"]` (`api_key.revoke`)

- **Writers.**
  - `_revoke_locked_key` → `record_in_transaction` at `saas_os/core/api_keys/service.py:619`, metadata from `_owner_metadata` (`:630-633`; `owner_service_account_id` for a service-account key). This is a revocation inside the tenant.
  - `record_platform_key_revocations` (`:844`) → `:860`, key at `:867`, with `"platform": true`. This writes one row per key revoked by the platform operations `revoke_user_api_keys` and `deactivate_user` (`saas_os/core/identity/user_authority.py`).
- **Purpose and role.** Resource owner: whose key was revoked. On platform-marked rows, it is the **target user of a platform operation**, recorded again in the tenant's trail as dual evidence (ADR-0045 section 8).
- **Decision.** For the tenant-internal rows (revocations by a tenant administrator): none; an outstanding risk. The platform-marked rows are decided by OD-3 (below). **D2 gate: no**, because the owner of the revoked key is not the requester.
- **Platform-marked rows: OD-3, decided (owner, 2026-11-03, final closure).** "Tenant API-key revocation records naming a platform target user remain subject to target-user reference treatment." The options set out before the decision were (a) leave it to P4, (b) omit the key in P1 and (c) a tenant reference after P3; reference treatment rules out (a) and (b).
  - **Design.** New platform-marked rows write a **tenant** reference under `owner_user_subject_ref` instead of `owner_user_id`. A tenant row's reference must be in the tenant's scope (D1), so this ships with the tenant tables, in P3 (O3, decided 2026-11-03: option (b)). Until then the rows keep `owner_user_id` raw, and the P1 release notes say so.
  - **Tests.** Decision record, OD-3.
- **Tenant-internal rows.** Revocations by a tenant administrator are not covered by OD-3: phase P4, with the per-field choices of section 3.
- **Migration strategy.** No schema change to the audit table; the tenant link tables of P3.
- **Compatibility.** A metadata key change for readers of platform-marked `api_key.revoke` rows (OD-3), and later of the tenant-internal ones (P4).

### TA-6 `core.audit_log.metadata["proposer_user_id"]` (`control_plane.action_approved`)

- **Writer.** `approve()` → `record_audit_event` at `saas_os/control_plane/approvals/service.py:143`, key at `:153`. Only the successful approval writes it; the proposal row (`:72`) has the proposer as actor.
- **Purpose and role.** Related party. It is the evidence that the approver (the row's actor) is not the proposer.
- **Decision.** None; an outstanding risk. **D2 gate: no.** The proposer did request the action being approved, but this row records the approval, whose requester is the approver. The key exists to evidence separation of duties, and refusing it would remove that evidence.
- **Note.** `control_plane.approval_requests.proposer_user_id` (OP-24) holds the same id indefinitely (`DEFERRED_POLICY`), so a reference here protects little until that table has a policy.
- **Migration strategy (phase P4 or P5).** A tenant reference after P3, decided together with the actor exception (TA-1), because the same row's actor is the approver.
- **Compatibility.** A metadata key change for AI Control Plane audit readers.

### TA-7 Product metadata keys

- **Writers.** Any product call to the tenant writers. Core cannot tell a user id from any other UUID in them.
- **Decision.** O5 (decided, owner, 2026-11-03, merge preparation): this is a product responsibility, the only stated option. **D2 gate:** only the reserved key `initiated_by`, which products cannot write (`ReservedMetadataKeyError`). The gate cannot reach other product keys without knowing what they mean.
- **Migration strategy.** Products should keep user ids out of metadata, or adopt references once the tenant mechanism ships (P3). The consumer guide states this.

## 4. Platform audit records (`core.platform_audit_log`)

Common to every field in this section:

- **Read access.** The tenant-context exclusion policy (`c4a9e1f07b52`) makes the rows visible only while no tenant is bound. They are read through `list_platform_audit` (`saas_os/core/platform_authority/oversight.py:452`) and `GET /platform/audit` (`saas_os/api/platform_admin/router.py:147`, `platform.audit:read`), which return every entry's actor, target, reason and metadata; any application-role code in an untenanted session can read them too.
- **Other copies.** The table owner and superusers can change rows. Backups hold every row.
- **Writes.** The application role cannot update or delete rows (`REVOKE UPDATE, DELETE`).
- **Retention.** `SECURITY_RETAIN` (`saas_os/core/tenancy/retention.py:85`), with no expiry.
- **Digest.** All of `actor_user_id`, `target_type`, `target_id`, `reason` and `metadata` (as stored text) are in `PLATFORM_AUDIT_LOG_COLUMNS`.

### PA-1 `core.platform_audit_log.actor_user_id`

- **Writers.** `_actor()` (`saas_os/core/platform_authority/audit.py:102-105`) in `_entry()` (`:108`), for every `UserCaller`. That covers every platform writer call made by a person: authenticated platform-admin routes, and operator commands with a declared `--operator` (`saas_os/ops/operator_cli.py`).
- **Purpose and role.** Actor (operator self).
- **Constraints.** FK to `core.users`; `ck_platform_audit_log_actor_pairing` requires the column for `actor_type = 'user'`.
- **Decision.** O1 (a temporary exception) and D6 (operator identities excluded). Under OD-1, the D6 exclusion covers rows whose actor performed an authenticated privileged operation; an actor declared with `--operator` on a command line is not an actual operator, and its id stays raw only as the O1 actor exception. **D2 gate: no.** It records the actor, and refusing it would leave operator acts unaudited.
- **Migration strategy (phase P5).** Only under a separate operator retention policy. The schema change is TA-1's, made on the platform table, with digest format v2.
- **Compatibility.** `list_platform_audit(actor_user_id=...)` and `GET /platform/audit` readers.

### PA-2 `core.platform_audit_log.target_id` when `target_type = 'user'`

- **Writers.**
  - `saas_os/core/identity/user_authority.py:135` (`_record_outcome`, refusal or failure rows of every user operation), `:170` (`_record_success`: session revoke, API-key revoke, deactivate, reactivate) and `:299` (refused erasure of an enrolled operator).
  - `resolve_user` (`:441-447`) through `run_oversight_read`. The attempt row (`oversight.py:174`) carries the user id that was asked for, and the completion row (`:189`) carries the user that was found (`target_id=str(user.id)`, `user_authority.py:439`). Refusals of that read go through `oversight.py:170` and `:203`.
  - The refusal rows of `enroll_operator` (`saas_os/core/platform_authority/service.py:134`, through `_run`, called with `target_type="user"` at `:357`).
- **Purpose and role.** Target.
- **Decision.** D6 is the first scope (P1). Every target user gets a platform reference under `target_type = 'user_subject'`, operators included: OD-2 (2026-11-03, final closure) applies the operator exclusion to actors only, so the writer makes no operator test. The rows that change classification by OD-2 are listed in section 2. Unknown user ids: O6, decided (owner, 2026-11-03, merge preparation): option (a), record no target. O6's foreign-key implications were addressed by the owner on 2026-11-04 (option A1): the `core.users` foreign key stays, the platform writers decide existence in the audit write's transaction with `SELECT ... FOR KEY SHARE` on `core.users` (option A1 of `docs/architecture/AUDIT-P1-FOREIGN-KEY-OPTIONS.md`), and an unknown id is recorded as `target_type = 'user'` with a NULL `target_id` and no link row (decision record, "O6 foreign-key decision"; the `23503` risk was get-or-create on the `core.users` foreign key of `core.platform_audit_subject_links`, proposal, sections 4.3 and 4.4).
- **D2 gate: no.** This is the target, not an initiator. D6 handles it with references instead of a refusal, because refusing would leave platform operations on users unaudited.
- **Migration strategy (phase P1).** No change to the audit table (`target_id` is `varchar`); new link, marker and hold tables (proposal, section 4.3).
- **Compatibility.** `GET /platform/audit` shows a new target type, which must go in the release notes. Every reference row resolves only through the decided lookup (D3, O4).

### PA-3 `core.platform_audit_log.metadata["user_id"]` (operator events)

- **Writers.** `saas_os/core/platform_authority/service.py`:
  - enrolment success `:230` (key at `:225`);
  - status changes `:260` (`:267`);
  - grant creation `:321` (`:331`);
  - operator revocation `:446` (`:454`);
  - grant revocation `:526` (`:536`).
- **Purpose and role.** Target: the user behind the operator acted on (`target_id`, PA-7). The actor is the operator who enrolled, changed, granted or revoked.
- **Decision.** OD-2 (2026-11-03, final closure): the target of an action gets target-user reference treatment, operator or not. In the D6 first scope. **D2 gate: no**, because it names the operator acted on, not an initiator.
- **Migration strategy (phase P1).** New rows write a platform reference under `user_subject_ref` instead of `user_id`. No schema change. The person stays linkable through `target_id` (PA-7) and `core.platform_operators.user_id` (OP-19) for as long as OP-19 keeps the id (P6).
- **Compatibility.** Operator-history readers: a metadata key change.

### PA-4 `core.platform_audit_log.metadata["filters"]["actor_user_id"]`

- **Writer.** `list_platform_audit` builds `request_metadata["filters"]` (`saas_os/core/platform_authority/oversight.py:513-519`, key at `:516`). The attempt row is written through `record_oversight_attempt` (`oversight.py:174`).
- **Purpose and role.** The value is the filter an operator asked for, normally an operator id: who did what was asked about, recorded as asked, never as found.
- **Decision.** D6: an operator's audit read about operators. Unchanged by OD-2: the value names a person as the actor of the rows queried, not as the target of an operation. **D2 gate: no**, because it is a request filter, not an initiator.
- **Migration strategy.** None planned. If the filter could name a non-operator, P5 would record a platform reference instead.
- **Compatibility.** None until then.

### PA-5 `core.platform_audit_log.metadata["run_by_user_id"]` (tenant purge)

- **Writers.** `purge_tenant` adds it from `--actor` (`saas_os/core/tenancy/service.py:1793-1795`). It goes into the platform rows `record_platform` at `:1836` and `:1953` (`saas_os/core/tenancy/authority.py:175`).
- **Purpose and role.** Actor, declared: the person who ran the command. The row's own actor is the `TENANT_PURGE` system purpose.
- **Decision.** None. It is an actor, not a target, so it is outside D6's scope. The runner is declared on the command line, not authenticated, so under OD-1 it is not an actual operator and the operator exclusion does not cover it: an outstanding actor risk. **D2 gate: no**, because it names who ran the act.
- **Migration strategy (phase P5).** With the actor exception, or a platform reference for declared runners.
- **Compatibility.** Purge evidence readers.

### PA-6 `core.platform_audit_log.metadata["initiated_by"]`

- **Writers.** No Core writer. On this branch, `record_platform_event_in_transaction` (`saas_os/core/platform_authority/audit.py:151`) accepts any metadata that `validate_metadata` accepts, and `initiated_by` is not reserved there. A caller could therefore store a user initiator.
- **Purpose and role.** Initiator, if a caller supplied one.
- **Decision.** D2. **D2 gate: yes**, because this is the same field with the same meaning on the platform table. On 2026-11-03 PR #201 is being extended to refuse a user initiator here. PR #201 is the authority for what it implements.
- **Migration strategy.** P0 (PR #201).
- **Compatibility.** None known in Core. PR #201 records its call-site and consumer audit.

### PA-7, PA-8, PA-9 Indirect operator identifiers

- **PA-7.** `target_id` with `target_type = 'platform_operator'`: the operator id. Writers: `saas_os/core/platform_authority/service.py:134` (refusals of operator operations other than enrolment), `:230`, `:260`, `:321`, `:446`, `:526`, and `saas_os/core/platform_authority/bootstrap.py:399` (recovery's suspended operator). It resolves to a user through `core.platform_operators` and `GET /platform/operators`.
- **PA-8.** Metadata `operator_id` (`saas_os/core/platform_authority/audit.py:397`, a session issued to an operator) and `previous_operator_id` (`saas_os/core/platform_authority/service.py:229`, re-enrolment).
- **PA-9.** `target_id` with `target_type = 'session'`: the id of the session issued to an operator (`audit.py:391-396`). It resolves through `core.sessions` until the session row is deleted.
- **Decision.** By role, after OD-2 (2026-11-03, final closure):
  - **PA-7** and PA-8's **`previous_operator_id`** name the operator **acted on**: targets. They are operator ids, not user ids, so the reference mechanism does not replace them; they keep identifying the record and identify the person through `core.platform_operators.user_id` (OP-19) while that row keeps it.
  - PA-8's **`operator_id`** and **PA-9** belong to the row of an operator's own login, whose actor is that operator: operator self, excluded by D6.
  - **D2 gate: no**, because none of them is an initiator.
- **Migration strategy.** PA-7 and `previous_operator_id`: none in the audit row; the person stops being identifiable when OP-19's retention (P6) removes the link. PA-8's `operator_id` and PA-9: phase P5, only under the operator policy.

### PA-10 `core.platform_audit_log.reason` (free text)

- **Writers.** Every platform change that takes a `reason`. `validate_reason` (`saas_os/core/platform_authority/audit.py:86`) checks only that it is not empty, its length (500) and that it holds no control characters. On refusals the column holds a fixed code.
- **Purpose and role.** The operator's justification, meant to be a ticket reference. Core cannot stop a name or an e-mail address being typed into it.
- **Decision.** None. **D2 gate: no**, because it is free text with no defined meaning.
- **Migration strategy (phase P4).** Guidance that the reason is a ticket reference (`docs/RUNBOOKS.md` already says so for `--reason`), and possibly a pattern check, which would be an owner decision because it refuses existing usage.

## 5. Outbox (`core.outbox_events`)

Common to every field in this section:

- **Read access.** Tenant row-level security (`8d3f1a6c2e70`). The dispatcher reads rows and hands payloads to the consumers. The rows are not digested.
- **Retention.** `OPERATIONAL_PURGE`: tenant purge deletes every event. Published events are kept until then; nothing prunes them.
- **Requirement.** The two-year policy names audit records only. Whether published events and logs follow it is open (proposal, section 10).

### OB-1 `payload["saas_os.initiated_by"]` = `{"type": "user", "user_id": ...}`

- **Writer.** `append_event(..., initiated_by=...)` (`saas_os/core/outbox/service.py:116`, stored at `:162`).
- **Purpose and role.** Initiator, carried to the consumer.
- **Erasure.** `erase_user_initiator` (`saas_os/core/outbox/initiator_erasure.py:57`) rewrites it to `"unavailable"` in every status, for the tenants given to `erase_user_identity` (owner decision of 2026-11-02).
- **Decision.** D2 preserves this behaviour ("existing outbox erasure behaviour"). **D2 gate: no.** D2 gates audit records; the outbox must keep the initiator so that the consumer receives it.
- **Migration strategy (phase P6).** A retention rule for published events, which is a separate decision.
- **Compatibility.** Unchanged.

### OB-2 `payload["recipient_user_id"]`, OB-3 column `aggregate_id` with `aggregate_type = 'user'`, OB-4 `payload["recipient_email"]`

- **Writer.** `dispatch_notification` (`saas_os/core/notifications/service.py:189`): the payload at `:230-238` and `append_event` at `:240` (`aggregate_id=str(recipient_user_id)` at `:245`). The e-mail address is encrypted with the field-encryption key (`_encrypt_recipient_email`, `:238`). The payload also holds the notification's `subject` and `body` (content, which may be personal).
- **Purpose and role.** Target: the recipient, and the recipient's contact data.
- **Erasure.** `purge_user_notification_events_in_tenant` (`:580`) deletes the user's notification events in the tenants given to the erasure. Its query (`delete_aggregate_events`, `saas_os/core/outbox/service.py:172`) has no status predicate, so published events are deleted too.
- **Decision.** None (outside the audit policy). **D2 gate: no**, because the recipient is not an initiator.
- **Migration strategy (phase P6).** Retention for published events.
- **Compatibility.** None.

### OB-5 Product payloads

- **Writers.** Webhook deliveries carry the product's `event_data` (`saas_os/core/webhooks/service.py:1134-1144`); product events carry their own payloads.
- **Decision.** A product obligation. **D2 gate: no.** Core cannot interpret the content.

The other Core producers carry no user id: billing projections (`saas_os/core/billing/projections.py:147`, subscription id and version) and usage (`saas_os/core/usage/service.py:185`, metric and quantity).

## 6. Operational tables

These are not audit records: the two-year policy does not name them, and no retention requirement has been decided for them (`docs/DATA-ARCHITECTURE.md` section 8). None is digested. **D2 gate: no** for every one of them, because D2 concerns audit records. Read access follows each table's row-level security:

- **Tenant tables:** visible to application-role code bound to the tenant.
- **Global identity tables** (`core.users`, `core.external_identities`, `core.sessions`) **and `core.api_keys`:** no RLS, so visible to application-role code in any session. `core.api_keys` must be resolvable by key hash before the tenant is known (`tests/architecture/test_tenant_session_boundary.py`).
- **Platform tables:** the exclusion policy (untenanted sessions only). `GET /platform/operators` and `GET /platform/grants` (`platform.operator:read`) return their user-id columns (`saas_os/api/platform_admin/router.py:503-518`).

"Erasure" below means what `erase_user_identity()` (`saas_os/core/identity/erasure.py:280`) does today for the tenants it is given.

| # | Table.column | Writers | Role | Retention class; erasure today |
|---|---|---|---|---|
| OP-1 | `core.tenant_memberships.user_id` | `saas_os/core/identity/service.py:382`, `:1256` | the member (target) | `OPERATIONAL_PURGE`; row deleted |
| OP-2 | `core.external_identities.user_id` | `saas_os/core/identity/service.py:237`, `:348` | the person | `GLOBAL_IDENTITY`; every row deleted |
| OP-3 | `core.external_identities.subject` (with `issuer`) | same | identity data | as OP-2 |
| OP-4 | `core.sessions.user_id` | `saas_os/core/identity/sessions.py:86-90` | the person | `GLOBAL_IDENTITY`; every session deleted (`purge_user_sessions`, `:179`); expired rows cleaned by session retention |
| OP-5 | `core.sessions.verified_email` | `saas_os/core/identity/sessions.py:90` (from `saas_os/api/auth/routes.py:338`); cleared at `:176` | contact data | as OP-4 |
| OP-6 | `core.invitations.invited_email` | `saas_os/core/identity/service.py:919` | contact data of the invitee (target) | `OPERATIONAL_PURGE`; **remediated for individual erasure (P6.1, 2026-11-04)**: `erase_user_identity` deletes the person's invitations in the listed tenants; kept otherwise until tenant purge |
| OP-7 | `core.invitations.inviter_user_id` | `saas_os/core/identity/service.py:921` | actor | `OPERATIONAL_PURGE`; **kept** (NOT NULL FK) |
| OP-8 | `core.invitations.accepted_by_user_id` | `saas_os/core/identity/service.py:1246` | actor | `OPERATIONAL_PURGE`; kept |
| OP-9 | `core.invitations.revoked_by_user_id` | `saas_os/core/identity/service.py:1018` | actor | `OPERATIONAL_PURGE`; kept |
| OP-10 | `core.api_keys.user_id` | `saas_os/core/api_keys/service.py:270`, `:782` (rotation) | resource owner | `OPERATIONAL_PURGE`; the user's keys deleted (`purge_user_api_keys_in_tenant`, `:911`) |
| OP-11 | `core.notifications.recipient_user_id` | `saas_os/core/notifications/service.py:461` | target | `OPERATIONAL_PURGE`; deleted (`purge_user_notifications_in_tenant`, `:547`) |
| OP-12 | `core.support_access_requests.requester_user_id` | `saas_os/core/rbac/service.py:1816` | actor | `SECURITY_RETAIN`; kept |
| OP-13 | `core.support_access_requests.approved_by_user_id` | `saas_os/core/rbac/service.py:1959` | actor | `SECURITY_RETAIN`; kept |
| OP-14 | `core.support_access_requests.denied_by_user_id` | `saas_os/core/rbac/service.py:2014` | actor | `SECURITY_RETAIN`; kept |
| OP-15 | `core.support_access_requests.revoked_by_user_id` | `saas_os/core/rbac/service.py:2075`, `:2161` | actor | `SECURITY_RETAIN`; kept |
| OP-16 | `core.delegation_grants.delegator_principal_id` | `saas_os/core/rbac/service.py:1218`, `:1333` | actor (grantor) | `OPERATIONAL_PURGE` (kept revoked when audit references the grant); kept |
| OP-17 | `core.delegation_grants.delegate_principal_id` | `saas_os/core/rbac/service.py:1220` | target (grantee) | as OP-16 |
| OP-18 | `core.deny_grants.principal_id` | `saas_os/core/rbac/service.py:1544` | target | `OPERATIONAL_PURGE`; kept |
| OP-19 | `core.platform_operators.user_id` | `saas_os/core/platform_authority/service.py:218` | operator self | `SECURITY_RETAIN`; erasure refused while unrevoked; kept |
| OP-20 | `core.platform_operators.enrolled_by_user_id` | `saas_os/core/platform_authority/service.py:220` | actor (operator) | `SECURITY_RETAIN`; kept |
| OP-21 | `core.platform_operators.status_changed_by_user_id` | `saas_os/core/platform_authority/service.py:221`, `:258`, `:444` | actor (operator) | `SECURITY_RETAIN`; kept |
| OP-22 | `core.platform_grants.granted_by_user_id` | `saas_os/core/platform_authority/service.py:317` | actor (operator) | `SECURITY_RETAIN`; kept |
| OP-23 | `core.platform_grants.revoked_by_user_id` | `saas_os/core/platform_authority/service.py:440`, `:524` | actor (operator) | `SECURITY_RETAIN`; kept |
| OP-24 | `control_plane.approval_requests.proposer_user_id` | `saas_os/control_plane/approvals/service.py:61` | actor (proposer) | `DEFERRED_POLICY`; kept |
| OP-25 | `control_plane.approval_requests.approver_user_id` | `saas_os/control_plane/approvals/service.py:136`, `:172` | actor | `DEFERRED_POLICY`; kept |
| OP-26 | `control_plane.ai_inference_attempts.actor_user_id` | `saas_os/control_plane/inference/service.py:434-440` | actor | `DEFERRED_POLICY`; kept |
| OP-27 to OP-30 | `self_learning.experiments.created_by_user_id`, `executed_by_user_id`, `completed_by_user_id`, `cancelled_by_user_id` | `saas_os/control_plane/self_learning/experiments/service.py:217`, `:264`, `:326`, `:376` | actor | `DEFERRED_POLICY`; kept |
| OP-31 to OP-33 | `self_learning.adaptations.created_by_user_id`, `activated_by_user_id`, `rolled_back_by_user_id` | `saas_os/control_plane/self_learning/adaptive/service.py:243`, `:370`, `:434` | actor | `DEFERRED_POLICY`; kept |
| OP-34 to OP-39 | `self_learning.canaries.created_by_user_id`, `started_by_user_id`, `concluded_by_user_id`, `promoted_by_user_id`, `rolled_back_by_user_id`, `cancelled_by_user_id` | `saas_os/control_plane/self_learning/autonomous_improvement/service.py:575`, `:644`, `:817`, `:852`, `:702`, `:927` | actor | `DEFERRED_POLICY`; kept |

`core.users` itself holds no personal data (`id`, `is_active`, timestamps), and `core.users.id` is never deleted, because many `NOT NULL` foreign keys reference it (`saas_os/core/identity/erasure.py`, module docstring).

**Findings for the owner** (recorded as deferred rows in `docs/P-ROADMAP.md`):

- **First priority: the `invited_email` erasure gap (remediated, P6.1, 2026-11-04).** Until then an erased person's e-mail address stayed in `core.invitations.invited_email` (OP-6) until tenant purge, because erasure never touched `core.invitations`. That contradicted the documented scope of erasure (`docs/MULTI-TENANCY.md` section 6, and the module docstring's "one person's own identity data, wherever it lives"). `erase_user_identity` now deletes the person's invitations in the listed tenants (section 6.1, "Implementation"); `docs/MULTI-TENANCY.md` section 6 and the module docstring state what is removed and what is kept.
- Every actor column above, together with the platform operator tables, keeps the user id indefinitely, because `DEFERRED_POLICY` and `SECURITY_RETAIN` tables have no expiry.

**Migration strategy and compatibility (phase P6).** Apart from P6.1, these depend on a retention decision for each table, which is not part of the audit identity policy. Possible changes:

- set retention periods for `DEFERRED_POLICY` tables once the AI Control Plane's drain and disposition are decided (`saas_os/core/tenancy/retention.py`, `DEFERRED_POLICY`);
- use references for actor columns, which is the same question as TA-1.

Each change alters what products and operators read from these tables.

### 6.1 Remediation of the `invited_email` erasure gap (phase P6.1; implemented 2026-11-04)

**Implementation (2026-11-04).** Implemented as designed below, on `main` after PR #207 (`965d6d1`), by the pull request that carries this change; the owner authorised it ("Apply invited_email erasure fix"). The text below is the design as it was approved, kept as the historical record; where the code differs, this paragraph says so. Differences and additions: (a) the address match is made by `delete_user_invitations_in_tenant` in `saas_os/core/identity/service.py`, with a second helper `normalize_invitation_addresses` (the same `_normalize_email`, validating before anything is deleted) and `list_user_verified_emails` in `saas_os/core/identity/sessions.py`; none is exported from `saas_os.core.identity`, so the public API snapshot does not change; (b) `saas-os-operator erase-user` gained the repeatable `--invited-email`, as designed in item 1; (c) the count row uses the same caller as the neighbouring erasure audit rows, `UserCaller(actor_user_id)` in the actor columns, and no `initiated_by`, so the D2 gate does not apply to it; (d) the module docstring of `saas_os/core/identity/erasure.py` ("Limits of the invitation step") and `docs/RUNBOOKS.md` (`erase-user`, "Limits") state two residual limits that the design did not list: an invitation the user accepts after the invitation step of a tenant has run but before the erasure ends (an acceptance by a person whose session is still valid) survives until the erasure is run again, and the address read for source (iii) is read before the rows are locked, so an acceptance committed between the two is matched by `accepted_by_user_id` only; a second run finishes both. Tests: `tests/core/identity/test_erasure_integration.py` (15 PostgreSQL tests for this step), `tests/core/identity/test_erasure_unit.py`, `tests/ops/test_operator_cli_unit.py`; negative controls are listed in the pull request.

**Status of the design.** Approved design (originally: not implemented, no code change authorised in that cycle). It is independent of P0 to P5 and of every owner decision in the decision record, blocks nothing else, and may ship before or after any of them. Facts verified on `feat/system-actor-step1`: `core.invitations` (migration `87efe7908288`, RLS added by `cb7120cfa806`) has `invited_email varchar(320) NOT NULL`, stored after `_normalize_email` (`saas_os/core/identity/service.py:823`: `strip().casefold()`); indexes `ix_invitations_tenant_email (tenant_id, invited_email)` and the partial unique `uq_invitations_live_unique`; no foreign key in the schema points at `core.invitations`; tenant purge already deletes every invitation of a tenant as the application role (`purge_tenant_invitations`, `service.py:1301`: "nothing about it is retained"); `core.sessions.verified_email` holds the e-mail the identity provider verified at login (OP-5); `accept_invitation` locks the invitation row before it reads the membership (`_consume_locked_invitation`, `service.py:1213`).

**1. Functions that change.**
- `saas_os/core/identity/service.py`: a new module-owned step `delete_user_invitations_in_tenant(session, *, tenant_id, user_id, addresses) -> int`, next to `purge_tenant_invitations`. It takes the caller's tenant-bound session, so it runs inside the erasure's transaction.
- `saas_os/core/identity/erasure.py`:
  - `erase_user_identity(user_id, tenant_ids, *, actor_user_id, invited_emails=())`: a new keyword-only argument, default empty, so existing callers are unchanged.
  - `_erase_membership_in_tenant`: calls the new step first in its first tenant transaction (`tenant_session_scope`, `erasure.py:199-226`), before `erase_user_initiator` and before the membership row is locked, and in that same transaction writes the step's audit row (item 4). Today that function uses three transactions per tenant: the first locks the membership and rewrites outbox initiators, the second deletes the membership (`:229-238`), and `identity.erasure_membership_removed` is written in a third by `record_audit_event` (`:241`). The invitation step therefore does **not** use the membership row for its count.
  - `IdentityErasureResult`: a new field `invitations_deleted: int = 0`.
- `saas_os/ops/operator_cli.py`, `erase-user`: a repeatable `--invited-email <address>`, passed through. It is never printed or logged; the command prints counts only, as today.

**2. Which addresses, and which rows.** Core stores no e-mail on `core.users`, so matching by user id alone finds only accepted invitations. The address set `A` is the union of:
- (i) the caller's `invited_emails`, each normalised with `_normalize_email`; an invalid one raises `InvalidInvitationEmailError` **before the identity links are removed**, so nothing is deleted;
- (ii) every non-null `core.sessions.verified_email` of the user, read in `erase_user_identity` before the tenant loop (the sessions are deleted only by its last step, `purge_user_sessions`);
- (iii) per tenant, the `invited_email` of the rows that tenant holds with `accepted_by_user_id = user_id`.

In each tenant of `tenant_ids`, the step deletes every row with `tenant_id = :tenant_id AND (accepted_by_user_id = :user_id OR invited_email = ANY(:A))`, in every state:

| State (read-time projection, `InvitationStatus`) | Effect |
|---|---|
| Pending (`accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()`) | Deleted. The token is gone: a later `accept_invitation` with it fails with the same `InvitationInvalidError` as an unknown token, and the tenant can invite again |
| Accepted (`accepted_at IS NOT NULL`) | Deleted, whether matched by `accepted_by_user_id` or by address. The membership it created is removed by the same erasure |
| Revoked | Deleted |
| Expired (not accepted, not revoked, `expires_at <= now()`) | Deleted |
| Issued **by** the person (`inviter_user_id = user_id`) to someone else | Unchanged: it is the other invitee's invitation, and `inviter_user_id` is a `NOT NULL` actor column (OP-7) |
| Addressed to the person in a tenant **not** in `tenant_ids` | Unchanged; discovery stays the caller's responsibility, as for memberships |
| Revoked **by** the person (`revoked_by_user_id = user_id`) and addressed to someone else | Unchanged, and `revoked_by_user_id` is **kept**. It is an actor column (OP-9), like `inviter_user_id`, whose retention belongs to the rest of P6. It cannot simply be nulled: `ck_invitations_revocation_pairing` requires it while `revoked_at` is set, and clearing both would make a revoked invitation pending again |

Deletion, not an in-place scrub, follows the tenant-purge precedent and leaves nothing to scrub: a placeholder address would have to stay unique under `uq_invitations_live_unique` and would leave a live token behind. The `invitation.create`, `invitation.revoke` and acceptance audit rows keep naming the invitation id as `resource_id`; none of them holds the address (`service.py:926`, `:1020`, `:1171`). Matching is exact on the normalised, case-folded value. An address in (iii) is used only in its own tenant; to cover other listed tenants the caller declares it in (i).

**3. Tenant scope, RLS and order.** The step runs in `tenant_session_scope(tenant_id)` as the application role under the table's tenant RLS, with `tenant_id` also in the predicate. It selects the matching rows `FOR UPDATE ORDER BY id` and deletes them, as `purge_tenant_invitations` does. No new role, grant or `BYPASSRLS`. It runs in the first tenant transaction, before the membership lock, which is `accept_invitation`'s order (invitation, then membership). A concurrent acceptance therefore either commits first, and the erasure then finds and removes the membership in its later transactions, or waits and then finds no invitation.

**4. Audit evidence.** Counts only; the address and the number of declared addresses are never recorded or logged.
- Whenever `n > 0`, whether or not a membership exists or is later removed, a new row `identity.erasure_invitations_erased` (actor `actor_user_id`, `resource_type = 'user'`, `resource_id = str(user_id)`, metadata `{"invitations_deleted": n}`) is written by `record_in_transaction` **in the transaction that deletes the rows** (the first tenant transaction). The deletion and its count commit together or not at all.
- `identity.erasure_membership_removed` is not changed: it is written in a later transaction (`:241`) and must not carry a count whose deletion committed earlier.
- When `n == 0`, no row is written, as for the outbox initiator count.
- **Concurrent erasures of the same person in one tenant.** Both lock the matching rows `FOR UPDATE`; the second waits and, after the first commits, finds none. The first records `n` with its deletion; the second deletes nothing and writes no row. No count is lost or recorded twice. If the first rolls back, neither its deletion nor its row survives, and the second deletes and records the rows itself.
- `IdentityErasureResult.invitations_deleted` is the sum of the committed per-tenant counts.

These rows name the user as `resource_id`, like the existing erasure rows (TA-2).

**5. Idempotency and non-enumeration.** A deleted row is not found again: a second call returns `invitations_deleted == 0`. A nonexistent user, a user with no invitations and an already erased user give the same all-zero result. Two concurrent erasures serialise on the row locks; the second finds nothing.

**6. Migration.** None. The address match uses `ix_invitations_tenant_email`; the `accepted_by_user_id` match is bounded to one tenant through `ix_invitations_tenant_id`. The application role already deletes from `core.invitations` (`purge_tenant_invitations`).

**7. Tests that prove it** (`tests/core/identity/test_erasure_integration.py` unless stated; PostgreSQL 16).
1. One pending, one accepted, one revoked and one expired invitation to a declared address in a listed tenant: all four deleted; `invitations_deleted == 4`.
2. Without a declared address: the invitation accepted by the user is deleted, and so is a pending invitation in the same tenant to the address it carried.
3. An address taken only from a live session's `verified_email` is matched.
4. Unchanged: an invitation to the same address in an unlisted tenant; invitations to other addresses; an invitation issued by the user to someone else.
5. After the erasure, `accept_invitation` with the deleted pending token raises `InvitationInvalidError`.
6. Audit: in a tenant where a membership is removed, and in one where none exists, exactly one `identity.erasure_invitations_erased` row carries `n`, and `identity.erasure_membership_removed` has no invitation key. A failure injected after the deletion and before commit rolls back both the deletion and the row. A failure injected in the later membership transaction leaves the committed deletion and its row in place, and a rerun reports 0 for the invitations. No audit row, log line or result field contains the address.
7. Idempotency: a second call gives zero; a nonexistent user gives the same all-zero result.
8. An invalid declared address raises before anything is deleted: the external identities are still present.
9. Concurrency, two connections: erasure against `accept_invitation` in both orders, with no deadlock and no surviving invitation; two concurrent erasures of the same person give one `identity.erasure_invitations_erased` row whose count equals the rows deleted, and the second call's result reports 0 for that tenant.
10. Unit (`tests/core/identity/test_erasure_unit.py`, the CLI tests): the new result field's default; `--invited-email` is passed through and never printed.
11. Unchanged: the tenant-purge and invitation lifecycle tests.

Negative controls: removing the step makes tests 1 to 3 fail; removing the `tenant_id` predicate, and separately running the step outside the tenant-bound session (RLS), make test 4 fail on the predicate and on RLS alone; recording the address in the metadata makes test 6 fail; writing the count with `record_audit_event` in its own transaction instead of `record_in_transaction` makes test 6's rollback case fail.

**8. Documentation fix (`docs/MULTI-TENANCY.md` section 6), with the implementation.** In the erasure paragraph, after "touching no other member's data and no tenant business data)", insert: "then, in each named tenant, in the tenant transaction that rewrites the outbox initiators and before the membership is locked, deletes every `core.invitations` row addressed to the person, whatever its state: rows the user accepted, and rows whose `invited_email` equals one of the person's addresses (addresses the caller declares, the verified e-mail of the user's remaining sessions, and, per tenant, the address of an invitation the user accepted there); invitations the person issued or revoked for others keep `inviter_user_id` and `revoked_by_user_id`; the count, never the address, is recorded in an `identity.erasure_invitations_erased` row committed in that same transaction,". In "Retained records", add `core.invitations.inviter_user_id` and `revoked_by_user_id`. The module docstring of `saas_os/core/identity/erasure.py` gets the same statement. Until it ships, the accurate statement is: "`erase_user_identity()` does not touch `core.invitations`: an invitation addressed to an erased person keeps `invited_email` until tenant purge (deferred finding, `docs/P-ROADMAP.md`)."

## 7. Outside the database (not counted)

- **Application logs** carry user ids in structured fields: for example `auth_logout` (`saas_os/api/auth/routes.py:381`), `platform_bootstrap_completed` (`saas_os/api/platform_bootstrap.py:279-284`), `tenant_bootstrap_completed` (`saas_os/api/tenant_bootstrap.py:527-534`) and `user_deactivation_retry` (`saas_os/core/identity/user_authority.py:745`). Their retention is the deployment's logging configuration. Whether logs follow the two-year rule is open (proposal, section 10).
- **URLs.** `GET /platform/users/{user_id}` and the user operation routes carry the user id in the path, and so in access logs. The proposed lookup routes use `POST` for this reason (proposal, section 4.5).
- **Redis.** It holds outbox event ids and claim tokens only (`docs/CONSUMER-GUIDE.md`). arq keeps job keys for about 24 hours.
- **Backups** contain every table above, for `BACKUP_RETENTION_COUNT` runs (default 7), and bring back removed identification on restore (proposal, section 4.12).
- **ADR-0053 digest log lines** contain hashes and counts only, never row contents.

## 8. Why the D2 gate stays on `initiated_by`

D2 and O1 refuse one thing: a raw user id recorded as the **initiator** of an act. Every other field above records something else, and refusing it would refuse the act or remove evidence that a rule requires:

- **Actors** (TA-1, PA-1, PA-5, every `*_by_user_id`): an audit row must say who did the act (ADR-0031), and the CHECK constraints require it.
- **Targets** (TA-2, TA-4, PA-2, PA-3, PA-7, OB-2/OB-3): refusing would make operations on people unauditable. D6 provides references for platform target users instead, operators included (OD-2).
- **Resource owners and related parties** (TA-5, TA-6): these keys exist as evidence of the operation or of separation of duties. TA-5's platform-marked rows get tenant references (OD-3).
- **Operator self as actor** (PA-4, PA-8, PA-9): excluded by D6 (OD-1).
- **Free text and product keys** (PA-10, TA-7, OB-5): Core cannot know what they mean.

The gate applies only where the meaning is the same: TA-3 on the tenant table, and PA-6, the same key on the platform table, which PR #201 is covering.

## 9. Consolidated remediation design (phased)

Each phase is its own PR, with migration review where it changes the schema, and needs the owner's implementation approval. Approval of one phase does not imply approval of the next. "Decided" refers to the decision record.

| Phase | What changes | Order and dependencies | Owner decisions | Tests that prove it |
|---|---|---|---|---|
| **P0** D2 gate | Tenant writers refuse a user initiator (TA-3); `record_platform_event_in_transaction` refuses one in `metadata["initiated_by"]` (PA-6); consumer guide | PR #201; #196 and #201 are one compatibility unit (#196 never merged without #201) | D2, O1: decided | In PR #201 (its authority): refusal before insert on every path, no raw user initiator in any new row of either table, outbox erasure tests unchanged, negative controls |
| **P1** Platform targets | Platform link, marker and hold tables; references for every PA-2 target, operators included, with no operator test (OD-2), and for PA-3 (`user_subject_ref`); `target_type = 'user_subject'`; lookup routes; platform erasure step; the link-table architecture test (O11 interim); an inventory pin test (below) | After P0. The lookup needs PR #198 (the `platform.security_retention:report` permission) and the register PR #203 (independent register eligibility), both merged; an amendment of ADR-0045's route table is still open; SQL review (proposal, section 8) | D1, D3, D6, O2, O4, O6 (option (a), record no target), O7 (option (a), probes not recorded), O11, OD-1, OD-2: decided. O6's foreign-key implications addressed (2026-11-04, option A1: the foreign key stays and the writers decide existence in the audit transaction); P1 is no longer blocked by O6, and its first slice does not need the lookup routes | Decision record, D1, D3, O2, O4 and O11 entries: one reference per UTC day, concurrency, collision retry; operator targets get references; refusal without the permission, without eligibility, inside the 120-day delay and after revocation; attempt rows before reads; architecture test with negative control; FK behaviour for unknown ids |
| **P2** Holds and expiry | Hold routes (place and release through the API; a CLI that can only place); the expiry command with dry run, confirmations and report job; `--apply` behind a literal `False` gate; markers expire under the same command | After P1 | D4, D7, D8, O8, O9, O10, the exact two-year rule and the hold route permission (`platform.security_retention_hold:manage`, PR #198): decided. **Needed:** for `--apply`, an authenticated, register-eligible approval mechanism, implemented, independently reviewed and tested (O9) | The test vectors of the exact rule (leap day, UTC first, inclusive boundary); a held link survives expiry and erasure; first run after release; the hash test vectors; `--apply` refused without connecting; no release path in the CLI; O10 cases (live link after marker expiry, re-erasure, restore drill) |
| **Gate (O11)** | An ADR evaluating database-enforced lookup restrictions, prepared | Before P3 starts. What it must evaluate is listed in the decision record, O11 | O11: decided | The ADR exists before any P3 work; the reviewer checks it at P3's approval |
| **P3** Tenant initiators (final phase of the reference mechanism) | Tenant link, marker and hold tables; writers produce `initiated_by` references, which lifts D2's gate; TA-5's platform-marked rows write `owner_user_subject_ref` (OD-3); expression index built `CONCURRENTLY`; tenant lookup, erasure and expiry | After P2 and the O11 ADR | O3 decided (2026-11-03, merge preparation: option (b), deferred to P3); everything else for TA-3 and OD-3 is decided | Cross-tenant lookup refused by RLS alone and by the predicate alone (proposal, section 4.3, item 6); isolation-level refusal; index build and `INVALID` index check; D5 digests recompute identically; OD-3 tests (decision record) |
| **P4** Remaining tenant targets and related parties | TA-2 (erasure evidence), TA-4, TA-5 (tenant-internal rows only), TA-6 and PA-10 guidance, using tenant references or omission as decided per field | After P3 (needs tenant references) | **Needed:** a decision to extend the policy's mechanism beyond D6 to tenant targets; per-field choices (section 3); how erasure is to be proven (TA-2) | Per field: the new shape is written, the old key is absent from new rows, readers handle both; erasure evidence verifiable as decided |
| **P5** Actors and operator identities | TA-1 and PA-1 (actor references; CHECK relaxed; digest format v2), PA-5 (declared runner, not an actual operator under OD-1), and PA-4, PA-8's `operator_id` and PA-9 under an operator retention policy | After P3; needs an ADR amending ADR-0053 (format v2) and the separate operator policy (D6) | **Needed:** lifting the O1 exception; the operator retention policy; digest format v2 | The v2 verifier reads v1 windows unchanged; the CHECK accepts a reference and refuses neither id nor reference; operator lifecycle evidence intact |
| **P6.1** Invitation e-mail erasure (first priority of P6) | **Implemented (2026-11-04).** `erase_user_identity` deletes the invitations addressed to the erased person in the listed tenants (OP-6, and OP-8 with them): design and implementation notes in section 6.1 | Independent of P0–P5 and of every open decision; blocks nothing else | Implementation approved by the owner ("Apply invited_email erasure fix"); no policy decision was open for it | Section 6.1, item 7, with its negative controls (PostgreSQL tests in `tests/core/identity/test_erasure_integration.py`) |
| **P6** Outbox and operational data (rest) | Retention for published outbox events (OB-1 to OB-4); retention periods for the operational columns that erasure keeps (OP-7, OP-9, OP-12 to OP-39) | Independent of P1–P5; depends on a compliance target (`docs/DATA-ARCHITECTURE.md` section 8) | **Needed:** a data retention decision per table; outside the audit identity policy | Per decision: pruning jobs, erasure coverage tests, tenant-purge tests unchanged |
| — | Legacy rows (D5) | Never in this policy; in-place redaction would need an ADR amending ADR-0051 and ADR-0053 | D5: decided (no rewrite) | ADR-0053 verification across every phase above shows no change to existing windows |

**Inventory pin test (proposed for P1).** An architecture test should fail when a new place to store a raw user id appears without a classification here. It would pin:
- every column that references `core.users.id`, and every column named like `*_user_id`, `*_principal_id`, `*email*`, `subject`;
- every platform `target_type` value;
- every literal audit metadata key whose value is built from a user id.

Its negative control adds an unclassified column, or a metadata key named `*_user_id`, and the test fails.

**What remains identifiable after P3, if P4 to P6 are not approved.** TA-1, TA-2, TA-4, TA-5 (the tenant-internal rows), TA-6, PA-1, PA-4, PA-5, PA-7 to PA-10 (PA-3's person through PA-7 and OP-19), every operational column, `invited_email` of invitations addressed to an erased person in a tenant not named in the erasure, or at an address neither declared nor verified nor carried by an accepted invitation (P6.1 limits), and the actor columns `inviter_user_id` and `revoked_by_user_id`, the outbox fields until tenant purge or erasure, and every legacy row (D5). The privacy notice must list these as identification kept beyond two years.
