# Raw user identifiers stored by SaaS OS: inventory and phased privacy remediation

**Status: Inventory and remediation design. Documentation only; nothing is implemented. The phases in section 9 are proposals; each needs separate implementation approval, and the later phases need owner decisions that have not been taken.** The inventory was verified against the code of branch `feat/system-actor-step1` at `1e9e215`. The last code change on that branch is `e148526`; everything after it is documentation. Owner decisions referred to here are recorded in `docs/architecture/AUDIT-IDENTITY-OPEN-ITEMS-DECISION-BRIEF.md` (the decision record), and the reference mechanism is designed in `docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md` (the proposal). Date: 2026-11-03.

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
- Product tables and product metadata or payload keys: Core cannot detect a user id in them (O5).
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
- **Decided scope:** two are in the decided scope of the reference mechanism: TA-3 (gated by D2, then tenant references in P3) and PA-2 (D6, P1, for targets who are not operators, O2). PA-6 is covered by the D2 gate extension in PR #201.
- **Temporary exception:** TA-1 is the decided temporary exception (O1). PA-1, PA-3, PA-4 and PA-7 to PA-9 are operators' own identities, excluded by D6.
- **Not yet decided:** every other entry is an outstanding risk or outside the audit policy, and needs a decision before it can be remediated (section 9).

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
  - **Operator ids.** Platform operations write rows in the tenant's trail naming the **operator** as actor: `record_platform_key_revocations` (`saas_os/core/api_keys/service.py:860`), outbox replay (`saas_os/core/outbox/replay.py:167`), feature-flag overrides (`saas_os/core/feature_flags/service.py:384`, `:457`) and lifecycle rows (`saas_os/core/tenancy/authority.py:216`).
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
- **Decision.** None; an outstanding risk. **D2 gate: no**, because the owner of the revoked key is not the requester.
- **Interaction with P1 (open point OD-3).** P1 replaces the platform row's target user with a reference (D6). The same person stays named raw in these tenant rows, which tenant administrators and application code can read. The owner's text does not cover this, because D6 is limited to platform audit records. Options:
  - (a) Leave it to phase P4, and say in the P1 release notes that P1 does not cover it.
  - (b) In P1, omit `owner_user_id` from new platform-marked rows: `resource_id` names the key, and `core.api_keys.user_id` names its owner until erasure deletes the key.
  - (c) After P3, write a tenant reference.
  - Recommendation: (b) together with P1. It removes the leak without new tables, and the tenant administrators keep the key id and the platform marker. It is a change to the row shape, so it needs the owner's approval.
- **Migration strategy.** As above. No schema change.
- **Compatibility.** A metadata key change for readers of `api_key.revoke` rows.

### TA-6 `core.audit_log.metadata["proposer_user_id"]` (`control_plane.action_approved`)

- **Writer.** `approve()` → `record_audit_event` at `saas_os/control_plane/approvals/service.py:143`, key at `:153`. Only the successful approval writes it; the proposal row (`:72`) has the proposer as actor.
- **Purpose and role.** Related party. It is the evidence that the approver (the row's actor) is not the proposer.
- **Decision.** None; an outstanding risk. **D2 gate: no.** The proposer did request the action being approved, but this row records the approval, whose requester is the approver. The key exists to evidence separation of duties, and refusing it would remove that evidence.
- **Note.** `control_plane.approval_requests.proposer_user_id` (OP-24) holds the same id indefinitely (`DEFERRED_POLICY`), so a reference here protects little until that table has a policy.
- **Migration strategy (phase P4 or P5).** A tenant reference after P3, decided together with the actor exception (TA-1), because the same row's actor is the approver.
- **Compatibility.** A metadata key change for AI Control Plane audit readers.

### TA-7 Product metadata keys

- **Writers.** Any product call to the tenant writers. Core cannot tell a user id from any other UUID in them.
- **Decision.** O5 (open): this is a product obligation. **D2 gate:** only the reserved key `initiated_by`, which products cannot write (`ReservedMetadataKeyError`). The gate cannot reach other product keys without knowing what they mean.
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
- **Decision.** D6 (operator identities excluded) and O1 (a temporary exception). **D2 gate: no.** It records the actor, and refusing it would leave operator acts unaudited.
- **Migration strategy (phase P5).** Only under a separate operator retention policy. The schema change is TA-1's, made on the platform table, with digest format v2.
- **Compatibility.** `list_platform_audit(actor_user_id=...)` and `GET /platform/audit` readers.

### PA-2 `core.platform_audit_log.target_id` when `target_type = 'user'`

- **Writers.**
  - `saas_os/core/identity/user_authority.py:135` (`_record_outcome`, refusal or failure rows of every user operation), `:170` (`_record_success`: session revoke, API-key revoke, deactivate, reactivate) and `:299` (refused erasure of an enrolled operator).
  - `resolve_user` (`:441-447`) through `run_oversight_read`. The attempt row (`oversight.py:174`) carries the user id that was asked for, and the completion row (`:189`) carries the user that was found (`target_id=str(user.id)`, `user_authority.py:439`). Refusals of that read go through `oversight.py:170` and `:203`.
  - The refusal rows of `enroll_operator` (`saas_os/core/platform_authority/service.py:134`, through `_run`, called with `target_type="user"` at `:357`).
- **Purpose and role.** Target.
- **Decision.** D6 is the first scope (P1), and O2 classifies the target when the row is written: a user who is not an actual operator gets a platform reference under `target_type = 'user_subject'`; an actual operator stays raw. What counts as an actual operator, and whether the rule extends beyond enrolments, are OD-1 and OD-2. Unknown user ids are O6.
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
- **Purpose and role.** Operator self: the user behind the operator id in `target_id`.
- **Decision.** D6: excluded, under the separate operator policy. **D2 gate: no**, because it names the operator acted on.
- **Migration strategy (phase P5).** Only under the operator policy. `core.platform_operators.user_id` (OP-19) keeps the same id in any case.
- **Compatibility.** Operator-history readers.

### PA-4 `core.platform_audit_log.metadata["filters"]["actor_user_id"]`

- **Writer.** `list_platform_audit` builds `request_metadata["filters"]` (`saas_os/core/platform_authority/oversight.py:513-519`, key at `:516`). The attempt row is written through `record_oversight_attempt` (`oversight.py:174`).
- **Purpose and role.** The value is the filter an operator asked for, normally an operator id: who did what was asked about, recorded as asked, never as found.
- **Decision.** D6: an operator's audit read about operators. **D2 gate: no**, because it is a request filter, not an initiator.
- **Migration strategy.** None planned. If the filter could name a non-operator, P5 would record a platform reference instead.
- **Compatibility.** None until then.

### PA-5 `core.platform_audit_log.metadata["run_by_user_id"]` (tenant purge)

- **Writers.** `purge_tenant` adds it from `--actor` (`saas_os/core/tenancy/service.py:1793-1795`). It goes into the platform rows `record_platform` at `:1836` and `:1953` (`saas_os/core/tenancy/authority.py:175`).
- **Purpose and role.** Actor, declared: the person who ran the command. The row's own actor is the `TENANT_PURGE` system purpose.
- **Decision.** None. It is an actor, not a target, so it is outside D6's scope. Whether it falls under the operator policy depends on whether the runner is an operator, which the command does not check. **D2 gate: no**, because it names who ran the act.
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
- **Decision.** All three are D6, operator self. **D2 gate: no**, because none of them is an initiator.
- **Migration strategy (phase P5).** Only under the operator policy.

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
| OP-6 | `core.invitations.invited_email` | `saas_os/core/identity/service.py:919` | contact data of the invitee (target) | `OPERATIONAL_PURGE`; **kept** |
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

**Findings for the owner.** Neither of these is in the decided scope, and both need a decision:

- An erased person's e-mail address stays in `core.invitations.invited_email` (OP-6) until tenant purge, and erasure does not look at it.
- Every actor column above, together with the platform operator tables, keeps the user id indefinitely, because `DEFERRED_POLICY` and `SECURITY_RETAIN` tables have no expiry.

**Migration strategy and compatibility (phase P6).** These depend on a retention decision for each table, which is not part of the audit identity policy. Possible changes:

- extend erasure to invitations addressed to the erased person's e-mail address;
- set retention periods for `DEFERRED_POLICY` tables once the AI Control Plane's drain and disposition are decided (`saas_os/core/tenancy/retention.py`, `DEFERRED_POLICY`);
- use references for actor columns, which is the same question as TA-1.

Each change alters what products and operators read from these tables.

## 7. Outside the database (not counted)

- **Application logs** carry user ids in structured fields: for example `auth_logout` (`saas_os/api/auth/routes.py:381`), `platform_bootstrap_completed` (`saas_os/api/platform_bootstrap.py:279-284`), `tenant_bootstrap_completed` (`saas_os/api/tenant_bootstrap.py:527-534`) and `user_deactivation_retry` (`saas_os/core/identity/user_authority.py:745`). Their retention is the deployment's logging configuration. Whether logs follow the two-year rule is open (proposal, section 10).
- **URLs.** `GET /platform/users/{user_id}` and the user operation routes carry the user id in the path, and so in access logs. The proposed lookup routes use `POST` for this reason (proposal, section 4.5).
- **Redis.** It holds outbox event ids and claim tokens only (`docs/CONSUMER-GUIDE.md`). arq keeps job keys for about 24 hours.
- **Backups** contain every table above, for `BACKUP_RETENTION_COUNT` runs (default 7), and bring back removed identification on restore (proposal, section 4.12).
- **ADR-0053 digest log lines** contain hashes and counts only, never row contents.

## 8. Why the D2 gate stays on `initiated_by`

D2 and O1 refuse one thing: a raw user id recorded as the **initiator** of an act. Every other field above records something else, and refusing it would refuse the act or remove evidence that a rule requires:

- **Actors** (TA-1, PA-1, PA-5, every `*_by_user_id`): an audit row must say who did the act (ADR-0031), and the CHECK constraints require it.
- **Targets** (TA-2, TA-4, PA-2, OB-2/OB-3): refusing would make operations on people unauditable. D6 provides references for platform targets instead.
- **Resource owners and related parties** (TA-5, TA-6): these keys exist as evidence of the operation or of separation of duties.
- **Operator self** (PA-3, PA-4, PA-7 to PA-9): excluded by D6.
- **Free text and product keys** (PA-10, TA-7, OB-5): Core cannot know what they mean.

The gate applies only where the meaning is the same: TA-3 on the tenant table, and PA-6, the same key on the platform table, which PR #201 is covering.

## 9. Consolidated remediation design (phased)

Each phase is its own PR, with migration review where it changes the schema, and needs the owner's implementation approval. Approval of one phase does not imply approval of the next. "Decided" refers to the decision record.

| Phase | What changes | Order and dependencies | Owner decisions | Tests that prove it |
|---|---|---|---|---|
| **P0** D2 gate | Tenant writers refuse a user initiator (TA-3); `record_platform_event_in_transaction` refuses one in `metadata["initiated_by"]` (PA-6); consumer guide | PR #201; #196 and #201 are one compatibility unit (#196 never merged without #201) | D2, O1: decided | In PR #201 (its authority): refusal before insert on every path, no raw user initiator in any new row of either table, outbox erasure tests unchanged, negative controls |
| **P1** Platform targets | Platform link, marker and hold tables; references for PA-2 with the write-time operator classification; `target_type = 'user_subject'`; lookup routes; platform erasure step; the link-table architecture test (O11 interim); an inventory pin test (below) | After P0. The lookup needs PR #198 (the `platform.security_retention:report` permission) and the register PR (independent register eligibility) merged; amendment of ADR-0045's route table; SQL review (proposal, section 8) | D1, D3, D6, O2, O4, O11: decided. **Needed:** OD-1, OD-2 (classification), OD-3 (TA-5's platform-marked rows; recommendation (b) in this phase), O6 (unknown user ids) | Decision record, D1, D3, O2, O4 and O11 entries: one reference per UTC day, concurrency, collision retry; refusal without the permission, without eligibility, inside the 120-day delay and after revocation; attempt rows before reads; architecture test with negative control; FK behaviour for unknown ids |
| **P2** Holds and expiry | Hold routes (place and release through the API; a CLI that can only place); the expiry command with dry run, confirmations and report job; `--apply` behind a literal `False` gate; markers expire under the same command | After P1 | D4, D7, D8, O8, O9, O10 and the exact two-year rule: decided. **Needed:** the hold route permission (reusing `platform.security_retention_hold:manage` adds none); for `--apply`, an authenticated, register-eligible approval mechanism, implemented, independently reviewed and tested (O9) | The test vectors of the exact rule (leap day, UTC first, inclusive boundary); a held link survives expiry and erasure; first run after release; the hash test vectors; `--apply` refused without connecting; no release path in the CLI; O10 cases (live link after marker expiry, re-erasure, restore drill) |
| **Gate (O11)** | An ADR evaluating database-enforced lookup restrictions, prepared | Before P3 starts. What it must evaluate is listed in the decision record, O11 | O11: decided | The ADR exists before any P3 work; the reviewer checks it at P3's approval |
| **P3** Tenant initiators (final phase of the reference mechanism) | Tenant link, marker and hold tables; writers produce `initiated_by` references, which lifts D2's gate; expression index built `CONCURRENTLY`; tenant lookup, erasure and expiry | After P2 and the O11 ADR | O3 (sequencing) still open; everything else for TA-3 is decided | Cross-tenant lookup refused by RLS alone and by the predicate alone (proposal, section 4.3, item 6); isolation-level refusal; index build and `INVALID` index check; D5 digests recompute identically |
| **P4** Remaining tenant targets and related parties | TA-2 (erasure evidence), TA-4, TA-5 (rows inside the tenant), TA-6 and PA-10 guidance, using tenant references or omission as decided per field | After P3 (needs tenant references) | **Needed:** a decision to extend the policy's mechanism beyond D6 to tenant targets; per-field choices (section 3); how erasure is to be proven (TA-2) | Per field: the new shape is written, the old key is absent from new rows, readers handle both; erasure evidence verifiable as decided |
| **P5** Actors and operator identities | TA-1 and PA-1 (actor references; CHECK relaxed; digest format v2), PA-3, PA-4, PA-5, PA-7 to PA-9 under an operator retention policy | After P3; needs an ADR amending ADR-0053 (format v2) and the separate operator policy (D6) | **Needed:** lifting the O1 exception; the operator retention policy; digest format v2 | The v2 verifier reads v1 windows unchanged; the CHECK accepts a reference and refuses neither id nor reference; operator lifecycle evidence intact |
| **P6** Outbox and operational data | Retention for published outbox events (OB-1 to OB-4); erasure of invitations by e-mail address (OP-6); retention periods for the operational columns that erasure keeps (OP-7 to OP-9, OP-12 to OP-39) | Independent of P1–P5; depends on a compliance target (`docs/DATA-ARCHITECTURE.md` section 8) | **Needed:** a data retention decision per table; outside the audit identity policy | Per decision: pruning jobs, erasure coverage tests, tenant-purge tests unchanged |
| — | Legacy rows (D5) | Never in this policy; in-place redaction would need an ADR amending ADR-0051 and ADR-0053 | D5: decided (no rewrite) | ADR-0053 verification across every phase above shows no change to existing windows |

**Inventory pin test (proposed for P1).** An architecture test should fail when a new place to store a raw user id appears without a classification here. It would pin:
- every column that references `core.users.id`, and every column named like `*_user_id`, `*_principal_id`, `*email*`, `subject`;
- every platform `target_type` value;
- every literal audit metadata key whose value is built from a user id.

Its negative control adds an unclassified column, or a metadata key named `*_user_id`, and the test fails.

**What remains identifiable after P3, if P4 to P6 are not approved.** TA-1, TA-2, TA-4, TA-5 (the tenant-internal rows, and the platform-marked rows unless OD-3 (b) is adopted), TA-6, PA-1, PA-3 to PA-5, PA-7 to PA-10, every operational column, the outbox fields until tenant purge or erasure, and every legacy row (D5). The privacy notice must list these as identification kept beyond two years.
