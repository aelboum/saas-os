# Owner decision D2: audit-writer callsite and consumer audit

**Status: audit record for PR #201 (the D2 gate), 2026-11-03.** It describes the code on the branch `feat/audit-d2-initiator-gate` (stacked on `feat/system-actor-step1`, PR #196); #196 and #201 are one compatibility unit and are never merged separately. Line numbers are those of this branch at the commit that last changed this document.

**Decisions this applies (owner, 2026-11-02 and 2026-11-03, decided):** D2 "Until the new reference/link-table mechanism is implemented, reject user initiators in audit records. Do not store raw user IDs in new audit records. Preserve the existing outbox erasure behaviour." O1: "D2 applies to `initiated_by`. [...] Existing mandatory `actor_user_id` storage remains a temporary exception because current database constraints require it for user-actor records." D2 rejects new user initiators in `initiated_by`; the tenant audit-writer gate is accepted in principle; `actor_user_id` is the documented temporary exception and is not touched here. Background: `docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md` (on #196).

## 1. Result

- **No SaaS OS code path can store a user initiator in a new audit row.** No Core or in-repo example callsite passes `initiated_by=` to an audit writer, and none builds metadata with an `initiated_by` key at any depth (sections 4 and 5). A user initiator can come only from a caller of a public writer, and every public way in is gated (section 3).
- **Two ways in were open on `bae8862` and are closed by this change:** an `initiated_by` key nested inside the metadata of a tenant writer (only a top-level key was refused), and any `initiated_by` key in the metadata of the platform writers, which had no initiator check at all.
- **No consumer on this machine passes, or can pass, a user initiator** (section 6). None uses `Initiator`, `initiated_by`, `record_system_action_in_transaction` or a platform writer's metadata. None needs a change for D2. Every one pinned before the `saas_os` import root (LeadStack, ai-agent, ChronoGaz, MarketStack) needs the import-root change for any upgrade to #196+#201; that change is independent of D2.

## 2. Method

1. Every call of an audit writer under `saas_os/`, `examples/`, `products/` and `scripts/` was listed from the syntax tree (Python `ast`), following import aliases (`record as record_audit_event`, `from saas_os.core import audit_log`) and function-local imports: `record`, `record_in_transaction`, `record_system_action_in_transaction`, `record_platform_event_in_transaction`, `record_oversight_attempt`, `record_platform_refusal`, `recording_platform_refusal`, `record_operator_session_issued_in_transaction`, the helper `run_oversight_read` (which forwards `request_metadata` to `record_oversight_attempt`), and the outbox producer `append_event` (which forwards an `Initiator`). Result: **136 callsites** (section 5).
2. For each callsite, the metadata argument was classified: none, a literal with fixed keys, or a variable. Every variable was traced by hand to where it is built (wrappers such as `_audit`, `record_billing_audit`, `record_platform`, `_record_lifecycle_event` were followed to each of their callers). Every one is built by Core with fixed keys, except the forwarding parameters of the public writers themselves (marked PUBLIC).
3. `initiated_by`, `Initiator`, `from_caller`, `from_job_initiator` and `INITIATED_BY` were searched in all of `saas_os/`. They occur only in `saas_os/core/authority/attribution.py` (the type), `saas_os/core/audit_log/` (the writers and the gate), `saas_os/core/outbox/` (`append_event`, `_split_initiator`, erasure), `saas_os/api/outbox_dispatcher.py` (`_job_initiator`, which hands the event's initiator to the consumer context) and `saas_os/infra/jobs/context.py` (`JobInitiator`). None of these forwards an initiator to an audit writer.
4. Rows are built only by the writers: `AuditLogEntry(...)` only in `saas_os/core/audit_log/service.py` (`_validated_entry`), `PlatformAuditLogEntry(...)` only in `saas_os/core/platform_authority/audit.py` (`_entry`; pinned by `tests/architecture/test_platform_authority_contract.py`).
5. The four in-repo outbox consumers (`saas_os/api/outbox_dispatcher.py` `outbox_event_handlers()`: webhooks, usage, notifications, billing projections) write no audit row (none of their modules' audit calls is in a consumer path), so none reads `context.initiated_by` into an audit writer. A product cannot register an outbox event handler of its own (`outbox_event_handlers()` returns Core's four); `context.initiated_by` reaches a product only through those Core handlers or a test.

## 3. Gates

| Gate | Where | What it refuses | Error |
|---|---|---|---|
| G1 | `_require_attribution_types` (`saas_os/core/audit_log/service.py`), called by `record_in_transaction` and, through `_attribution`, `record_system_action_in_transaction` | a typed `initiated_by=` that is not `None` and not an `Initiator` of type service account or system (allowlist `AUDIT_INITIATOR_TYPES`) | `InvalidActorError` |
| G2 | `_refuse_reserved_metadata` (same file), all three tenant writers | a caller-supplied top-level `initiated_by` key (also `system_actor`, `correlation`; any case or padding), whatever it holds | `ReservedMetadataKeyError` |
| G3 | `refuse_user_initiators` (`saas_os/core/audit_log/metadata.py`), called in `_validated_entry` on the final metadata of every tenant row | any `initiated_by` key, any case or padding, at any depth inside dicts, lists and tuples, holding anything but `None`, `"unavailable"` or the exact recorded shape of a service-account or system initiator (`Initiator.as_metadata()`) | `InvalidActorError` |
| G4 | the same `refuse_user_initiators`, called in `_entry` (`saas_os/core/platform_authority/audit.py`) for every platform row | as G3 | `InvalidActorError` |

All four run before the insert. The messages name no id and no key path. A refused user initiator is never converted to `None`: the write fails. `None` is still recorded as `"unavailable"` where the tenant writers did so before (the typed argument); a `None` placed in metadata is stored as given. G3 also re-checks the attribution the tenant writers themselves write under the top-level key (defence in depth behind G1).

**G5, system initiators and actors (review of `25c9a77`, MEDIUM).** An allowlisted system shape could still carry a user id: `Initiator.system(actor, record_type="user", record_id=<user id>)` or `SystemActor(kind, "user.<uuid>")`. Enforced at construction in `saas_os/core/authority/attribution.py` and `saas_os/core/authority/system_actor.py` (`InvalidSystemActorError`, naming the field only), and therefore also for serialized shapes, which G3/G4 parse with `Initiator.from_metadata`: a `record_type` that names a principal (words split at `_ . : -`: any word starting with `user`; `member(s)`, `membership(s)`, `principal(s)`, `operator(s)`, `person(s)`, `people`, `identity`, `identities`, `subject(s)`, `owner(s)`, `actor(s)`; `account(s)` bare or after `service`) or embeds a UUID; a string `record_id` whose first word names a principal (only the first word, so an opaque provider id with a random tail is not misread); a `SystemActor` name that embeds a UUID (hyphenated or 32 hex digits). Record types are product-chosen (`provider_event`, `unsubscribe_link`), so an allowlist of types was not feasible; the closed word rule is the alternative. `billing_account` and `merchant_account` name records and stay accepted. A UUID `record_id` beside a non-principal `record_type` is accepted: it identifies that record. Because such values can no longer be built, `append_event` cannot store them either, so user erasure (which rewrites user-shaped initiators only) has nothing to miss. The UUID check ignores the separators `- _ . :`, so an id split by any of them is found (re-review of `549c6d8`). The tenant writers also re-validate a typed `Initiator` by round trip (`Initiator.from_metadata(initiated_by.as_metadata())` must give back the same shape), so one assembled around its validation with `object.__new__`/`object.__setattr__` is refused (`InvalidActorError`). The executing actor written under `system_actor` (by `record_system_action_in_transaction` and by `record_in_transaction` for a `SystemCaller` with an actor) is re-validated the same way, by rebuilding a `SystemActor` from its recorded shape (re-review of `8a21d39`). The platform writers record no `system_actor`. Since the re-review of `acf43f5`, both are rebuilt from their *fields* (each exactly type-checked) through the constructors, and only the rebuilt object's own shape is stored, never anything the caller's object returns (a forged `as_metadata` returning a dict that claims to equal anything cannot add keys).

**Threat model.** Deliberate in-process forgery (`object.__new__`, `object.__setattr__`, instance-level method overrides) is outside the threat model: code running in the process can insert audit rows directly with the application role. These checks only guarantee that such an object cannot make the writers store anything a validly constructed value could not. This is the last hardening round for this class.

**This word rule is a guard against mistakes, not a security boundary.** It catches the honest slip (`record_type="user"`, `user:42`, a UUID pasted into a component name), not deliberate obfuscation, which it does not detect: an abbreviation or other word (`usr`, `uid`, `acct_holder`, `customer`), an id in another encoding (base64, decimal, a hash of the id), an id that is not in the first word of a `record_id` (`evt_<user uuid>`, `link:<user uuid>`), or a bare user UUID as the `record_id` of a non-principal `record_type` (indistinguishable from any record's UUID). Keeping user ids out of system initiators remains the caller's obligation under D2.

Refused, by G3/G4: a user shape (`{"type": "user", "user_id": ...}`), an `Initiator` object of any type, a bare user id or any other string except exactly `"unavailable"`, a list, a number, an empty dict, a shape with an extra field (for example a service account with a `user_id`) or a nested value, a null `record_type`/`record_id`, an unknown type, a non-canonical id spelling. Not D2's business: other key names (`initiator`, `requested_by`, `user_id`, `owner_user_id`; O1 limits D2 to `initiated_by`, and product key names are a product obligation, O5 of the proposal).

### Public ways in (where a caller can supply an initiator)

| Public function | Parameter that can carry an initiator | Gate | Outcome of a user initiator |
|---|---|---|---|
| `saas_os.core.audit_log.record` | `metadata` | G2 (top level), G3 (nested) | raises before the write; nothing written |
| `saas_os.core.audit_log.record_in_transaction` | `initiated_by`, `metadata` | G1, G2, G3 | raises before the insert; the caller's transaction rolls back with the change |
| `saas_os.core.audit_log.record_system_action_in_transaction` | `initiated_by`, `metadata` | G1, G2, G3 | as above |
| `saas_os.core.platform_authority.record_platform_event_in_transaction` | `metadata` | G4 | raises before the insert; the transaction rolls back |
| `saas_os.core.platform_authority.record_oversight_attempt` | `metadata` | G4 | raises; no attempt row; the read must not run |
| `saas_os.core.platform_authority.run_oversight_read`, `run_tenant_oversight_read` | `request_metadata` | G4 (through `record_oversight_attempt`) | raises; no attempt row; nothing read |
| `saas_os.core.platform_authority.run_platform_change` | `PlatformChange.metadata` returned by `change` | G4 | raises; the change rolls back; no row |
| `saas_os.core.platform_authority.record_platform_refusal` | `metadata` | G4 | the metadata is refused (not stored, not turned into `None`); the `denied` row is still written, with the fixed marker `{"metadata_refused": "d2"}` in its place (review of `25c9a77`); log `platform_refusal_metadata_refused`, no id |
| `saas_os.core.platform_authority.recording_platform_refusal` | `metadata` | G4 (through `record_platform_refusal`) | the refusal is re-raised unchanged; the `denied` row is written with the marker, as above |
| `saas_os.core.platform_authority.record_operator_session_issued_in_transaction` | none (fixed metadata) | n/a | n/a |
| `saas_os.core.outbox.append_event` | `initiated_by` | none by decision | D2 preserves outbox storage: the user initiator is stored with the event, handed to the consumer, and rewritten on erasure; the consumer's audit write is gated (section 7) |

Before this change (`bae8862`) G1 and G2 existed; G3 and G4 did not, so a nested key in tenant metadata and any key in platform metadata could store a user id under `initiated_by`.

## 4. Findings about the callsites

- **0** callsites pass `initiated_by=` to an audit writer (35 `record`, 43 `record_in_transaction`, **0** `record_system_action_in_transaction`).
- **0** callsites build an `initiated_by` key, top level or nested. The only variable metadata reaching a writer from outside Core is the forwarding parameter of a public writer (5 PUBLIC rows in section 5).
- `append_event` (4 Core producers) never passes `initiated_by`: Core's own outbox events carry no initiator, so Core's consumers always see `context.initiated_by = None`.
- Raw user ids that new audit rows still hold outside `initiated_by` (not D2's scope under O1, listed for the retention work): `actor_user_id` (decided temporary exception); metadata `owner_user_id` (`saas_os/core/api_keys/service.py`), `proposer_user_id` (`saas_os/control_plane/approvals/service.py`), `user_id` (`saas_os/core/identity/service.py`, `saas_os/core/platform_authority/service.py`), `filters.actor_user_id` (`list_platform_audit`), and **`run_by_user_id`** in the platform rows of a tenant purge (`saas_os/core/tenancy/service.py` `purge_tenant`, written through `record_platform`, row 126 below: the operator's declared id). `run_by_user_id` is listed in #196's raw-identity inventory at `77d0680` (`docs/architecture/AUDIT-RAW-IDENTITY-INVENTORY.md`, PA-5) and in section 2.4 of the retention proposal there.

## 5. Every callsite

G1 to G4 as in section 3. "Core-built keys": the metadata is built by Core with fixed key names, none of them `initiated_by`; the gate still runs on it.

### Tenant audit writers (`core.audit_log`)

| # | Callsite | Writer | In | Metadata passed | `initiated_by` reachable | Gate |
|---|---|---|---|---|---|---|
| 1 | `saas_os/api/dependencies.py:625` | `record` | `_dependency` | none | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 2 | `saas_os/api/dependencies.py:669` | `record` | `_dependency` | none (`**_audit_actor(context)` passes actor columns only) | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 3 | `saas_os/api/dependencies.py:742` | `record` | `_dependency` | none (`**_audit_actor(context)` passes actor columns only) | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 4 | `saas_os/api/tenant_bootstrap.py:286` | `record` | `_audit` | `{bootstrap, **metadata}`; callers `:307` none, `:339` `{from_status, to_status}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 5 | `saas_os/control_plane/approvals/service.py:72` | `record` | `propose_action` | literal `{tool_key: tool_key}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 6 | `saas_os/control_plane/approvals/service.py:118` | `record` | `approve` | literal `{reason: self_approval_not_allowed}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 7 | `saas_os/control_plane/approvals/service.py:143` | `record` | `approve` | literal `{tool_key: approval.tool_key, proposer_user_id: str(approval.proposer_user_id)}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 8 | `saas_os/control_plane/approvals/service.py:179` | `record` | `reject` | literal `{tool_key: approval.tool_key}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 9 | `saas_os/control_plane/data_authorization/service.py:139` | `record` | `authorize_data_access` | local dict, fixed keys (`denial_reason` added on denial) | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 10 | `saas_os/control_plane/inference/config/tenant_policy.py:108` | `record` | `_record_denied` | literal `{reason: not_authorized}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 11 | `saas_os/control_plane/inference/config/tenant_policy.py:148` | `record_in_transaction` | `_authorized_change` | second value of the four Core `change` closures, fixed keys (`change`, `enabled`, `use_case`, ...) | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 12 | `saas_os/control_plane/inference/service.py:305` | `record` | `_record_denied` | `{reason}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 13 | `saas_os/control_plane/orchestration/service.py:168` | `record` | `_audit` | `{tool_key}` plus `extra_metadata` from 5 Core callers, fixed keys (`denied_gate`, ...) | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 14 | `saas_os/control_plane/self_learning/adaptive/service.py:116` | `record` | `_audit` | wrapper `_audit`; caller `:250` fixed keys | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 15 | `saas_os/control_plane/self_learning/adaptive/service.py:141` | `record_in_transaction` | `_audit_in_transaction` | wrapper `_audit_in_transaction`; callers `:374`, `:444` fixed keys | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 16 | `saas_os/control_plane/self_learning/autonomous_improvement/service.py:274` | `record` | `_audit` | wrapper `_audit`; callers `:582`, `:778`, `:824`, `:859`, `:935` fixed keys | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 17 | `saas_os/control_plane/self_learning/autonomous_improvement/service.py:299` | `record_in_transaction` | `_audit_in_transaction` | wrapper `_audit_in_transaction`; callers `:647`, `:706`, `:729` fixed keys | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 18 | `saas_os/control_plane/self_learning/continuous_loop/service.py:237` | `record` | `_audit` | local dict in `_audit`, fixed keys (`seed_source_kind`, ...) | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 19 | `saas_os/control_plane/self_learning/evaluation/service.py:283` | `record` | `run_evaluation` | local dict, fixed keys | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 20 | `saas_os/control_plane/self_learning/experiments/service.py:118` | `record` | `_audit` | wrapper `_audit`; callers `:224`, `:271`, `:384` fixed keys, `:345` local dict with fixed keys | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 21 | `saas_os/control_plane/self_learning/policy_gate/service.py:270` | `record` | `evaluate_and_record_policy_gate_decision` | local dict, fixed keys | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 22 | `saas_os/control_plane/self_learning/service.py:248` | `record` | `authorize_learning_use` | local dict, fixed keys | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 23 | `saas_os/control_plane/self_learning/system_learning/service.py:412` | `record` | `propose_system_learning_proposal` | local dict, fixed keys | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 24 | `saas_os/control_plane/self_learning/system_learning/service.py:462` | `record` | `withdraw_system_learning_proposal` | literal, fixed keys | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 25 | `saas_os/core/api_keys/service.py:279` | `record_in_transaction` | `create_api_key` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 26 | `saas_os/core/api_keys/service.py:362` | `record_in_transaction` | `create_service_account_api_key` | literal `{service_account_id: str(service_account_id)}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 27 | `saas_os/core/api_keys/service.py:425` | `record` | `validate_api_key` | none | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 28 | `saas_os/core/api_keys/service.py:438` | `record` | `validate_api_key` | none | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 29 | `saas_os/core/api_keys/service.py:466` | `record` | `validate_api_key` | literal `{denied_gate: tenant_lifecycle}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 30 | `saas_os/core/api_keys/service.py:486` | `record` | `validate_api_key` | literal `{denied_gate: inactive_user}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 31 | `saas_os/core/api_keys/service.py:502` | `record` | `validate_api_key` | none | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 32 | `saas_os/core/api_keys/service.py:619` | `record_in_transaction` | `_revoke_locked_key` | `_owner_metadata(key)`: `{owner_user_id}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 33 | `saas_os/core/api_keys/service.py:792` | `record_in_transaction` | `rotate_api_key` | literal `{previous_key_id: str(key_id)}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 34 | `saas_os/core/api_keys/service.py:860` | `record_in_transaction` | `record_platform_key_revocations` | literal `{owner_user_id: str(user_id), platform: True}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 35 | `saas_os/core/billing/authorization.py:231` | `record_in_transaction` | `record_billing_audit` | `record_billing_audit`: `{**metadata, **audit_note}`; 18 Core callers (catalog, commercial, inheritance, parties) with fixed keys; `audit_note` is `{}` or `{trusted_system_reason}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 36 | `saas_os/core/billing/commercial.py:818` | `record` | `_create_commercial_subscription` | fixed keys plus `**extra` from `audit_actor()`: `{}`, `{trusted_system_reason}` or `{system_authority, ...}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 37 | `saas_os/core/billing/commercial.py:1019` | `record_in_transaction` | `_audit_refused_creation` | literal, fixed keys | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 38 | `saas_os/core/billing/commercial.py:1191` | `record` | `_record_payment_page_issued` | fixed keys plus `**details` (fixed keys) and `**extra` (as `:818`) | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 39 | `saas_os/core/billing/commercial.py:1219` | `record` | `_record_payment_page_refused` | `{stage, **extra}` (as `:818`) | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 40 | `saas_os/core/billing/service.py:331` | `record` | `subscribe` | literal `{plan_key: plan_key}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 41 | `saas_os/core/billing/service.py:570` | `record` | `upgrade_subscription` | local dict, fixed keys | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 42 | `saas_os/core/billing/service.py:620` | `record` | `cancel_subscription` | local dict, fixed keys, or none | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 43 | `saas_os/core/feature_flags/service.py:384` | `record_in_transaction` | `_attempt` | literal `{enabled: enabled, platform: True}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 44 | `saas_os/core/feature_flags/service.py:457` | `record_in_transaction` | `remove_tenant_override` | literal `{platform: True}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 45 | `saas_os/core/identity/erasure.py:218` | `record_in_transaction` | `_erase_membership_in_tenant` | literal `{outbox_initiators_erased: outbox_initiators_erased}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 46 | `saas_os/core/identity/erasure.py:241` | `record` | `_erase_membership_in_tenant` | literal, fixed keys | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 47 | `saas_os/core/identity/erasure.py:260` | `record` | `_erase_membership_in_tenant` | literal `{outbox_initiators_erased: outbox_initiators_erased}` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 48 | `saas_os/core/identity/service.py:385` | `record_in_transaction` | `add_tenant_membership` | literal `{user_id: str(user_id)}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 49 | `saas_os/core/identity/service.py:501` | `record_in_transaction` | `create_service_account` | literal `{name: name}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 50 | `saas_os/core/identity/service.py:577` | `record_in_transaction` | `_set_service_account_status` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 51 | `saas_os/core/identity/service.py:731` | `record_in_transaction` | `_transition_membership_status` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 52 | `saas_os/core/identity/service.py:926` | `record_in_transaction` | `create_invitation` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 53 | `saas_os/core/identity/service.py:1020` | `record_in_transaction` | `revoke_invitation` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 54 | `saas_os/core/identity/service.py:1167` | `record_in_transaction` | `accept_invitation` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 55 | `saas_os/core/outbox/replay.py:167` | `record_in_transaction` | `replay_dead_lettered_events` | local dict, fixed keys, plus `platform` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 56 | `saas_os/core/rbac/service.py:327` | `record_in_transaction` | `create_role` | literal `{role_name: name}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 57 | `saas_os/core/rbac/service.py:386` | `record_in_transaction` | `delete_role` | literal `{role_name: role_name}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 58 | `saas_os/core/rbac/service.py:539` | `record_in_transaction` | `grant_permission` | literal, fixed keys | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 59 | `saas_os/core/rbac/service.py:621` | `record_in_transaction` | `revoke_permission` | literal `{permission_id: str(permission_id)}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 60 | `saas_os/core/rbac/service.py:820` | `record_in_transaction` | `_insert_membership_role` | literal `{role_id: str(role_id), scope: scope.value}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 61 | `saas_os/core/rbac/service.py:916` | `record_in_transaction` | `remove_role` | literal `{role_id: str(role_id)}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 62 | `saas_os/core/rbac/service.py:1026` | `record_in_transaction` | `assign_service_account_role` | literal `{service_account_id: str(service_account_id), role_id: str(role_id), scope: scope.value}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 63 | `saas_os/core/rbac/service.py:1112` | `record_in_transaction` | `remove_service_account_role` | literal `{service_account_id: str(service_account_id), role_id: str(role_id)}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 64 | `saas_os/core/rbac/service.py:1229` | `record_in_transaction` | `create_delegation` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 65 | `saas_os/core/rbac/service.py:1344` | `record_in_transaction` | `create_delegation_to_service_account` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 66 | `saas_os/core/rbac/service.py:1448` | `record_in_transaction` | `revoke_delegation` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 67 | `saas_os/core/rbac/service.py:1551` | `record_in_transaction` | `create_deny` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 68 | `saas_os/core/rbac/service.py:1633` | `record_in_transaction` | `create_deny_for_service_account` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 69 | `saas_os/core/rbac/service.py:1723` | `record_in_transaction` | `revoke_deny` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 70 | `saas_os/core/rbac/service.py:1824` | `record_in_transaction` | `create_support_access_request` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 71 | `saas_os/core/rbac/service.py:1961` | `record_in_transaction` | `approve_support_access` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 72 | `saas_os/core/rbac/service.py:2016` | `record_in_transaction` | `deny_support_access` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 73 | `saas_os/core/rbac/service.py:2077` | `record_in_transaction` | `revoke_support_access` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 74 | `saas_os/core/rbac/service.py:2165` | `record_in_transaction` | `revoke_tenant_support_access` | literal `{reason: _TENANT_PURGE_REVOCATION_REASON}` | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 75 | `saas_os/core/tenancy/authority.py:216` | `record_in_transaction` | `record_tenant` | wrapper `record_tenant`; callers `:420`, `:428`, `:689`, `:1455` fixed keys or none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 76 | `saas_os/core/tenancy/service.py:1100` | `record` | `_record_lifecycle_event` | wrapper `_record_lifecycle_event`; callers `:1849`, `:1993` fixed keys, `:2010` `_purge_completed_metadata()` fixed keys and `deleted_<step>` for each Core `PURGE_STEPS` | no (no `initiated_by=`; Core-built keys) | G2, G3 |
| 77 | `saas_os/core/webhooks/service.py:691` | `record_in_transaction` | `subscribe` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |
| 78 | `saas_os/core/webhooks/service.py:756` | `record_in_transaction` | `unsubscribe` | none | no (no `initiated_by=`; Core-built keys) | G1, G2, G3 |

### Platform audit writers (`core.platform_authority`)

| # | Callsite | Writer | In | Metadata passed | `initiated_by` reachable | Gate |
|---|---|---|---|---|---|---|
| 79 | `saas_os/api/dependencies.py:855` | `record_platform_refusal` | `_refused` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 80 | `saas_os/control_plane/inference/config/service.py:990` | `run_oversight_read` | `read_ai_configuration` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 81 | `saas_os/core/billing/oversight.py:159` | `record_oversight_attempt` | `commercial_overview` | literal `{cursor: None if cursor is None else str(cursor), page_size: limit}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 82 | `saas_os/core/billing/oversight.py:167` | `record_platform_refusal` | `commercial_overview` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 83 | `saas_os/core/billing/oversight.py:184` | `record_platform_event_in_transaction` | `commercial_overview` | literal `{attempt_id: str(attempt_id), returned: len(tenant_ids)}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 84 | `saas_os/core/billing/oversight.py:192` | `record_platform_refusal` | `commercial_overview` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 85 | `saas_os/core/billing/oversight.py:197` | `record_platform_refusal` | `commercial_overview` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 86 | `saas_os/core/billing/oversight.py:206` | `record_platform_refusal` | `commercial_overview` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 87 | `saas_os/core/feature_flags/service.py:124` | `recording_platform_refusal` | `create_flag` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 88 | `saas_os/core/feature_flags/service.py:133` | `record_platform_event_in_transaction` | `create_flag` | literal `{enabled_by_default: enabled_by_default}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 89 | `saas_os/core/feature_flags/service.py:239` | `run_oversight_read` | `read_flag_catalog` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 90 | `saas_os/core/feature_flags/service.py:296` | `run_oversight_read` | `read_tenant_flag_overrides` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 91 | `saas_os/core/feature_flags/service.py:328` | `record_platform_event_in_transaction` | `_record_override` | wrapper `_record_override`; callers `:366` `{enabled}`, `:446` `{removed}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 92 | `saas_os/core/feature_flags/service.py:397` | `recording_platform_refusal` | `set_tenant_override` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 93 | `saas_os/core/feature_flags/service.py:430` | `recording_platform_refusal` | `remove_tenant_override` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 94 | `saas_os/core/identity/sessions.py:103` | `record_operator_session_issued_in_transaction` | `issue_session` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 95 | `saas_os/core/identity/user_authority.py:135` | `record_platform_refusal` | `_record_outcome` | wrapper `_record_outcome`; callers in `_run` `:201` `{ceiling}` or none, `:208` `{tenant_id}`, others none | no (no `initiated_by=`; Core-built keys) | G4 |
| 96 | `saas_os/core/identity/user_authority.py:170` | `record_platform_event_in_transaction` | `_record_success` | wrapper `_record_success`; callers `:486`, `:538`, `:683`, `:795` fixed keys | no (no `initiated_by=`; Core-built keys) | G4 |
| 97 | `saas_os/core/identity/user_authority.py:299` | `record_platform_refusal` | `remove_identity_links_unless_enrolled_operator` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 98 | `saas_os/core/identity/user_authority.py:441` | `run_oversight_read` | `resolve_user` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 99 | `saas_os/core/outbox/replay.py:128` | `recording_platform_refusal` | `replay_dead_lettered_events` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 100 | `saas_os/core/outbox/replay.py:177` | `record_platform_event_in_transaction` | `replay_dead_lettered_events` | local dict, fixed keys | no (no `initiated_by=`; Core-built keys) | G4 |
| 101 | `saas_os/core/outbox/replay.py:189` | `record_platform_refusal` | `replay_dead_lettered_events` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 102 | `saas_os/core/platform_authority/audit.py:269` | `record_platform_event_in_transaction` | `record_oversight_attempt` | PUBLIC: `record_oversight_attempt(metadata=)` forwarded | yes, whatever the public caller passes | G4 |
| 103 | `saas_os/core/platform_authority/audit.py:394` | `record_platform_refusal` | `recording_platform_refusal` | PUBLIC: `recording_platform_refusal(metadata=)` forwarded | yes, whatever the public caller passes | G4 |
| 104 | `saas_os/core/platform_authority/audit.py:433` | `record_platform_event_in_transaction` | `record_operator_session_issued_in_transaction` | literal `{operator_id: str(enrolled.id)}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 105 | `saas_os/core/platform_authority/bootstrap.py:183` | `record_platform_refusal` | `_require_bootstrap_caller` | `{marker: True}`; `marker` is `"bootstrap"` or `"recovery"` (Core literals) | no (no `initiated_by=`; Core-built keys) | G4 |
| 106 | `saas_os/core/platform_authority/bootstrap.py:308` | `record_platform_refusal` | `bootstrap_platform_owner` | literal `{bootstrap: True}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 107 | `saas_os/core/platform_authority/bootstrap.py:399` | `record_platform_refusal` | `recover_platform_authority` | literal `{recovery: True}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 108 | `saas_os/core/platform_authority/changes.py:68` | `recording_platform_refusal` | `run_platform_change` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 109 | `saas_os/core/platform_authority/changes.py:73` | `record_platform_event_in_transaction` | `run_platform_change` | PUBLIC: `PlatformChange.metadata` of the caller's `change`; Core callers (`control_plane/inference/config/service.py`, 13 changes) fixed keys | yes, whatever the public caller passes | G4 |
| 110 | `saas_os/core/platform_authority/oversight.py:170` | `recording_platform_refusal` | `run_oversight_read` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 111 | `saas_os/core/platform_authority/oversight.py:174` | `record_oversight_attempt` | `run_oversight_read` | PUBLIC: `run_oversight_read(request_metadata=)`; Core callers `_page_metadata` `{cursor, page_size}`, `list_platform_audit` adds `filters`, flags `{cursor, page_size}`, `resolve_user` `{lookup}`, AI usage `{since, until}` | yes, whatever the public caller passes | G4 |
| 112 | `saas_os/core/platform_authority/oversight.py:189` | `record_platform_event_in_transaction` | `run_oversight_read` | literal `{attempt_id: str(attempt_id), returned: outcome.returned}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 113 | `saas_os/core/platform_authority/oversight.py:203` | `record_platform_refusal` | `run_oversight_read` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 114 | `saas_os/core/platform_authority/oversight.py:247` | `run_oversight_read` | `run_tenant_oversight_read` | PUBLIC: `run_tenant_oversight_read(request_metadata=)` forwarded | yes, whatever the public caller passes | G4 |
| 115 | `saas_os/core/platform_authority/oversight.py:363` | `run_oversight_read` | `list_platform_operators` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 116 | `saas_os/core/platform_authority/oversight.py:414` | `run_oversight_read` | `list_platform_grants` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 117 | `saas_os/core/platform_authority/oversight.py:578` | `run_oversight_read` | `list_platform_audit` | `{cursor, page_size, filters: {since, until, actor_user_id, action, target_tenant_id}}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 118 | `saas_os/core/platform_authority/service.py:134` | `record_platform_refusal` | `_run` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 119 | `saas_os/core/platform_authority/service.py:230` | `record_platform_event_in_transaction` | `enroll_in_transaction` | local `{user_id[, previous_operator_id]}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 120 | `saas_os/core/platform_authority/service.py:260` | `record_platform_event_in_transaction` | `_set_status` | literal `{user_id: str(operator.user_id), from: expected.value, to: new.value}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 121 | `saas_os/core/platform_authority/service.py:321` | `record_platform_event_in_transaction` | `grant_in_transaction` | literal `{permission: permission.value, grant_id: str(grant.id), user_id: str(operator.user_id)}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 122 | `saas_os/core/platform_authority/service.py:446` | `record_platform_event_in_transaction` | `body` | literal, fixed keys | no (no `initiated_by=`; Core-built keys) | G4 |
| 123 | `saas_os/core/platform_authority/service.py:526` | `record_platform_event_in_transaction` | `body` | literal `{permission: permission.value, grant_id: str(grant.id), user_id: str(operator.user_id)}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 124 | `saas_os/core/tenancy/authority.py:144` | `recording_platform_refusal` | `refusal_recorded` | wrapper `refusal_recorded`; callers (`tenancy/service.py` `:359`, `:529`, `:1798`, `:1938`) none | no (no `initiated_by=`; Core-built keys) | G4 |
| 125 | `saas_os/core/tenancy/authority.py:165` | `record_platform_refusal` | `record_refusal` | wrapper `record_refusal`; callers `:440`, `:1465` none, `:1359` fixed keys | no (no `initiated_by=`; Core-built keys) | G4 |
| 126 | `saas_os/core/tenancy/authority.py:191` | `record_platform_event_in_transaction` | `record_platform` | wrapper `record_platform`; callers `:417`, `:678`, `:1443` fixed keys or none; `:1836`, `:1953` `{from_status, to_status, **attribution}`, `attribution` `{}` or `{run_by_user_id}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 127 | `saas_os/core/tenancy/registry.py:134` | `recording_platform_refusal` | `list_tenant_registry` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 128 | `saas_os/core/tenancy/registry.py:136` | `record_oversight_attempt` | `list_tenant_registry` | literal `{cursor: None if cursor is None else str(cursor), page_size: limit}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 129 | `saas_os/core/tenancy/registry.py:152` | `record_platform_event_in_transaction` | `list_tenant_registry` | literal `{attempt_id: str(attempt_id), returned: len(entries)}` | no (no `initiated_by=`; Core-built keys) | G4 |
| 130 | `saas_os/core/tenancy/registry.py:193` | `recording_platform_refusal` | `read_tenant_registry_entry` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 131 | `saas_os/core/tenancy/registry.py:197` | `record_oversight_attempt` | `read_tenant_registry_entry` | none | no (no `initiated_by=`; Core-built keys) | G4 |
| 132 | `saas_os/core/tenancy/registry.py:209` | `record_platform_event_in_transaction` | `read_tenant_registry_entry` | literal `{attempt_id: str(attempt_id), returned: 0 if entry is None else 1}` | no (no `initiated_by=`; Core-built keys) | G4 |

### Outbox producers (`append_event`, not an audit writer)

| # | Callsite | Writer | In | Metadata passed | `initiated_by` reachable | Gate |
|---|---|---|---|---|---|---|
| 133 | `saas_os/core/billing/projections.py:147` | `append_event` | `announce_subscription_change` | none | no `initiated_by=` passed: the event stores no initiator | n/a (outbox storage is unchanged by D2) |
| 134 | `saas_os/core/notifications/service.py:240` | `append_event` | `dispatch_notification` | none | no `initiated_by=` passed: the event stores no initiator | n/a (outbox storage is unchanged by D2) |
| 135 | `saas_os/core/usage/service.py:185` | `append_event` | `ingest_event` | none | no `initiated_by=` passed: the event stores no initiator | n/a (outbox storage is unchanged by D2) |
| 136 | `saas_os/core/webhooks/service.py:1134` | `append_event` | `trigger_event` | none | no `initiated_by=` passed: the event stores no initiator | n/a (outbox storage is unchanged by D2) |

## 6. Consumer compatibility inventory (read-only, 2026-11-03)

Every checkout under `C:/Users/imran/Documents/` was searched (to depth 4, excluding virtual environments and `node_modules`) for `saas_os`, `saas-os`, `from core.audit_log` and `from core import audit_log`; each hit was then scanned with the same syntax-tree method as section 2, for both import roots (`saas_os.core` and the older `core`), including wrappers that forward `metadata`, and every source line naming `initiated_by` or `Initiator` was listed. Nothing in any consumer was modified; no pin was changed.

| Consumer (checkout, HEAD) | SaaS OS pin (`pyproject.toml`) | Import root at the pin | Audit-writer calls | `Initiator` / `initiated_by` uses | Passes a user initiator? | Upgrade to #196+#201 |
|---|---|---|---|---|---|---|
| LeadStack (`Leadstack`, `a4422a0`, 72 uncommitted files; pin identical in the working tree and `uv.lock`) | `b126f1ad0c9cf4173ada15e20b14850d9e600c14` (2026-09-26) | `core` | 10 `record()` (9 `_audit` helpers and `scheduling/reconcile.py:333`), 50 helper calls; every metadata has fixed keys (`fields`, `role`, `tag_id`, `channel`, ...) | 0 | no | No change for D2. Not possible without product-side changes that D2 does not cause: the import root moved from `core` to `saas_os.core` after the pin, so every `from core import audit_log` / `from core.audit_log import ...` must become `saas_os.core...` (audit imports: `src/leadstack/domains/crm/activity.py:25-26`, `crm/service.py:22-23`, `forms/service.py:35-36`, `messaging/service.py:46-47`, `sales/service.py:24-25`, `automation/service.py:31-32`, `scheduling/service.py:25-26`, `scheduling/reconcile.py:34-35`, `workspaces/service.py:29-30`; 89 `core`/`infra`/`api` import lines in 43 files in all), plus every upgrade step of `docs/CONSUMER-GUIDE.md` section 14 from v0.1.0. After #196 its successful `ActorType.SYSTEM` rows through `record()` (`scheduling/reconcile.py:333`, `automation/service.py:449`, `forms/service.py:546`, `messaging/service.py:356`, `:401`, `:584`, `scheduling/service.py:603`) emit the ADR 0061 deprecation warning and log line; they are not refused. |
| ai-agent (`1b3ee67`) | `ff550010e5eafecace7311038aadc99fcecfbe3d` (2026-09-19) | `core` | 22 `record()`, metadata none or fixed keys | 0 | no | No change for D2; import-root change needed for any upgrade (independent of D2). |
| ChronoGaz (`22045e4`) | `2a299a3b5fa62e810d87e3ff2d8e844763e6a38b` (2026-09-18) | `core` | 0 | 0 | no | No change for D2; import-root change needed for any upgrade. |
| crm-app (`0dd4a3c`) | `d980e73b0313ed63f2a59fd4a991a89f75791c0e` (2026-10-31) | `saas_os` | 29 `record_in_transaction` (metadata fixed keys or `**meta` keyword helpers whose keys are keyword names in the source; `records.py:307` forwards fixed-key dicts built in `records.py`) | 0 | no | No change for D2. |
| crm-app-v050 (`70eaa06`) | `b03d87a5272924d1e413c144dc5c3b41ac430580` (v0.5.0) | `saas_os` | 0 | 0 | no | No change for D2. |
| MarketStack (`marketstack`, `cf50aad`) | `4fccc9370f3acf82cbc03fedd5c3adbade223d97` (2026-10-03) | `core` | 163 `record()`; 4 variable metadata, each traced to fixed keys (`automation/durable/definitions.py:349`, `crm/contacts.py:322`, `telephony/call_session.py:419`, `telephony/calls.py:670` with `transfer.py:323`) | 0 | no | No change for D2; import-root change needed for any upgrade. |
| leadstack-crm (`dcc2476`) | none: a JavaScript application; working tree mostly deleted (not by this audit); no `saas_os` reference at HEAD (`git grep`) or in `leadstack-crm-main.zip` | n/a | 0 | 0 | no | Not a code consumer. |
| crm-app-login (`8e6192a`) | none found | n/a | 0 | 0 | no | Not a consumer. |

No consumer writes an `initiated_by` key (top level or nested), uses a platform audit writer, or registers an outbox consumer, so no consumer reaches G1 to G4 or the dead-letter consequence below.

## 7. Dead-letter consequence for an outbox consumer

The outbox keeps a user initiator (D2 preserves outbox storage and erasure): `append_event(initiated_by=Initiator.from_caller(UserCaller(...)))` stores it, and the dispatcher hands it to the consumer as `context.initiated_by`. A consumer that writes it into an audit row, through the typed argument (G1) or through its metadata (G2 for a top-level key, G3 nested), gets `InvalidActorError` (or `ReservedMetadataKeyError`) before the insert on **every** attempt. `_run_outbox_event` (`saas_os/api/outbox_dispatcher.py`) treats it as an ordinary failure: `fail_event` stores `last_error = "InvalidActorError: <message>"` (no id), the event is retried with backoff and, after `max_attempts`, **dead-lettered**; no audit row is written. Tested: `test_a_consumer_passing_on_a_user_initiator_retries_then_dead_letters` and `test_a_consumer_passing_a_user_initiator_through_metadata_dead_letters` (`tests/api/test_outbox_attribution_integration.py`).

Detect it: `core.outbox_events` rows with `status = 'dead_lettered'` and `last_error` starting with `InvalidActorError:` or `ReservedMetadataKeyError:`; the worker log line `outbox_event_failed` with `error_type` `InvalidActorError`. Fix the consumer to pass `initiated_by=None` for a user initiator (recorded as `"unavailable"`), then replay the dead-lettered events (`saas-os-operator replay-outbox-events`, `platform.outbox:replay`). For the platform refusal writer the sign is the log line `platform_refusal_audit_failed`.

None of Core's four consumers writes an audit row, and Core's producers record no initiator, so SaaS OS itself never reaches this path.

## 8. Limits

- Only the key name `initiated_by` is gated, normalised by `strip().lower()` (case and surrounding whitespace), at any depth. **By design, other spellings are not covered**: `initiatedBy` (lowercased to `initiatedby`), `initiated-by`, `initiated by`, or a name containing a zero-width or other non-whitespace invisible character (`initiated​by`) are ordinary product keys, like any other key name. A user id under another key is outside D2 (O1) and is a product obligation for product keys (O5).
- `record_platform_refusal` writes the `denied` row with the marker `{"metadata_refused": "d2"}` instead of the refused metadata, so the rest of that metadata is not recorded on that row.
- The platform writers validate `action` and `target_type` before the D2 check, so a call that is wrong in both ways reports the first error (`InvalidPlatformRequestError`); either way nothing is written.
- Rows written before this change are not rewritten (D5).
