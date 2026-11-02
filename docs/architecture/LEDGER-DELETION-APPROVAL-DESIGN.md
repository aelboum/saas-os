# Authenticated approval for deleting expired permission grant ledger rows

**Status: Architecture decision proposal; not implemented; deletion stays disabled until the complete approval mechanism is implemented, independently reviewed and tested.** Date: 2026-11-02. Enabling deletion afterwards is a separate change that the owner approves.

Nothing described here exists in the code. Today `saas_os.core.permission_grants.expiry._DELETION_ENABLED` is the literal `False`. With it, `expire_permission_grant_ledger_rows(apply=True)` raises `LedgerDeletionDisabledError` (code `deletion_disabled`). This proposal does not change that. It has no ADR number of its own. It extends the ADR-0045 amendment of 2026-11-02 ("Separation of duties", bullet "Approval control"). If the owner accepts it, a later ADR-0045 amendment records the decision.

Related documents: ADR-0045 (section 7, the HTTP and CLI boundaries; amendment of 2026-11-02), ADR-0044 (the same-origin check), ADR-0049 (operator multi-factor login), ADR-0051 (audit tables are append-only for the application role), ADR-0053 (audit digests in external logs), `docs/RUNBOOKS.md` ("Granting legal-hold management", "Deleting expired permission grant ledger rows") and PR #198.

**Terms.** A *declared* id is a user id that the person running a command types; nothing authenticates it. An *authenticated* id is the user of the SaaS OS session that the platform-admin HTTP chain validated. *Releaser* means the authenticated actor of a hold release. *DB clock* means PostgreSQL's time, never the clock of the application or the command host.

---

## 0. What the code does today (verified on the branch at `40a0888`)

| Fact | Where |
|---|---|
| Platform routes are declared in one table, `PLATFORM_ROUTES` (27 routes, pinned by `tests/api/test_platform_admin_unit.py`). Each route gets the dependency `require_platform_permission(permission, operation=..., fresh_session=...)`. The prefix is `/v1/platform`. No retention route exists. | `saas_os/api/platform_admin/router.py`: `PLATFORM_ROUTES`, `build_router` |
| The handler's caller is always `UserCaller(context.actor_id)`. It is never taken from the path or the body. | `router.py`: `_caller` |
| The chain: the deployment opt-in (else 404) → `get_current_session` (a Bearer header or the session cookie, sessions only; the ADR-0044 same-origin check for a cookie-authenticated unsafe method) → a rate limit keyed by actor and route → `is_active_platform_operator` (else the 404 of an unknown path) → ADR-0049 MFA, where the deployment requires it (`401 multi_factor_required`) → `fresh_session` age, where the route declares it (`401 session_not_fresh`) → `platform_can` (`403`). The result is `PlatformRequestContext(actor_id, session_id)`. | `saas_os/api/dependencies.py`: `require_platform_permission`, `PlatformRequestContext`, `_enforce_same_origin_for_cookie_mutation`, `get_current_session` |
| The session's user comes from the OIDC callback. It validates the ID token (`identity_provider.validate_id_token`), maps issuer and subject to a user (`get_or_create_user_for_external_identity`) and calls `issue_session(user.id, multi_factor=identity.multi_factor, ...)`. Each later request presents the session secret, and `validate_session(raw_token)` returns the `Session` whose `user_id` becomes `actor_id`. | `saas_os/api/auth/routes.py` (callback), `saas_os/core/identity/sessions.py`: `validate_session` |
| Request bodies are pydantic models. None sets `extra="forbid"` today, so an unknown field is ignored rather than rejected. No exception handler is registered for `RequestValidationError`, so a schema error is FastAPI's default `422`. | `router.py`: `ReasonRequest`, `EnrollOperatorRequest`, ... |
| No platform route uses `Idempotency-Key`. `get_idempotency_key` is used only by `saas_os/api/v1/billing.py`, and Core idempotency is keyed by `(tenant_id, operation, key)`, so it has no platform form. | `dependencies.py`: `get_idempotency_key`; `saas_os/core/idempotency/service.py` |
| Pagination: `cursor` (UUID) and `limit` in the query, `next_cursor` in the response. Core rejects a page above its maximum with a 400 (`validate_page_request`, `MAX_OVERSIGHT_PAGE_SIZE = 200`). | `router.py`: `_page_arguments`, `PageSize`; `saas_os/core/platform_authority/oversight.py` |
| Core errors are translated by `_translated`: `PlatformNotAuthorizedError` → 403; `PlatformRefusalError` → `409` with its fixed `code`; `InvalidPlatformRequestError` → 400; a timeout or transaction conflict → `503` with `Retry-After`. Any other exception stays a 500. The retention errors (`PermissionGrantLedgerRetentionError` subclasses, each with a fixed `code`) are `ValueError`s and are not mapped. | `router.py`: `_translated`; `saas_os/core/permission_grants/errors.py` |
| `authorize_platform_caller(caller, session=..., operation=...)` reads the operation row. It refuses every `ServiceAccountCaller`. It accepts a `SystemCaller` only for a purpose the row lists. For a `UserCaller` it evaluates `platform_can` in the operation's own transaction, locking the user, operator and grant rows `FOR SHARE`. | `saas_os/core/platform_authority/authorization.py` |
| The operation table has 38 rows and the vocabulary has 28 permissions. The four retention rows (`permission_grant_ledger.retention_report`, `.hold_place`, `.hold_release`, `.expired_delete`) accept no system purpose (`_NONE`). | `saas_os/core/platform_authority/operations.py`: `_ROWS`, `PERMISSION_GRANT_LEDGER_*` |
| `record_platform_event_in_transaction` appends one platform audit row inside the caller's transaction. Its `entry_id` can be fixed beforehand, so a state row can name it. `record_platform_refusal` / `recording_platform_refusal` write a `denied` row in a transaction of their own, best effort, and never raise. Audit metadata is limited to 8192 bytes (`MAX_METADATA_BYTES`) and has a key denylist. | `saas_os/core/platform_authority/audit.py`; `saas_os/core/audit_log/metadata.py` |
| The holds table (`core.permission_grant_ledger_holds`, migration `a9c3e5f7b1d4`) has the tenant-context exclusion policy, a one-way release trigger (`permission_grant_ledger_holds_release_once`) and runtime privileges `SELECT`, `INSERT` and `UPDATE (released_at, released_by_platform_audit_id)`; `DELETE` is revoked. It has no foreign key onto the audit log. | `saas_os/infra/db/migrations/versions/a9c3e5f7b1d4_create_core_permission_grant_ledger_holds.py` |
| Hold placement locks the tenant row `FOR UPDATE`. Hold **release** locks only the hold row (`session.get(..., with_for_update=True)`). Both write their platform row with a pre-chosen id that the hold row records. | `saas_os/core/permission_grants/retention.py`: `place_permission_grant_ledger_hold`, `release_permission_grant_ledger_hold` |
| The report recomputes eligibility with the DB clock and records `eligible_ledger_rows` and `eligible_digest` (SHA-256 of canonical JSON of the eligible tenants' ledger row ids). | `retention.py`: `permission_grant_ledger_retention_report`, `eligible_ledger_digest`, `retention_eligibility` |
| Deletion: one transaction on the migrations role. It authorizes the declared `UserCaller`, locks the tenant rows in scope in id order, re-decides eligibility with the DB clock, compares count and digest, deletes per tenant inside its RLS scope, and writes the run and per-tenant audit rows. It refuses with `deletion_disabled` before the run connects (only `_record_denied` then opens a migrations-role connection, to write the `denied` row). | `saas_os/core/permission_grants/expiry.py`: `expire_permission_grant_ledger_rows`, `_DELETION_ENABLED` |
| The migrations-role connection checks `current_user`: the role must own the ledger (or be a member of its owner), hold `DELETE`, and not be `DATABASE_URL`'s user. There is no fallback. | `saas_os/infra/db/migrations_role.py`: `validate_migrations_role`, `migrations_role_session_scope` |
| The first owner gets 27 permissions. `platform.security_retention_hold:manage` is in `NOT_GRANTED_AT_BOOTSTRAP`, and the only way to grant it is the break-glass `recover --grant`. | `saas_os/api/platform_bootstrap.py`: `BOOTSTRAP_PERMISSIONS`, `NOT_GRANTED_AT_BOOTSTRAP` |
| Every retention command (`saas-os-operator permission-grant-ledger-retention`, `hold-permission-grant-ledger`, `release-permission-grant-ledger-hold`, and `python -m saas_os.ops.permission_grant_ledger_expiry`) takes a **declared** `--operator`. | `saas_os/ops/operator_cli.py`, `saas_os/ops/permission_grant_ledger_expiry.py` |

---

## 1. Decision proposal

### 1.1 Context

The owner's rules of 2026-11-02 are:

1. Deletion needs a verifiable approval.
2. A person who releases a legal hold must not be able to authorise, alone, the deletion of the same records.
3. A declared operator id is not an authenticated identity.
4. No new permission (the vocabulary stays at 28) and no runtime `DELETE` on the ledger.
5. Deletion stays a manual migrations-role procedure.

Section 0 shows why the current design cannot meet rules 1 and 2. Release and deletion are both recorded under declared ids, so a single person who holds both credentials can declare a different operator for each step. The only authenticated operator channel is the platform-admin HTTP API.

### 1.2 Decision (proposed)

1. **Authenticated retention API.** These are added to the existing opt-in platform-admin router: placing, releasing and listing legal holds, the retention report, a deletion request, an approval and an execution authorisation. Identity comes only from the session (`_caller(context)`). Every body forbids extra fields and has no identity field.
2. **Person-distinct steps.** A deletion needs three recorded acts by authenticated users: a *request*, an *approval* and an *execution authorisation*. The requester and the approver must be different users, and the approver and the execution authoriser must be different users. **Distinct user ids do not prove distinct humans**: one person can hold several OIDC accounts (threat T4a), which is why decision 13 restricts who can hold approval eligibility at all. Neither the approver nor the authoriser may be the authenticated releaser of any hold on any tenant in scope. A release that is not authenticated (made through the command line, before or after the API exists) blocks those tenants.
3. **Binding.** The request, the approval and the execution authorisation all bind the same exact scope: a sorted, distinct set of tenant ids, the eligible row count and the eligible digest. An approval is single use and expires 72 hours after it is given, by the DB clock. An execution authorisation is single use and short-lived.
4. **Execution stays on the migrations role.** The runtime role keeps no `DELETE`. The procedure takes the execution authorisation id instead of `--operator`, `--confirm-rows` and `--confirm-digest`. Under the tenant-row locks it revalidates scope, count, digest, active holds, the person-distinctness rules and the current authority of the approver and the authoriser. In the deletion's own transaction it then consumes the approval and the authorisation. The process that runs the command is still **not authenticated**: whoever holds the migrations credential runs it.
5. **No new permission.** Every new operation row uses `platform.security_retention:report` or `platform.security_retention_hold:manage`.
6. **The gate stays.** `_DELETION_ENABLED` stays the literal `False` until all of the above is implemented, independently reviewed and tested. Turning it on is a separate change that the owner approves. No setting or environment variable is ever added for it.

### 1.3 Consequences

- Rule 2 is checked over **authenticated** ids for every release made through the API. A release made through the command line cannot be attributed, so it keeps the affected tenant's rows. That errs towards retention.
- This reverses "No HTTP route: operator commands only" from the ADR-0045 amendment of 2026-11-02, for retention operations only. The ADR's section 7 table and the pinned route contract grow to match.
- Three new global tables with one-way triggers, nine new routes, five new operation rows (43 operations in total; still 28 permissions), and one change to existing behaviour: a hold release also locks the tenant row (section 5.4).
- Holders of the database credentials can still bypass every control (section 2). This design makes the legitimate path the only audited one and makes a bypass detectable. It does not make a bypass impossible.

### 1.4 Alternatives rejected

| Alternative | Why rejected |
|---|---|
| **Compare declared ids** (approver ≠ releaser on the command line) | One holder of both credentials declares a different operator for each step. The check compares two strings that the same person typed, so it looks like separation of duties without being one. |
| **Signed approvals** (each operator signs the digest with a personal key registered out of band) | Real separation if each key is held by one person. But it needs a key registry, enrolment, rotation, revocation and signature verification in Core, which is a second identity system beside OIDC. It also stores public keys that the application role could replace. It is heavier than reusing the authenticated session, and it brings provider-like key management into Core. Reconsider it only if the owner refuses HTTP routes for retention. |
| **Two-person database credential** (the migrations secret split, or dual control in the secret store) | Lives outside SaaS OS and is specific to a provider. Nothing ties it to the rows or to a person in the audit log, and it does not bind *who released a hold*. Worth having beside this design, not instead of it (decision 9). |
| **Keep deletion disabled permanently** | The current fallback, and it stands until this design is built. It keeps rows beyond two years, against the owner's policy of a two-year default retention. |
| **A runtime `DELETE` behind the API** | Violates rule 4. |

---

## 2. Threat model

**Actors.**
- The *platform owner*: the first operator, with 27 permissions including report, and without hold management.
- The *hold manager*: holds only `platform.security_retention_hold:manage`, granted out of band.
- The *reporter / approver*: any operator holding `platform.security_retention:report`.
- The *application credential holder*: `DATABASE_URL`, the runtime role.
- The *migrations credential holder*: `MIGRATIONS_DATABASE_URL`, the schema owner.
- A *compromised OIDC session*: a stolen session secret, or a hijacked browser.
- An *insider pair* who collude.

**Assets.** The ledger rows (`core.permission_grant_applications`), the hold history, the approval records, the platform audit log, and its external digests (ADR-0053).

| # | STRIDE | Actor | Threat | Mitigation in this design | Residual risk |
|---|---|---|---|---|---|
| T1 | Spoofing | Any caller | Puts an `operator`, `user_id` or `approver` field in a body to act as someone else | Every request model sets `extra="forbid"` (unknown field → `422`), and none has an identity field. The caller is only `UserCaller(context.actor_id)` (`router.py`: `_caller`). Architecture test (section 8.5) | None at the API |
| T2 | Spoofing | Compromised OIDC session | Uses a stolen session to approve or authorise execution | `fresh_session=True` on release, approve and execution-authorise (decision D2's 900-second ceiling). ADR-0049 MFA when the deployment requires it (decision 6 asks to require it). The session's age is recorded. A second, distinct account is still needed. Rate limit. | A fresh stolen session acts as its user within the window. One stolen session cannot complete a deletion alone (it needs two distinct accounts plus the migrations credential) |
| T3 | Elevation | Hold manager | Releases a hold and then approves the deletion of the same rows | The approver must not be the authenticated releaser of any hold on any tenant in scope, checked at approval and again at execution. A release is authenticated only if its audit row's `session_id` names a `core.sessions` row of the same user, created before the release (section 4.2). The hold manager normally lacks report (runbook), so approval is refused with `403` first | **Relies on T6 (custody of the application credential):** the runtime role can write the audit metadata, a session row and `released_by_platform_audit_id`, so a credential holder can fabricate or hide a release. With credentials held properly: none for releases made through R4. Also T4a (the releaser using a second account) |
| T4 | Elevation | Platform owner | Requests and approves the deletion alone, with one account | approver ≠ requester; authoriser ≠ approver | With one account: none. With several accounts: T4a |
| T4a | Spoofing, Elevation | **One person, several accounts** (typically the platform owner, who holds `platform.authority:manage` and report) | Enrols a second OIDC account of their own (`POST /v1/platform/operators`, `EnrollOperatorRequest.user_id`), grants it report (anti-amplification allows it: the owner holds report), then requests with account 1, approves with account 2 and authorises execution with account 1. **No database credential is needed** | Decision 13: option (a) makes approval eligibility out-of-band only (as hold management already is), so no in-product path creates a second eligible account; option (b), the provenance check of section 4.2, refuses parties linked by enrolment or grant, or too recently enrolled or granted; option (c) records it as residual. Every enrolment and grant has its own platform audit row (`platform.operator.enroll`, `platform.grant.create`) with `enrolled_by_user_id` / `granted_by_user_id` | Without (a): **open**. (b) alone is bypassed by waiting the age limit or by using two accounts that a third, earlier account created. Distinct user ids never prove distinct humans; out-of-band provisioning under (a) moves the control to the written, independently approved request and the custody of the database credential (break-glass) |
| T5 | Repudiation | Any operator | Denies having approved | Each act writes one platform audit row in its own transaction, holding `actor_user_id`, `session_id`, the request id and the correlation id. ADR-0053 digests fix the rows outside the database | Repudiation by claiming a stolen session (T2) |
| T6 | Tampering | Application credential holder | Inserts a forged request, approval, authorisation or audit row directly (the runtime role has `INSERT`) | Triggers force DB-clock times and copy-equality, but **not authenticity**. Detection: an approval whose audit row has no matching HTTP access record, `session_id` or `core.sessions` row; reconciliation (below) | **Cannot be prevented.** The application credential can forge any record that the application itself writes |
| T7 | Tampering, Elevation | Migrations credential holder | Deletes ledger rows with plain SQL, disables triggers, rewrites approval rows, or runs the procedure with any authorisation id | None preventive. The procedure only makes the legitimate path the audited one (as `saas_os/core/platform_authority/bootstrap.py` says of recovery). Detection: ADR-0053 digests (a rewritten audit row changes a settled window's digest); reconciliation of ledger counts against approvals and runs | **Cannot be prevented.** The schema owner and superusers can bypass every control in the application and the database |
| T8 | Elevation | Colluding pair | One requests, the other approves, then the first (or a third) authorises execution | Out of scope. Two people are the control the owner asked for (assuming T4a is closed). Every step names both. Decision 5 can require three people | Accepted: separation of duties assumes no collusion |
| T9 | Tampering | Any | Changes holds or ledger rows between approval and execution | Execution locks the tenant rows and recomputes count, digest, scope, holds and releasers. Any change → refused | None |
| T10 | Info. disclosure | Any operator | Approval records reveal tenants | The tables carry the tenant-context exclusion policy and hold only ids, counts and digests. Reading them needs the report permission | Operators with report see tenant ids (as the report shows today) |
| T11 | Denial of service | Operator | Floods requests or blocks scopes with overlapping requests | Rate limit per actor and route. At most one live request per tenant (section 3.1 defines *live*). A request expires 72 h after it is made unless approved; an approval stays live 72 h after it is given | A live request blocks another overlapping one until it expires or is consumed (by design) |
| T12 | Spoofing | Service account / system caller | Reaches a retention operation | Service accounts are refused by `authorize_platform_caller`, and the API takes sessions only. Every new row has `_NONE` system purposes | None |
| T13 | Replay | Migrations credential holder | Reuses a consumed approval | Single use: `consumed_*` is set in the deletion's transaction, and a trigger refuses a second set | Bypass only by T7 |

**Database credentials (explicit).** Whoever holds the application or the migrations database credential can bypass **every** application-level control in this design. The application credential can forge approval and audit rows. The migrations credential can delete ledger rows, drop triggers and rewrite rows. Nothing in SaaS OS prevents this. What exists is **detection**:
1. **The platform audit log.** Every legitimate step leaves a row. A deletion without a `platform.permission_grant_ledger.expired_delete` run row naming a consumed approval is suspect.
2. **ADR-0053 audit digests.** Settled windows of `core.platform_audit_log` are hashed into an external log chain, so a later rewrite or deletion of an approval or run audit row is detectable against the external copy. A forgery inserted *before* the window settles is not.
3. **Reconciliation of ledger counts against approval and run records** (runbook query, proposed). For each `PURGED` tenant, compare the current ledger row count with the counts in its earlier retention report rows. Any drop must be explained by a run row whose `approval_id` names a consumed approval whose `eligible_ledger_rows` and `scope_digest` match.

---

## 3. Endpoint contract

All routes are added to `PLATFORM_ROUTES` under `/v1/platform`. Each is a plain (non-async) handler whose dependency is `require_platform_permission`. Each calls one Core function with `caller=_caller(context)`.

### 3.1 Conventions (inherited, not new)

- **Authentication and CSRF.** These come from `require_platform_permission`. Sessions only: a Bearer header or the session cookie; an API key is never accepted. For a cookie-authenticated POST, `Origin` must equal the trusted origin and `Sec-Fetch-Site`, if sent, must be `same-origin` (ADR-0044); otherwise a generic `403`. A non-operator gets `404`. A route marked **fresh** below needs a session at most `PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS` old (at most 900); otherwise `401 session_not_fresh` and a `denied` audit row. With `PLATFORM_OPERATOR_REQUIRE_MFA`: `401 multi_factor_required`.
- **Identity.** There is no `operator`, `user_id`, `actor`, `approver`, `requester` or `authorized_by` field in any request. Every request model is declared `model_config = ConfigDict(extra="forbid")`, which is new for platform-admin bodies. A body that adds one, such as `{"reason": "T-1", "user_id": "…"}`, is a `422` whose FastAPI error type is `extra_forbidden`. The handler never runs, and no value from it reaches Core. The actor in each response is the session's own user.
- **Idempotency.** As on every existing platform route, there is **no `Idempotency-Key`**: Core's idempotency store is scoped by tenant, and these operations are installation-scoped. Retrying is safe because each mutation is guarded by state. A repeated release gets `409 hold_already_released`. A repeated request gets `409 overlapping_request` (one live request per tenant). A repeated approval gets `409 request_already_approved`. A repeated execution authorisation gets a second, separate authorisation, which is harmless because only one can be consumed.
- **Live request.** A request is *live* while either (i) it has no approval and `now() < request.expires_at`, or (ii) it has an approval with `now() < approval.expires_at` and `consumed_at IS NULL`. So an approved request stays live for up to 72 h after approval, even after the request's own 72 h have passed. `overlapping_request`, T11 and section 7 all use this definition.
- **Pagination.** `cursor` (UUID) and `limit` (at most 200; above that, `400`), keyset in id order. The response carries `next_cursor` (`null` at the end).
- **Errors.** `403 {"detail":"Not authorized."}`. `404 {"detail":"<resource> not found."}`. `409 {"detail":"<code>"}`, always a fixed code and never a value. `400 {"detail":"<Core message>"}` for `invalid_request`. `422` for schema errors. `429` and `503` with `Retry-After`. `_translated` gains one explicit table that maps each `PermissionGrantLedgerRetentionError` code to its status (section 3.4). An unknown subclass stays a 500.
- **Free text.** `reason` is 1 to 500 characters with no control characters (the existing `Reason` type). `reference` matches `^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$` (an opaque matter id, never a name).

### 3.2 Routes

| # | Method and path (after `/v1/platform`) | Permission | Operation (row) | Fresh | Success |
|---|---|---|---|---|---|
| R1 | `POST /permission-grant-ledger/retention-report` | report | `permission_grant_ledger.retention_report` (existing) | no | 200 |
| R2 | `GET /permission-grant-ledger/holds` | hold:manage | `permission_grant_ledger.hold_read` (**new**) | no | 200 |
| R3 | `POST /permission-grant-ledger/holds` | hold:manage | `permission_grant_ledger.hold_place` (existing) | no | 201 |
| R4 | `POST /permission-grant-ledger/holds/{hold_id}/release` | hold:manage | `permission_grant_ledger.hold_release` (existing) | **yes** | 200 |
| R5 | `POST /permission-grant-ledger/deletion-requests` | report | `permission_grant_ledger.deletion_request` (**new**) | no | 201 |
| R6 | `GET /permission-grant-ledger/deletion-requests` | report | `permission_grant_ledger.deletion_read` (**new**) | no | 200 |
| R7 | `GET /permission-grant-ledger/deletion-requests/{request_id}` | report | `permission_grant_ledger.deletion_read` | no | 200 |
| R8 | `POST /permission-grant-ledger/deletion-requests/{request_id}/approve` | report | `permission_grant_ledger.deletion_approve` (**new**) | **yes** | 201 |
| R9 | `POST /permission-grant-ledger/deletion-requests/{request_id}/execution-authorizations` | report | `permission_grant_ledger.deletion_execution_authorize` (**new**) | **yes** | 201 |

There is no route for the deletion itself; it runs on the migrations role (section 5). R1 is offered so that a reporter can obtain an *authenticated* report; the command-line report stays available.

### 3.3 Schemas

All UUIDs are lowercase strings. All times are RFC 3339 UTC strings from the DB clock. Every request object below is `additionalProperties: false`.

**R1 request**
```json
{"tenant_ids": ["uuid", "..."], "all_purged": false, "after": null, "limit": 1000, "reason": "string"}
```
This mirrors `permission_grant_ledger_retention_report`. `as_of` is **not** accepted over HTTP. Either `tenant_ids` (1 to 1000) or `all_purged`. `after` only goes with `all_purged`.

**R1 response**
```json
{"as_of": "time", "more": false, "eligible_ledger_rows": 0, "eligible_digest": "64 hex",
 "tenants": [{"tenant_id": "uuid", "status": "eligible|legal_hold|retention_running|not_purged|purge_time_unknown|purge_time_ambiguous|tenant_not_found",
              "ledger_rows": 0, "active_holds": 0, "purged_at": "time|null", "expires_at": "time|null"}]}
```

**R2 query:** `tenant_id` (optional), `active` (optional bool), `cursor`, `limit`.
**R2 response**
```json
{"holds": [{"id": "uuid", "tenant_id": "uuid", "reference": "string", "placed_at": "time",
            "released_at": "time|null", "release_authenticated": true}], "next_cursor": "uuid|null"}
```
`release_authenticated` is `null` while the hold is active. Otherwise it is `true` only when the release's audit row has `channel = "platform_http"` (section 4.3).

**R3 request** `{"tenant_id": "uuid", "reference": "string", "reason": "string"}`. **R4 request** `{"reason": "string"}`.
**R3 and R4 response**
```json
{"hold_id": "uuid", "tenant_id": "uuid", "reference": "string", "placed_at": "time",
 "released_at": "time|null", "platform_audit_id": "uuid"}
```

**R5 request**
```json
{"tenant_ids": ["uuid", "..."], "eligible_ledger_rows": 1, "eligible_digest": "64 hex", "reason": "string"}
```
`tenant_ids` holds 1 to 1000 entries. Core sorts the list and removes duplicates. Every tenant named must be eligible and have at least one ledger row (`scope_not_eligible` otherwise; decision 10), so the scope is exactly the eligible set. The count and digest are copied from a report. Core recomputes them under lock and refuses `confirmation_mismatch` unless both are equal.

**R5, R7 and R8 response (the request with its state)**
```json
{"id": "uuid", "tenant_ids": ["uuid"], "scope_digest": "64 hex", "eligible_ledger_rows": 1,
 "eligible_digest": "64 hex", "requested_at": "time", "request_expires_at": "time",
 "state": "pending|approved|consumed|expired",
 "approval": null | {"id": "uuid", "approved_at": "time", "expires_at": "time", "consumed_at": "time|null"},
 "requested_by_user_id": "uuid", "approved_by_user_id": "uuid|null"}
```
`*_by_user_id` are read from the audit rows' `actor_user_id`; they are never request inputs. **R6 response:** `{"requests": [ ...same objects... ], "next_cursor": "uuid|null"}`, with query `state` (optional), `cursor` and `limit`.

**R8 request**
```json
{"eligible_ledger_rows": 1, "eligible_digest": "64 hex", "reason": "string"}
```
The approver restates what they verified. Core recomputes under lock, and a mismatch means `confirmation_mismatch`.

**R9 request** `{"reason": "string"}`.
**R9 response**
```json
{"id": "uuid", "approval_id": "uuid", "request_id": "uuid", "authorized_at": "time", "expires_at": "time",
 "eligible_ledger_rows": 1, "eligible_digest": "64 hex", "scope_digest": "64 hex"}
```
The `id` is what the operator passes to the migrations-role command.

### 3.4 Status and error codes

| Code | HTTP | Raised by |
|---|---|---|
| (unknown body field, bad type, out of range) | 422 | FastAPI / pydantic (`extra_forbidden`, ...) |
| `invalid_request` | 400 | Core validation (existing `InvalidLedgerRetentionRequestError`) |
| `not_authorized` | 403 | `platform_can` or `authorize_platform_caller` (route or Core) |
| `session_not_fresh`, `multi_factor_required` | 401 | dependency chain |
| `tenant_not_found` / `hold_not_found` / `request_not_found` | 404 | R3 / R4 / R7–R9 |
| `hold_already_active`, `hold_already_released` | 409 | R3, R4 (existing codes) |
| `confirmation_mismatch` | 409 | R5, R8, and execution |
| `scope_not_eligible` | 409 | R5, R8, R9 (a tenant in scope is no longer eligible or has no rows) |
| `overlapping_request` | 409 | R5 (a live request, as defined in 3.1, already names a tenant in scope) |
| `request_expired`, `request_already_approved` | 409 | R8 |
| `approver_is_requester` | 409 | R8 |
| `approver_released_hold` | 409 | R8, execution |
| `unauthenticated_release_in_scope` | 409 | R5, R8, R9, execution (decision 2) |
| `approval_missing`, `approval_expired`, `approval_consumed` | 409 | R9, execution |
| `authorizer_is_approver`, `authorizer_released_hold` | 409 | R9, execution |
| `approver_linked_to_requester`, `authorizer_linked_to_approver` | 409 | R8 / R9, execution (provenance check, decision 13 option (b); `NULL` provenance counts as linked) |
| `party_holds_authority_manage` | 409 | R8, R9, execution (a requester, approver or authoriser currently holds `platform.authority:manage`; decision 13 option (a)) |
| `execution_authorization_not_found` / `_expired` / `_consumed` | (command, exit 1) | execution |
| `approval_no_longer_authorized` | (command, exit 1) | execution (the approver lost report or was suspended) |
| `deletion_disabled` | (command, exit 1) | execution, while `_DELETION_ENABLED` is `False` |
| rate limit / backend | 429 / 503 | dependency chain |
| lock timeout, deadlock, serialization failure | 503 | `_translated` (existing) |

Each code above is the `code` of a `PermissionGrantLedgerRetentionError` subclass, or of a `PlatformRefusalError`, and is recorded as the `reason` of the `denied` row.

---

## 4. Authorisation matrix

### 4.1 New operation rows (permissions unchanged: 28)

| Key | Permission | System purposes | Audit action |
|---|---|---|---|
| `permission_grant_ledger.hold_read` | `platform.security_retention_hold:manage` | none | `platform.permission_grant_ledger.hold_read` |
| `permission_grant_ledger.deletion_read` | `platform.security_retention:report` | none | `platform.permission_grant_ledger.deletion_read` |
| `permission_grant_ledger.deletion_request` | `platform.security_retention:report` | none | `platform.permission_grant_ledger.deletion_request` |
| `permission_grant_ledger.deletion_approve` | `platform.security_retention:report` | none | `platform.permission_grant_ledger.deletion_approve` |
| `permission_grant_ledger.deletion_execution_authorize` | `platform.security_retention:report` | none | `platform.permission_grant_ledger.deletion_execution_authorize` |

The existing rows (`retention_report`, `hold_place`, `hold_release`, `expired_delete`) are unchanged. The table goes from 38 to 43 rows. The two read rows follow the oversight convention: an attempt row and a completion row (`oversight_attempt_action`).

**Separation is by operation and person, not by permission.** Request (R5), approval (R8) and execution authorisation (R9) all require the same permission, `platform.security_retention:report`, because no new permission is allowed. The permission check therefore separates nothing between these three steps. Separation comes only from the distinct operation rows (each audited under its own action) and from the person-distinctness and provenance rules below, which compare distinct user accounts. Whether those accounts are distinct humans depends on decision 13.

### 4.2 Matrix

| Operation | Required permission | Who may | Who may **not** |
|---|---|---|---|
| Report (R1, or the command) | report | Any active operator holding report | Service accounts; system callers; holders of `platform.permission_grant:apply` or hold:manage alone |
| Place hold (R3, or the command) | hold:manage | Hold manager | Anyone without hold:manage, including the platform owner (not granted at bootstrap); service accounts; system callers |
| Release hold (R4) | hold:manage, fresh session | Hold manager | Same as placement; a stale session |
| Request deletion (R5) | report | Reporter | Service accounts; system callers; any caller while a scope tenant has an unauthenticated release (decision 2) |
| Approve (R8) | report, fresh session | An operator holding report who is **not** the requester and **not** an authenticated releaser of any hold (active or released) on any tenant in scope | The requester; any releaser in scope; anyone while an unauthenticated release exists in scope; service accounts; system callers |
| Authorise execution (R9) | report, fresh session | An operator holding report who is **not** the approver and **not** a releaser in scope. They **may** be the requester (decision 5) | The approver; any releaser in scope; anyone once the approval has expired or been consumed |
| Execute (migrations-role command) | none at the runner. The authoriser's report permission is re-checked; the approver's is re-checked too | Whoever holds the migrations credential and the authorisation id. **The runner is not authenticated** | A runner without the migrations role (connection refused); any run whose approval or authorisation is missing, expired, consumed or bound to another scope |

**Provenance check (decision 13, option (b); defence in depth).** The approver and the authoriser are each refused (`approver_linked_to_requester`, `authorizer_linked_to_approver`) when the other party involved is linked to them. A link means either enrolled the other's operator (`core.platform_operators.enrolled_by_user_id`) or granted the other's report permission (`core.platform_grants.granted_by_user_id`), checked both ways. They are also refused when their own operator enrolment or report grant is younger than N days (proposed 30, `created_at` / `granted_at`). This does not prove distinct humans (T4a). **NULL provenance counts as linked.** An operator enrolled, or a report permission granted, by bootstrap or by break-glass `recover` has `enrolled_by_user_id` or `granted_by_user_id` `NULL` (`saas_os/core/platform_authority/models.py`: `PlatformOperator`, `PlatformGrant`). The link check cannot see who stands behind such an account, so a `NULL` value is treated as linked to every other party, and such a party is not eligible for R8 or R9, unless the owner decides otherwise (decision 13).

**No authority holders in the chain (decision 13, option (a)).** At R8, at R9 and again at execution (section 5.3, step 6), Core refuses (`party_holds_authority_manage`) when the requester, the approver or the authoriser *currently* holds `platform.authority:manage`, evaluated with `platform_can` in that transaction. A check made only when the grant is created is not enough: the owner could later grant `platform.authority:manage` to an approver, who could then grant report to any account, including the owner's second account. This check stops that path. It does not stop two people who collude (T8).

**How a releaser is resolved.** `core.permission_grant_ledger_holds.released_by_platform_audit_id` → `core.platform_audit_log.id` → `actor_user_id`. The release counts as authenticated only when all of these hold: that audit row has `actor_type = 'user'`; its metadata has `channel = "platform_http"` and a `session_id`; and that `session_id` names a `core.sessions` row whose `user_id` equals the row's `actor_user_id` and whose `created_at` precedes the release. `channel` and `session_id` are bound only by the router: R4's handler passes the `PlatformRequestContext` to Core, and the Core release function accepts no channel or session argument from any other caller (the command-line path never sets them). These checks catch mistakes and the command-line path. **They do not stop a holder of the application credential**, who can write a session row, audit metadata or `released_by_platform_audit_id` directly. That protection rests on T6 (credential custody) and its detection. The lookup goes through a new helper in `saas_os.core.platform_authority` (like `purge_evidence.tenant_purge_completion_times`), because only that package touches the platform models. Releases of every hold on every tenant in scope count, from any time.

### 4.3 Releases made under declared ids (the command-line era)

A release made by `release-permission-grant-ledger-hold` records a declared `actor_user_id` and no `channel`. Who actually released the hold cannot be known. The options are:

| Option | Rule | Assessment |
|---|---|---|
| **A (recommended)** | Any unauthenticated release on a tenant in scope blocks request, approval, authorisation and execution for that tenant (`unauthenticated_release_in_scope`). Its rows stay retained. Lifting the block is a separate change that the owner approves | Conservative and simple. Errs towards keeping evidence. Few tenants are affected (holds are rare, and none can expire before 2028 on an installation that purges from now) |
| B | Allowed if the approver's operator never held hold:manage before the release time (from `core.platform_grants`, whose revoked rows are kept) | Weak: anyone holding the application credential could have run the release, whatever grants they had |
| C | Allowed with two distinct approvers for those tenants | Adds a second approval type; more code for a rare case |
| D | Treat the declared id as the releaser | Rejected: it is exactly what rule 3 forbids |

The same rule applies to a command-line release made **after** the API ships, if the command is kept (decision 3), so the rule enforces itself.

### 4.4 Callers that are always refused

`ServiceAccountCaller` is refused by `authorize_platform_caller` and cannot reach the routes (sessions only). `SystemCaller` is refused because every row has `_NONE` purposes. An unauthenticated request gets `401`. A non-operator gets `404`.

---

## 5. Execution model

### 5.1 Principles

- The runtime role never receives `DELETE` on `core.permission_grant_applications`. Deletion stays in `expire_permission_grant_ledger_rows` on `migrations_role_session_scope`, and no route, job or purge step reaches it (`tests/architecture/test_migrations_role_boundary.py`).
- The *authenticated* authorisation of the execution is R9: a record created by a person who is not the approver, valid for 60 minutes and never past the approval's own expiry (decision 4).
- The command presents that id:

  ```text
  python -m saas_os.ops.permission_grant_ledger_expiry \
      --execution-authorization <id> --reason "TICKET-9: retention expiry" [--apply] [--confirm-production]
  ```

  `--operator`, `--tenant`, `--all-purged`, `--after`, `--confirm-rows` and `--confirm-digest` are refused together with `--execution-authorization`, because scope and binding come only from the records. Without `--apply` the command verifies everything below and writes nothing. The existing dry-run form (`--operator` and a scope) stays for reports only. `--apply` without `--execution-authorization` is refused.
- Core's caller for the run is `UserCaller(<authoriser's actor_user_id from the authorisation's audit row>)`, read from the database and never typed. The run's audit rows state `runner = "migrations_role_unauthenticated"`.
- **The command runner is not authenticated.** Anyone who holds the migrations credential and knows a valid authorisation id can run it. The control is that the run can only do what two distinct authenticated accounts bound it to, once, before expiry.

### 5.2 Binding

| Bound value | Where it is fixed | Checked at |
|---|---|---|
| Scope: the sorted, distinct tenant id set, plus `scope_digest` = SHA-256 of the canonical JSON array of the sorted ids | Request (trigger-validated); copied into the approval (trigger checks it is equal) | R8, R9, execution |
| `eligible_ledger_rows` | Request; equal in the approval | R8 (restated), execution |
| `eligible_digest` (`eligible_ledger_digest`) | Request; equal in the approval | R8 (restated), execution |
| Single use | `consumed_*` on the approval and on the authorisation | execution |
| Expiry | `approved_at + 72 h`, DB clock (trigger); authorisation `least(authorized_at + 60 min, approval.expires_at)` | R9, execution |

### 5.3 The execution transaction (once enabled)

One transaction on the migrations role, in this order:

1. Validate the input. Refuse `deletion_disabled` before the run connects (the `denied` row is still written on a migrations-role connection of its own, `_record_denied`) while `_DELETION_ENABLED` is `False` (unchanged).
2. Read the authorisation, the approval and the request, all without locks: only the ids are needed to find the scope.
3. **Lock the tenant rows in scope `FOR UPDATE`, in id order.** This is the same lock that hold placement takes (and, after 5.4, hold release).
4. Lock the approval row and then the authorisation row `FOR UPDATE` (fixed order: tenants, approval, authorisation).
5. Take `t = clock_timestamp()` after the locks are held. `now()` is the transaction's start time and could be earlier than the lock wait. Refuse with `execution_authorization_consumed`, `approval_consumed`, `execution_authorization_expired` (`t >= expires_at`) or `approval_expired`.
6. Re-authorise: `authorize_platform_caller(UserCaller(authoriser))` for `permission_grant_ledger.expired_delete` (refused with `not_authorized` if the authoriser was suspended or lost report), and `platform_can(approver, report)` (refused with `approval_no_longer_authorized`). If decision 13 adopts option (a), also refuse `party_holds_authority_manage` when the requester, the approver or the authoriser now holds `platform.authority:manage`.
7. Recompute eligibility for exactly the bound scope with `t`. Every tenant must be `ELIGIBLE` with rows. The count and digest must equal the approval's, and the scope digest must equal it. Otherwise `confirmation_mismatch` or `scope_not_eligible`.
8. Re-check the people: approver ≠ requester; authoriser ≠ approver; neither is an authenticated releaser in scope; there is no unauthenticated release in scope. Releases between approval and execution are included.
9. Delete per tenant inside `bind_tenant_scope`, by id. A tenant that loses anything other than exactly the counted rows rolls back the whole transaction (unchanged).
10. Write the run, tenant and consume audit rows (section 6). Set `consumed_at = t` and `consumed_by_platform_audit_id` (the consume row's id) on the approval and on the authorisation. Commit.

### 5.4 Change to the existing hold release

`release_permission_grant_ledger_hold` must lock the hold's tenant row `FOR UPDATE` **before** the hold row. Today it locks only the hold row. With the change, a release that races with steps 3 to 10 either commits first (and step 8 sees it) or waits until the deletion has committed. The lock order then matches everywhere: tenant first.

### 5.5 Approval and authorisation tables (sketch; **not validated against PostgreSQL**)

```sql
-- Sketch only. Not validated against PostgreSQL; the migration that implements
-- it is hand-written, reviewed and tested like a9c3e5f7b1d4.
CREATE TABLE core.permission_grant_ledger_deletion_requests (
    id                              uuid PRIMARY KEY,
    tenant_ids                      uuid[] NOT NULL,
    scope_digest                    char(64) NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$'),
    eligible_ledger_rows            integer NOT NULL CHECK (eligible_ledger_rows > 0),
    eligible_digest                 char(64) NOT NULL CHECK (eligible_digest ~ '^[0-9a-f]{64}$'),
    requested_at                    timestamptz NOT NULL,  -- forced to now() by trigger
    expires_at                      timestamptz NOT NULL,  -- forced to now() + 72 h by trigger
    requested_by_platform_audit_id  uuid NOT NULL UNIQUE,
    CONSTRAINT ck_pgldr_scope_size CHECK (cardinality(tenant_ids) BETWEEN 1 AND 1000),
    CONSTRAINT ck_pgldr_scope_no_null CHECK (array_position(tenant_ids, NULL) IS NULL),
    CONSTRAINT fk_pgldr_audit FOREIGN KEY (requested_by_platform_audit_id)
        REFERENCES core.platform_audit_log (id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE core.permission_grant_ledger_deletion_approvals (
    id                             uuid PRIMARY KEY,
    request_id                     uuid NOT NULL UNIQUE
        REFERENCES core.permission_grant_ledger_deletion_requests (id),
    tenant_ids                     uuid[] NOT NULL,      -- trigger: equals the request's
    scope_digest                   char(64) NOT NULL,    -- trigger: equals the request's
    eligible_ledger_rows           integer NOT NULL,     -- trigger: equals the request's
    eligible_digest                char(64) NOT NULL,    -- trigger: equals the request's
    approved_at                    timestamptz NOT NULL, -- forced to now()
    expires_at                     timestamptz NOT NULL, -- forced to now() + 72 h
    approved_by_platform_audit_id  uuid NOT NULL UNIQUE,
    consumed_at                    timestamptz NULL,
    consumed_by_platform_audit_id  uuid NULL UNIQUE,
    CONSTRAINT ck_pglda_consumed_pairing
        CHECK ((consumed_at IS NULL) = (consumed_by_platform_audit_id IS NULL)),
    CONSTRAINT ck_pglda_order CHECK (expires_at > approved_at
        AND (consumed_at IS NULL OR consumed_at >= approved_at)),
    CONSTRAINT fk_pglda_audit FOREIGN KEY (approved_by_platform_audit_id)
        REFERENCES core.platform_audit_log (id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE core.permission_grant_ledger_deletion_execution_authorizations (
    id                               uuid PRIMARY KEY,
    approval_id                      uuid NOT NULL
        REFERENCES core.permission_grant_ledger_deletion_approvals (id),
    authorized_at                    timestamptz NOT NULL, -- forced to now()
    expires_at                       timestamptz NOT NULL, -- forced: least(now() + 60 min, approval.expires_at)
    authorized_by_platform_audit_id  uuid NOT NULL UNIQUE,
    consumed_at                      timestamptz NULL,
    consumed_by_platform_audit_id    uuid NULL,
    CONSTRAINT ck_pglde_consumed_pairing
        CHECK ((consumed_at IS NULL) = (consumed_by_platform_audit_id IS NULL)),
    CONSTRAINT fk_pglde_audit FOREIGN KEY (authorized_by_platform_audit_id)
        REFERENCES core.platform_audit_log (id) DEFERRABLE INITIALLY DEFERRED
);
-- At most one consumed authorisation per approval.
CREATE UNIQUE INDEX uq_pglde_one_consumed
    ON core.permission_grant_ledger_deletion_execution_authorizations (approval_id)
    WHERE consumed_at IS NOT NULL;
```

**Triggers.** None is `SECURITY DEFINER`; each uses `SET search_path = pg_catalog`; each refuses with `check_violation`.
- `BEFORE INSERT` on each table. It overwrites the times from `now()` and ignores supplied values. It requires `tenant_ids` to equal `ARRAY(SELECT DISTINCT u FROM unnest(NEW.tenant_ids) u ORDER BY u)`. On approvals, the four bound columns must equal the request's, and the request must be unexpired (`now() < request.expires_at`). On authorisations, the approval must be unexpired and unconsumed.
- **One-way consume** (`BEFORE UPDATE`). On requests, every update is refused. On approvals and authorisations, the only update allowed changes `consumed_at` and `consumed_by_platform_audit_id` from both `NULL` to both non-`NULL`; every other column must stay `IS NOT DISTINCT FROM` its old value. A second consume is refused.
- `BEFORE DELETE` on each table refuses every delete, whatever the role. The tables are dropped only by a migration downgrade, which refuses while any row exists (the `a9c3e5f7b1d4` pattern).

**RLS.** `tenant_context_exclusion_statements(<table>, schema="core")` on all three tables, so that no tenant-scoped transaction can read or write them (ADR-0045 section 9b, as for the holds).

**Grants.** The runtime role keeps `SELECT` and `INSERT` from the default privileges, and `REVOKE UPDATE, DELETE` on all three tables, so it can never consume, rewrite or remove a record. Only the migrations role (the owner) can update, and only the consume transition passes the trigger. The owner can disable the trigger: see T7.

---

## 6. Audit

Every act writes platform audit rows through `record_platform_event_in_transaction`, in the act's own transaction. Each state row records the pre-chosen id (`entry_id`) of the act's audit row. Refusals write one `denied` row through `recording_platform_refusal` / `record_platform_refusal`, after the rollback and best effort, with the refusal `code` as the `reason`. **Metadata holds only ids, counts, digests, times and fixed labels: no names, no e-mail addresses, no free text other than the ticket `reason`.** It stays under the 8192-byte limit, so a scope is recorded as `tenants` (a count) and `scope_digest`, never as the list itself. The list lives in the request row.

Metadata common to every HTTP act is `channel: "platform_http"` and `session_id`. `correlation_id` is set automatically from the request id.

| Act | Action | Outcome | Target | Metadata |
|---|---|---|---|---|
| Report (R1) | `…retention_report` (existing) | success | `permission_grant_ledger` | as today, plus `channel` and `session_id` |
| Hold read (R2) | `…hold_read_attempt` and then `…hold_read` | success | `permission_grant_ledger_hold` | filter flags, `returned` count |
| Hold place (R3) | `…hold_place` (existing) | success | the hold | `hold_id`, `reference`, `channel`, `session_id` |
| Hold release (R4) | `…hold_release` (existing) | success | the hold | `hold_id`, `reference`, `channel`, `session_id`, `session_age_seconds` |
| Request (R5) | `…deletion_request` | success | `permission_grant_ledger_deletion_request` / `request_id` | `request_id`, `tenants`, `scope_digest`, `eligible_ledger_rows`, `eligible_digest`, `expires_at` |
| Read (R6, R7) | `…deletion_read_attempt` and then `…deletion_read` | success | same | `request_id` or filter, `returned` |
| Approve (R8) | `…deletion_approve` | success | same | `request_id`, `approval_id`, `tenants`, `scope_digest`, `eligible_ledger_rows`, `eligible_digest`, `expires_at`, `session_age_seconds` |
| Authorise execution (R9) | `…deletion_execution_authorize` | success | same | `request_id`, `approval_id`, `execution_authorization_id`, `expires_at`, `session_age_seconds` |
| Execution: run | `…expired_delete` (existing) | success | `permission_grant_ledger` | as today (`phase: "run"`, counts, digest, `as_of`), plus `approval_id`, `execution_authorization_id`, `request_id`, `scope_digest`, `runner: "migrations_role_unauthenticated"` |
| Execution: per tenant | `…expired_delete` | success | the tenant | as today (`phase: "tenant"`, `run_id`, rows, purge and expiry times) plus `approval_id` |
| Execution: consumption | `…expired_delete` | success | `permission_grant_ledger_deletion_approval` / `approval_id` | `phase: "consume"`, `run_id`, `approval_id`, `execution_authorization_id`. Its id is the `consumed_by_platform_audit_id` of both records |
| Any refusal | the operation's action | `denied` | as above | `reason` = code; ids already known (`request_id`, `approval_id`), never values from the body |

The route-level refusals (`not_authorized`, `session_not_fresh`, `multi_factor_required`) are written by `require_platform_permission` as today, with target `http_route` and the declared route template.

---

## 7. Failure and recovery model

| Situation | Behaviour | Recovery |
|---|---|---|
| Crash between approval and execution | The approval stays unconsumed and expires at `approved_at + 72 h`. Nothing is deleted | Authorise again (R9) while the approval is valid. After expiry, start a new request |
| Expired approval or authorisation | R9 or execution refuses (`approval_expired`, `execution_authorization_expired`), with a `denied` row | A new request (approval) or a new R9 (authorisation) |
| Concurrent requests or approvals for overlapping scope | R5 and R8 lock the tenant rows in id order. R5 refuses `overlapping_request` while any live request (section 3.1: unexpired and unapproved, or with an unexpired, unconsumed approval) names a tenant in scope. Two R8 calls on one request: `request_id UNIQUE` on approvals, so the second gets `request_already_approved` (a unique violation translated to 409) | Wait for expiry or consumption |
| Hold placed during execution | Placement locks the tenant row first. Either it commits before step 3 (step 7 sees `legal_hold` → `scope_not_eligible`, nothing deleted) or it waits until the deletion commits. A hold then placed on a tenant whose rows are already gone protects nothing; that is existing behaviour, recorded in the audit | Re-request if still needed |
| Hold released during execution | After 5.4 the release waits for the tenant lock, or commits first and step 8 re-checks the releaser | None needed |
| Partial failure | A single transaction: any error (a row mismatch, a constraint, an audit insert) rolls back everything, including the consumption | Re-run with the same unconsumed authorisation, if it has not expired |
| Audit write failure | A success row is in the same transaction, so a failure rolls back the act (fail closed). A refusal row is best effort: if it fails, the failure is logged (`platform_refusal_audit_failed`, `ledger_expiry_refusal_audit_failed`) and the refusal still reaches the caller | Investigate the logs |
| Clock skew | Only the DB clock counts: `now()` in insert triggers, `clock_timestamp()` after the locks in execution. App and command-host clocks are never read. Expiry is compared in UTC | None |
| Replay of a consumed approval or authorisation | Refused (`approval_consumed`, `execution_authorization_consumed`). The trigger refuses a second consume even for the migrations role | None |
| Permission revoked between approval and execution | Step 6 re-authorises the authoriser and re-checks the approver | A new approval by a current holder |
| Suspended or revoked operator | `platform_can` is false: R8 and R9 refuse with `403`; execution refuses (`not_authorized` / `approval_no_longer_authorized`). A suspended requester does not invalidate an approval (decision 7) | As above |
| Deadlock or serialization failure | Lock order is the same everywhere (tenants, then request or approval, then authorisation). If one occurs anyway: `503` with `Retry-After` (existing `_translated`), nothing committed | Retry |
| Disabled gate | Execution refuses `deletion_disabled` before the run connects (one `denied` row on a separate migrations-role connection) | An owner-approved change, after review and tests |

---

## 8. Test plan

No test below exists yet. Names are proposals.

### 8.1 Unit
- Scope canonicalisation and `scope_digest` (order and duplicates do not change it; one id more or less does).
- Matching on error code: every new code maps to exactly one HTTP status, and an unknown subclass stays a 500.
- The command's argument rules: `--execution-authorization` excludes `--operator`, the scope and confirmation flags; `--apply` requires it.
- The operation table: 43 rows, 28 permissions, and the five new rows with `_NONE` purposes and the stated permissions (extends `tests/core/platform_authority/test_platform_operations_unit.py`).
- `PLATFORM_ROUTES` contract: 36 routes, permission, operation and `fresh_session` per route (extends `tests/api/test_platform_admin_unit.py`).

### 8.2 PostgreSQL integration (disposable database; rows created are removed)
- The full path: report → R5 → R8 by person B → R9 by person A or C → execution deletes exactly the bound rows, consumes both records and writes run, tenant and consume rows.
- Each refusal in 3.4 with its `denied` row.
- **Concurrency with real locks, both orderings** (two connections, an explicit `pg_advisory_lock`/barrier as in the existing hold/deletion race tests):
  - hold placement before / after the execution's tenant lock;
  - hold release before / after the execution's tenant lock (needs 5.4);
  - two R8 on one request; two R5 on overlapping scopes;
  - two executions with two authorisations of one approval (exactly one deletes).
- Expiry by DB clock: a stored `expires_at` in the past (set through the migrations role in a fixture), execution refused.
- Triggers: times ignore supplied values; copy equality; one-way consume; a second consume refused; delete refused, for both roles.
- Grants: runtime `UPDATE` and `DELETE` refused on the three tables; runtime `DELETE` on the ledger still refused.
- RLS: the three tables are invisible to a tenant-scoped transaction and writes are rejected there.
- The migration upgrade and downgrade, with the downgrade refused while any row exists.
- Releases before the API: a hold released through the command (no `channel`) blocks R5, R8, R9 and execution for its tenant.

### 8.3 API (TestClient)
- Each route: 401 without a session; 404 for a non-operator; 403 without the permission; `session_not_fresh` on the fresh routes; `multi_factor_required` with MFA required; the cookie POST without the trusted `Origin` gets 403.
- **No identity field accepted:** for each body, adding `operator`, `user_id`, `actor_user_id`, `approver`, `requested_by` gets `422 extra_forbidden`, and the Core function is never called (spy).
- The audit row's `actor_user_id` is the session's user, whatever the body says.

### 8.4 Negative controls (each protection removed in isolation, then restored byte for byte)

| Protection removed | Test that must fail |
|---|---|
| `extra="forbid"` on a request model | `test_identity_fields_in_any_retention_body_are_rejected` |
| approver ≠ requester check | `test_the_requester_cannot_approve` |
| releaser check at approval | `test_an_authenticated_releaser_cannot_approve_in_scope` |
| releaser re-check at execution | `test_a_release_after_approval_blocks_execution_by_that_person` |
| unauthenticated-release block | `test_a_declared_release_blocks_the_tenant` |
| authoriser ≠ approver check | `test_the_approver_cannot_authorise_execution` |
| re-authorisation at execution | `test_a_revoked_authoriser_cannot_execute` |
| expiry check (approval / authorisation) | `test_an_expired_approval_is_refused_by_the_database_clock` |
| consume in the deletion's transaction | `test_a_consumed_approval_cannot_be_replayed` |
| one-way consume trigger | `test_the_consume_is_one_way_for_every_role` |
| tenant lock in execution | `test_hold_placed_concurrently_is_seen_or_waits` (both orderings) |
| tenant lock in release (5.4) | `test_release_concurrent_with_execution_is_serialised` |
| scope equality at execution | `test_execution_refuses_a_changed_scope` |
| same-transaction audit row | `test_every_success_has_its_audit_row_in_the_same_transaction` |

### 8.5 Architecture tests
- Every request model of the retention routes forbids extra fields and has no field whose name matches `operator|user_id|actor|approver|requester|authori[sz]ed_by|executor`.
- `tests/architecture/test_migrations_role_boundary.py` keeps passing: only the expiry module opens the migrations-role session; no route, job or purge step reaches it; the routes import nothing from `expiry`.
- The runtime role still has no `DELETE` on the ledger (existing integration test, extended to the three new tables).
- `_DELETION_ENABLED` is still the literal `False` (`tests/core/permission_grants/test_expiry_disabled_unit.py::test_the_shipped_gate_is_off_and_is_a_literal`), until the explicit approved change that turns it on, which must edit that test in the same reviewed diff.
- No setting, environment variable or argument affects the gate.

### 8.6 The gate (explicit)

**Deletion remains disabled until this mechanism is implemented, independently reviewed and tested.** The implementation PR keeps `_DELETION_ENABLED = False`. A *separate* PR, approved by the owner, sets it to `True` only after:
1. the implementation has merged with all tests above passing in CI;
2. an independent review has been completed by someone who did not write the implementation (decision 8);
3. the negative controls have been recorded;
4. the runbook procedure has been rehearsed once against a disposable database.

---

## 9. Decisions still needed from the owner

1. **HTTP routes for retention.** Accept routes R1 to R9 on the opt-in platform-admin router, reversing "operator commands only" for retention. *Recommendation: accept.* Authentication is impossible without them.
2. **Releases under declared ids** (section 4.3). *Recommendation: option A.* Any unauthenticated release blocks deletion for that tenant, and only a separate owner-approved change lifts it.
3. **The command-line hold commands after the API ships.** *Recommendation:* keep `hold-permission-grant-ledger` (placing a hold is conservative and useful in an emergency), and retire `release-permission-grant-ledger-hold`. If it is kept, its releases block deletion under option A.
4. **Validity windows.** *Recommendation:* request 72 h, approval 72 h after approval (as the owner set), execution authorisation 60 min and never past the approval's expiry. All by the DB clock.
5. **Number of accounts.** May the execution authoriser be the requester (at least two accounts), or must it be a third? *Recommendation: allow two,* matching the owner's rule (two people, which holds only if decision 13 closes T4a). Three is an option for installations with enough operators.
6. **Session strength.** *Recommendation:* `fresh_session=True` on R4, R8 and R9, and refuse R8 and R9 (`409 multi_factor_not_enforced`) unless the deployment sets `PLATFORM_OPERATOR_REQUIRE_MFA=true` (ADR-0049).
7. **Re-checking authority at execution.** *Recommendation:* re-check both the approver and the authoriser (step 6), but not the requester.
8. **Independent review.** Who performs the independent review before the gate PR. *Recommendation:* a security reviewer who did not write the implementation and is not the platform owner who would approve.
9. **Two-person database credential as a complement.** *Recommendation:* document it in the runbook as recommended practice (dual control of `MIGRATIONS_DATABASE_URL`), without building anything.
10. **Request scope.** Must every tenant in a request be eligible with rows (the scope equals the eligible set), or may a request carry ineligible tenants that are skipped? *Recommendation: all eligible.* It keeps the binding exact and the refusal clear.
11. **Timing.** Implement now, or keep deletion disabled until a tenant nears eligibility? None can be eligible before two years after its purge. *Recommendation:* keep the gate off, and schedule the implementation no later than six months before the first tenant's `expires_at` shown by the report.
12. **Release locking change (5.4).** Accept that `release_permission_grant_ledger_hold` also locks the tenant row. *Recommendation: accept,* as part of the implementation PR.
13. **One person with several accounts (T4a).** Today the platform owner can enrol a second OIDC account of their own and grant it report, then act as requester and as approver. Options:
    - (a) Approval eligibility only out of band. `platform.security_retention:report` joins `NOT_GRANTED_AT_BOOTSTRAP` and is granted only by break-glass `recover --grant` after a written, independently approved request, to operators who do not hold `platform.authority:manage`, so that no in-product path creates an eligible account. Because `platform.authority:manage` could be granted to such an operator later, the invariant is checked when it is used, not only when the grant is made: R8, R9 and execution refuse a requester, approver or authoriser who currently holds it (`party_holds_authority_manage`, section 4.2). Collusion between two real people (T8) remains. Existing report grants are revoked by a runbook step. This changes the bootstrap and grant rules (owner decision), and the owner then reads retention only through the dry run or the migrations role.
    - (b) The provenance check of section 4.2 (no enrolment or grant link between the parties; a minimum age of N days). `NULL` provenance (bootstrap or break-glass) counts as linked, so such an account is not eligible, unless the owner decides to accept break-glass provenance. The owner decides between treating `NULL` as linked (proposed) and treating it as independent, which (a) needs for its break-glass recipients.
    - (c) Record it as an accepted residual risk.

    *Recommendation: (a), with (b) as defence in depth.* (b) alone is bypassable (T4a), and (c) leaves rule 2 unmet by a single person without any credential. Note the interaction: under (a), approvers are break-glass recipients with `NULL` provenance, so combining (a) and (b) requires the owner to accept `NULL` provenance for grants made with an independently approved written request recorded in the ticket. Decision 13 stays open. Until it is made, the design claims no more than *distinct accounts*, and deletion stays disabled.
