# Authenticated approval for deleting expired permission grant ledger rows

**Status: architecture decision, owner decisions of 2026-11-02 and 2026-11-03 applied, including the final-closure decisions F-1 to F-6. **Implemented, deletion disabled**, in PR #203 (open, not merged; stacked on #198, branch `feat/retention-approval-api`): migration `c3f9e1a7b5d2`, the routes of section 3.2, the register of section 4.5 and the execution model of section 5, tested against PostgreSQL 16. #198 alone contains the design only. Migration `c3f9e1a7b5d2` was edited in place before merge (final closure); any disposable database already at that revision must be rebuilt. Deletion stays disabled: `_DELETION_ENABLED` stays the literal `False`, and enabling it is a separate change that the owner approves after independent review.** First written 2026-11-02; revised 2026-11-03.

**Owner decisions of 2026-11-03 (authoritative).** The narrowly scoped authenticated platform-admin retention API is **authorised for implementation, as a separate pull request**. Design decision §9.13 is settled in detail. **Numbering:** below, the owner decisions of 2026-11-03 are cited as O-1 to O-11, and the design's own decisions of section 9 as §9.1 to §9.13.

1. Approver enrolment is valid for at most 12 months; a representative designation too.
2. Revocation is immediate and invalidates the outstanding approvals and execution authorisations made by the revoked approver. Revoking a designation suspends the enrolments it authorised, with the same invalidation.
3. The bootstrap owner keeps `platform.security_retention:report`, but it grants neither approver eligibility nor identity lookup.
4. The organisation's governing body designates the representative, not the platform owner alone.
5. The identity lookup of PR #196 (not built here) requires `platform.security_retention:report` **and** independent register eligibility. No new runtime permission anywhere: the vocabulary stays at 28.
6. **Register writes use a controlled authenticated process.** This supersedes recommendation 13f (an out-of-band migrations-role procedure with a declared runner): there is no migrations-role register procedure. Register writes are made through the authenticated platform-admin API (OIDC session).
7. Enrolments, revocations and provenance are reviewed independently every quarter.
8. 120 days pass between enrolment and first eligibility. One overlapping renewal is permitted.
9. Blank-provenance, bootstrap and break-glass accounts stay ineligible until independently verified and enrolled. Nobody approves their own enrolment or eligibility. Separate accounts are never proof of separate natural persons.
10. The register is append-only and independently reviewable. It holds reference identifiers and provenance evidence only, no unnecessary personal data.
11. Residual risks are documented: collusion, compromised OIDC accounts, owner and representative collusion, and direct database access with either credential (section 2).

**Owner decisions of 2026-11-03, final closure (authoritative; cited as F-1 to F-6).**

- **F-1. Two-party representative designation: accepted.** The design that implements O-4 and O-6 (section 4.5) is owner-approved: a platform owner *proposes* the representative, an independent security operator *confirms*, the representative *enrols* approvers, and either side of that dual control can *revoke*. It is no longer a design pending confirmation.
- **F-2. An expired designation immediately suspends the eligibility of the approvers enrolled under it.** This reverses the earlier design choice, under which an enrolment could outlive an expired, unrevoked designation. A new designation never revives those enrolments: the approvers become eligible again only through **fresh verification**, that is a new enrolment under the new designation with a `verification_ref` that none of their suspended enrolments carries, and with its own 120-day delay. Expiry is not an event, so nothing is invalidated when it passes; instead every use re-checks eligibility (approval R8, execution authorisation R9 and execution), and an outstanding approval or authorisation by such an approver **fails at its next use** (authorisation or execution) with `approver_not_eligible` or `authorizer_not_eligible`.
- **F-3. Confirmed as decided:** enrolment validity at most 12 months (O-1); immediate revocation invalidates outstanding approvals and authorisations (O-2); the bootstrap report permission grants neither approval nor lookup eligibility (O-3); designation by the governing body (O-4); quarterly independent review (O-7); a 120-day initial eligibility delay (O-8); one overlapping renewal, allowed only while both records remain valid (O-8); the existing `platform.security_retention_hold:manage` for the hold routes; no new permission; the identity lookup requires the report permission **and** valid independent register eligibility (O-5).
- **F-4. Independent reviewer (§9.8).** The review before the gate PR is made by a natural person different from the implementer, the platform owner, the representative proposer, the representative, every approver and the custodian of the migrations credential. The reviewer inspects the **exact final head** of the gate PR and the relevant security evidence; a review of an earlier commit is insufficient.
- **F-5. Migrations credential under dual control (§9.9).** Two separately authorised people; no shared personal accounts; credential access independently authorised; access and use audited; no substitution by a declared operator id. If the deployment environment cannot enforce dual control, deletion stays disabled. This is procedural and infrastructure control: **SaaS OS cannot enforce it** and contains nothing that claims to.
- **F-6. Deletion safety is unchanged.** `_DELETION_ENABLED = False`; no override; no runtime `DELETE`; no manual SQL bypass; no destructive expiry execution.

The retention API operations are: placing and releasing holds; requesting deletion approval; approving deletion; authorising execution; the eligibility and audit reports. A command may place an emergency hold but never releases a hold or approves a deletion: `release-permission-grant-ledger-hold` is removed, and a hold is released only through the authenticated route.

**History.** The first version (2026-11-02) proposed the API "for further design, not for implementation" and an approver register written only by an out-of-band migrations-role procedure, run by a *register custodian* under a declared runner id, with "custodian separation" as its main argument (former recommendation 13f and threat T15). O-6 replaces that procedure with authenticated register writes (section 4.5); the custodian, the declared runner id and the procedure's `export` subcommand are withdrawn.

This document has no ADR number of its own. It extends the ADR-0045 amendment of 2026-11-02 ("Separation of duties", bullet "Approval control"), which records the decisions.

Related documents: ADR-0045 (section 7, the HTTP and CLI boundaries; amendment of 2026-11-02), ADR-0044 (the same-origin check), ADR-0049 (operator multi-factor login), ADR-0051 (audit tables are append-only for the application role), ADR-0053 (audit digests in external logs), `docs/RUNBOOKS.md` ("Granting legal-hold management", "Deleting expired permission grant ledger rows") and PR #198.

**Terms.** A *declared* id is a user id that the person running a command types; nothing authenticates it. An *authenticated* id is the user of the SaaS OS session that the platform-admin HTTP chain validated. *Releaser* means the authenticated actor of a hold release. *DB clock* means PostgreSQL's time, never the clock of the application or the command host. *Platform owner* means a holder of `platform.authority:manage`. *Independent security operator* means a holder of `platform.security_retention_hold:manage` who does not hold `platform.authority:manage`. *Representative* means a user with an active `representative_designation` entry. *Registered approver* means a user with an eligible `approver_enrolment` entry.

---

## 0. What the code does before the implementation (verified on the branch at `40a0888`)

| Fact | Where |
|---|---|
| Platform routes are declared in one table, `PLATFORM_ROUTES` (27 routes, pinned by `tests/api/test_platform_admin_unit.py`). Each route gets the dependency `require_platform_permission(permission, operation=..., fresh_session=...)`. The prefix is `/v1/platform`. No retention route exists. | `saas_os/api/platform_admin/router.py`: `PLATFORM_ROUTES`, `build_router` |
| The handler's caller is always `UserCaller(context.actor_id)`. It is never taken from the path or the body. | `router.py`: `_caller` |
| The chain: the deployment opt-in (else 404) → `get_current_session` (a Bearer header or the session cookie, sessions only; the ADR-0044 same-origin check for a cookie-authenticated unsafe method) → a rate limit keyed by actor and route → `is_active_platform_operator` (else the 404 of an unknown path) → ADR-0049 MFA, where the deployment requires it (`401 multi_factor_required`) → `fresh_session` age, where the route declares it (`401 session_not_fresh`) → `platform_can` (`403`). The result is `PlatformRequestContext(actor_id, session_id)`. | `saas_os/api/dependencies.py`: `require_platform_permission`, `PlatformRequestContext`, `_enforce_same_origin_for_cookie_mutation`, `get_current_session` |
| The session's user comes from the OIDC callback. It validates the ID token (`identity_provider.validate_id_token`), maps issuer and subject to a user (`get_or_create_user_for_external_identity`) and calls `issue_session(user.id, multi_factor=identity.multi_factor, ...)`. Each later request presents the session secret, and `validate_session(raw_token)` returns the `Session` whose `user_id` becomes `actor_id`. Expired session rows are deleted by session retention (RA-12-5). | `saas_os/api/auth/routes.py` (callback), `saas_os/core/identity/sessions.py`: `validate_session`; `saas_os/core/identity/session_retention.py` |
| Request bodies are pydantic models. None sets `extra="forbid"`, so an unknown field is ignored rather than rejected. No exception handler is registered for `RequestValidationError`, so a schema error is FastAPI's default `422`. | `router.py`: `ReasonRequest`, `EnrollOperatorRequest`, ... |
| No platform route uses `Idempotency-Key`. Core idempotency is keyed by `(tenant_id, operation, key)`, so it has no platform form. | `dependencies.py`: `get_idempotency_key`; `saas_os/core/idempotency/service.py` |
| Pagination: `cursor` (UUID) and `limit` in the query, `next_cursor` in the response. Core rejects a page above its maximum with a 400 (`validate_page_request`, `MAX_OVERSIGHT_PAGE_SIZE = 200`). | `router.py`: `_page_arguments`, `PageSize`; `saas_os/core/platform_authority/oversight.py` |
| Core errors are translated by `_translated`: `PlatformNotAuthorizedError` → 403; `PlatformRefusalError` → `409` with its fixed `code`; `InvalidPlatformRequestError` → 400; a timeout or transaction conflict → `503` with `Retry-After`. Any other exception stays a 500. The retention errors are `ValueError`s and are not mapped. | `router.py`: `_translated`; `saas_os/core/permission_grants/errors.py` |
| `authorize_platform_caller(caller, session=..., operation=...)` reads the operation row. It refuses every `ServiceAccountCaller`. It accepts a `SystemCaller` only for a purpose the row lists. For a `UserCaller` it evaluates `platform_can` in the operation's own transaction, locking the user, operator and grant rows `FOR SHARE`. | `saas_os/core/platform_authority/authorization.py` |
| The operation table has 38 rows and the vocabulary has 28 permissions. The four retention rows accept no system purpose (`_NONE`). | `saas_os/core/platform_authority/operations.py` |
| `record_platform_event_in_transaction` appends one platform audit row inside the caller's transaction; its `entry_id` can be fixed beforehand, so a state row can name it. `record_platform_refusal` / `recording_platform_refusal` write a `denied` row in a transaction of their own, best effort. Audit metadata is limited to 8192 bytes and has a key denylist. | `saas_os/core/platform_authority/audit.py`; `saas_os/core/audit_log/metadata.py` |
| The holds table (`core.permission_grant_ledger_holds`, migration `a9c3e5f7b1d4`) has the tenant-context exclusion policy, a one-way release trigger and runtime privileges `SELECT`, `INSERT` and `UPDATE (released_at, released_by_platform_audit_id)`; `DELETE` is revoked. It has no foreign key onto the audit log (the platform test helpers truncate the audit log). | `saas_os/infra/db/migrations/versions/a9c3e5f7b1d4_create_core_permission_grant_ledger_holds.py` |
| Hold placement locks the tenant row `FOR UPDATE`. Hold **release** locks only the hold row. | `saas_os/core/permission_grants/retention.py` |
| The report recomputes eligibility with the DB clock and records `eligible_ledger_rows` and `eligible_digest`. | `retention.py`: `permission_grant_ledger_retention_report`, `eligible_ledger_digest` |
| Deletion: one transaction on the migrations role, authorising a declared `UserCaller`; refused with `deletion_disabled` before the run connects while `_DELETION_ENABLED` is `False`. | `saas_os/core/permission_grants/expiry.py` |
| The migrations-role connection checks `current_user`: owner (or member of the owner) of the ledger, holds `DELETE`, not `DATABASE_URL`'s user. No fallback. | `saas_os/infra/db/migrations_role.py` |
| The first owner gets 27 permissions; `platform.security_retention_hold:manage` is in `NOT_GRANTED_AT_BOOTSTRAP`, granted only by the break-glass `recover --grant`. | `saas_os/api/platform_bootstrap.py` |
| Every retention command takes a **declared** `--operator`. | `saas_os/ops/operator_cli.py`, `saas_os/ops/permission_grant_ledger_expiry.py` |

---

## 1. Decision

### 1.1 Context

The owner's rules of 2026-11-02 are:

1. Deletion needs a verifiable approval.
2. A person who releases a legal hold must not be able to authorise, alone, the deletion of the same records.
3. A declared operator id is not an authenticated identity.
4. No new permission (the vocabulary stays at 28) and no runtime `DELETE` on the ledger.
5. Deletion stays a manual migrations-role procedure.

The owner decisions of 2026-11-03 add: authenticated register writes (O-6), designation by the governing body (O-4), 12-month validity (O-1), a 120-day delay with one overlapping renewal (O-8), immediate revocation with invalidation (O-2), and the removal of every command that releases or approves. The final-closure decisions of the same day accept the two-party designation that implements O-4 and O-6 (F-1), make an expired designation suspend its approvers at once (F-2), and fix who reviews before the gate (F-4) and the dual control of the migrations credential (F-5).

### 1.2 Decision

1. **Authenticated retention API** (authorised for implementation, 2026-11-03). The routes of section 3.2 are added to the existing opt-in platform-admin router. Identity comes only from the existing IAM/OIDC session (`_caller(context)`). Every request body forbids extra fields (`extra="forbid"`) and has no identity field. The subject of a register write is named in the URL path, never in the body.
2. **Person-distinct steps.** A deletion needs three recorded acts by authenticated users: a *request*, an *approval* and an *execution authorisation*. The requester and the approver are different users; the approver and the execution authoriser are different users. **Separate accounts never prove separate human identities** (threat T4a). The approver and the authoriser must therefore each be a registered approver whose enrolment names a different verified natural person (section 4.5). Neither may be the authenticated releaser of any hold on any tenant in scope. A release that is not authenticated blocks those tenants.
3. **Binding.** The request, the approval and the execution authorisation bind the same exact scope: a sorted, distinct set of tenant ids, the eligible row count and the eligible digest. An approval is single use and expires 72 hours after it is given, by the DB clock. An execution authorisation is single use, valid for 60 minutes and never past the approval's expiry.
4. **Execution stays on the migrations role.** The runtime role keeps no `DELETE`. The procedure takes the execution authorisation id instead of `--operator`, `--confirm-rows` and `--confirm-digest`. Under the tenant-row locks it revalidates scope, count, digest, active holds, the person rules, invalidation and the current authority and eligibility of the approver and the authoriser, then consumes the approval and the authorisation in the deletion's own transaction. The process that runs the command is still **not authenticated**.
5. **No new permission.** Every new operation row uses an existing permission: `platform.security_retention:report`, `platform.security_retention_hold:manage`, `platform.authority:manage` or `platform.audit:read`.
6. **Approver eligibility register, written through the authenticated API** (O-6). Designation is a two-party authenticated act (the design implementing O-4 and O-6, accepted by the owner, F-1): a platform owner proposes and an independent security operator confirms (section 4.5). A representative enrols approvers. Every write is a platform operation of the session's user, audited in its own transaction. Eligibility is checked at approval, at execution authorisation and at execution. The register's strength is **procedural**; it does not make separate accounts separate people.
7. **The gate stays.** `_DELETION_ENABLED` stays the literal `False`. Turning it on is a separate change that the owner approves. No setting, environment variable or argument is ever added for it.

### 1.3 Consequences

- Rule 2 is checked over **authenticated** ids. A release made through the command line (before this change) cannot be attributed, so it keeps the affected tenant's rows. That errs towards retention.
- This reverses "No HTTP route: operator commands only" from the ADR-0045 amendment of 2026-11-02, for retention operations only. The ADR's section 7 table and the pinned route contract grow to match.
- Four new global tables (the register, requests, approvals and execution authorisations), eighteen retention routes (27 → 45; three of them use existing operation rows), fourteen new operation rows (38 → 52), still 28 permissions and no new system purpose. One change to existing behaviour: a hold release locks the tenant row first (section 5.4), and it takes the authenticated session evidence.
- **The runtime role now has `INSERT` on the register.** A holder of the application credential can therefore forge register entries, as it can already forge approvals (T6). The register makes forgery detectable (audit rows, ADR-0053 digests, the quarterly review); it does not prevent it. The earlier "custodian separation" argument is withdrawn with the migrations-role procedure.
- Approval needs at least two independently verified natural persons (approver and authoriser), each enrolled by a representative whom the governing body designated through two different authenticated accounts. Separate accounts never prove separate humans: the control is the out-of-band verification plus the register, and it is **procedural**.
- Holders of the database credentials can still bypass every control (section 2). The design makes the legitimate path the only audited one and makes a bypass detectable, not impossible.

### 1.4 Alternatives rejected

| Alternative | Why rejected |
|---|---|
| **Compare declared ids** (approver ≠ releaser on the command line) | One holder of both credentials declares a different operator for each step. |
| **Signed approvals** (personal keys registered out of band) | A second identity system beside OIDC, with key management in Core. |
| **Two-person database credential** only | Outside SaaS OS and specific to a provider; it does not bind who released a hold. Required beside this design (§9.9, F-5: dual control of the migrations credential, or deletion stays disabled), not instead of it. |
| **Keep deletion disabled permanently** | The fallback while this is built and reviewed; it keeps rows beyond the two-year policy. |
| **A runtime `DELETE` behind the API** | Violates rule 4. |
| **Out-of-band migrations-role register procedure** (the earlier 13f) | Superseded by O-6: its runner is unauthenticated and its "custodian separation" is purely procedural; authenticated writes record which session's user acted. |
| **A register check of the form "holds permission P"** | Any in-product permission the platform owner holds, the owner can grant to a second account of their own. The only in-product identity the owner cannot create is a holder of `platform.security_retention_hold:manage` (withheld at bootstrap, granted only by break-glass after an independently approved request); designation therefore needs that holder's confirmation (section 4.5). |

---

## 2. Threat model

**Actors.**
- The *platform owner*: a holder of `platform.authority:manage` (the bootstrap owner holds 27 permissions, report included, hold management excluded).
- The *independent security operator*: holds `platform.security_retention_hold:manage`, granted out of band, and not `platform.authority:manage`.
- The *reporter / requester*: any operator holding `platform.security_retention:report`.
- The *representative*: designated by the organisation's governing body; recorded by an owner's proposal and a security operator's confirmation.
- The *registered approver / authoriser*: holds report **and** an eligible enrolment.
- The *application credential holder*: `DATABASE_URL`, the runtime role.
- The *migrations credential holder*: `MIGRATIONS_DATABASE_URL`, the schema owner.
- A *compromised OIDC account or session*.
- *Colluding insiders*.

**Assets.** The ledger rows, the hold history, the approval records, the register, the platform audit log, and its external digests (ADR-0053).

| # | STRIDE | Actor | Threat | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T1 | Spoofing | Any caller | Puts an `operator`, `user_id` or `approver` field in a body | `extra="forbid"` on every request model (`422 extra_forbidden`), no identity field; the caller is only `UserCaller(context.actor_id)`; register subjects only in the path. Architecture test | None at the API |
| T2 | Spoofing | Compromised OIDC session | Uses a stolen session to approve, authorise or write the register | Fresh session on release, approval, authorisation and every register write; ADR-0049 MFA required by the deployment for approval, authorisation and register writes (§9.6); the session must be the caller's, live and multi-factor; rate limit. A second, distinct registered person is still needed | A fresh stolen session acts as its user within the window |
| T3 | Elevation | Hold manager | Releases a hold, then approves the deletion of the same rows | The approver and the authoriser must not be an authenticated releaser of any hold on any tenant in scope (approval, authorisation, execution). The hold manager cannot be enrolled (section 4.5) | Relies on T6 for forged release evidence |
| T4 | Elevation | Platform owner | Requests and approves alone | approver ≠ requester; authoriser ≠ approver | With one account: none. Several accounts: T4a |
| T4a | Spoofing, Elevation | **One person, several accounts** | Enrols a second OIDC account, grants it report, and uses one account per step | A report grant gives no eligibility. Eligibility comes only from an enrolment written by a representative, whose designation needs a platform owner **and** an independent security operator (two accounts the owner cannot both create in-product). Authority holders, hold managers and representatives cannot be enrolled; approver and authoriser need different `natural_person_ref`. `party_holds_authority_manage` keeps owner accounts out of every step except reporting | Separate accounts never prove separate humans. The control is the out-of-band verification behind each enrolment, and it is **procedural** (T14) |
| T5 | Repudiation | Any operator | Denies having approved | One platform audit row per act in the act's transaction, with `actor_user_id`, `session_id`, correlation id; ADR-0053 digests | Claiming a stolen session (T2) |
| T6 | Tampering | **Application credential holder** | Inserts a forged request, approval, authorisation, **register entry**, release evidence or audit row (the runtime role has `INSERT` on all of them) | Triggers force DB-clock times, shapes, references, copy-equality and append-only rules; a deferred check requires each state row's audit row by the same actor in the same transaction. These are **not authenticity**. Detection: audit rows without an HTTP access record or session; ADR-0053 digests; the quarterly review | **Cannot be prevented.** The application credential can forge anything the application writes, the register included |
| T7 | Tampering, Elevation | Migrations credential holder | Deletes ledger rows with SQL, disables triggers, rewrites rows, or runs the procedure with any authorisation id | None preventive in SaaS OS. Procedural (F-5, §9.9): the migrations credential is under dual control (two separately authorised people, no shared personal accounts, independently authorised and audited access and use, never replaced by a declared operator id); where the deployment cannot enforce that, deletion stays disabled. Detection: ADR-0053 digests; reconciliation of ledger counts against approvals and runs | **Cannot be prevented by SaaS OS**; dual control is infrastructure and procedure, which SaaS OS can neither enforce nor verify |
| T8 | Elevation | Colluding pair | Requester and approver, or approver and authoriser, agree to delete | Two independently verified people are the control asked for; every step names its account; quarterly review | **Accepted**: separation of duties assumes no collusion |
| T9 | Tampering | Any | Changes holds or ledger rows between approval and execution | Execution locks the tenant rows and recomputes count, digest, scope, holds and releasers | None |
| T10 | Info. disclosure | Any operator | Approval records or the register reveal tenants or people | Exclusion policy on the four tables; ids, counts, digests and opaque references only; reading needs report or `platform.audit:read` | Readers see tenant ids and user ids |
| T11 | Denial of service | Operator | Floods requests or blocks scopes | Rate limit; one live request per tenant; request and approval expiry | A live request blocks an overlapping one until expiry or consumption |
| T12 | Spoofing | Service account / system caller | Reaches a retention operation | Refused by `authorize_platform_caller`; sessions only; every new row `_NONE` | None |
| T13 | Replay | Migrations credential holder | Reuses a consumed approval | Single use, trigger-enforced one-way consume | Only by T7 |
| T14 | Elevation | **Colluding platform owner and representative**, or owner and security operator | The representative enrols the owner's second account, or a security operator confirms an owner's sham designation | Designation needs two authenticated parties; authority holders cannot be representatives or approvers; the governing body designates; each entry carries opaque references to the external records; the 120-day delay guarantees that a quarterly review cycle passes before first use | **Procedural.** Collusion of the owner with the representative (or with the security operator, for designation) defeats the register. Detection: the independent review against external records |
| T15 | Tampering, Elevation | **Direct database access, either credential** | Writes register entries, approvals or audit rows with SQL; a platform owner who also holds a database credential can do this alone, and can also give an account of their own `platform.security_retention_hold:manage` (break-glass `recover --grant` with container or database access, or a grant row written with the application credential), which defeats "the one identity the owner cannot create" and so the two-party designation | Triggers make a forged entry shaped and timed like a real one but do not authenticate it. The 120-day delay applies to every enrolment insert, forged or not, unless the triggers are disabled (migrations credential). Procedural (F-5, §9.9): dual control of the migrations credential; where the deployment cannot enforce it, deletion stays disabled. Detection: register rows without matching HTTP access records, sessions or external records; audit rows missing from the ADR-0053 chain; the quarterly review | **Cannot be prevented by SaaS OS.** Requirements 2 and 3 of section 4.5 hold only while the database credentials are not held by a platform owner acting alone (dual control, §9.9, which SaaS OS cannot enforce) |
| T16 | Spoofing | **Compromised OIDC account** of a registered approver or representative | Approves, authorises, enrols or revokes as that person | Fresh session and MFA; a second registered person still needed; revocation is immediate and invalidates outstanding approvals and authorisations | The account acts as its user until revoked. Detection: platform audit rows against IdP sign-in logs |

**Database credentials (explicit).** Whoever holds the application or the migrations database credential can bypass **every** application-level control here. The application credential can forge register entries, approvals, release evidence and audit rows; the migrations credential can also delete ledger rows, drop triggers and rewrite rows. What exists is **detection**:
1. **The platform audit log.** Every legitimate step leaves a row in its own transaction, naming the session. A deletion without a run row naming a consumed approval is suspect.
2. **ADR-0053 audit digests.** A later rewrite or deletion of an audit row is detectable against the external copy; a forgery inserted before the window settles is not.
3. **Reconciliation** of ledger counts against approvals and runs (runbook query).
4. **The quarterly independent review** (O-7) of every register entry against its external designation, authorisation and verification records.

---

## 3. Endpoint contract

All routes are added to `PLATFORM_ROUTES` under `/v1/platform`. Each is a plain handler whose dependency is `require_platform_permission`. Each calls one Core function with `caller=_caller(context)` and, for every state-changing route except the report and hold placement, the session evidence of the request (`PlatformSessionEvidence(session_id, multi_factor_required)`): Core checks that this session is the caller's, unrevoked and unexpired, and records its id and age.

### 3.1 Conventions

- **Authentication and CSRF** come from `require_platform_permission`: sessions only, ADR-0044 for cookie POSTs, `404` for a non-operator, `401 session_not_fresh` on fresh routes (at most `PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS`, at most 900), `401 multi_factor_required` with `PLATFORM_OPERATOR_REQUIRE_MFA`.
- **Multi-factor for approval, authorisation and register writes** (§9.6, adopted as recommended; implemented in PR #203 (open, not merged)): these refuse `409 multi_factor_not_enforced` unless the deployment requires MFA (`PLATFORM_OPERATOR_REQUIRE_MFA=true`) **and** the presenting session records a multi-factor login.
- **Identity.** No `operator`, `user_id`, `actor`, `approver`, `requester` or `authorized_by` field in any request. Every request model is `extra="forbid"`; an extra field is a `422` (`extra_forbidden`), the handler never runs. A register subject is a path parameter (`{user_id}`), and a register entry named in the path must belong to that subject (`404` otherwise).
- **Idempotent recovery.** A retried request, approval, execution authorisation, hold release or register write by the **same caller with identical content** returns the existing record with `"replay": true` (and writes an audit row marked `replay`). Any difference (another caller, another scope, count, digest, reference, validity or reason) is the operation's `409`. Hold placement is not replayed: an active hold with the same reference is `hold_already_active`, whoever asks. Content is the bound values and the reason (compared with the original act's audit row). There is still no `Idempotency-Key` (Core's store is tenant-scoped).
- **Live request.** A request is *live* while (i) it has no approval and `now() < request.expires_at`, or (ii) it has an approval with `now() < approval.expires_at` that is neither consumed nor invalidated.
- **Pagination.** `cursor` (UUID) and `limit` (at most 200), keyset in id order; `next_cursor`.
- **Errors.** `403 {"detail":"Not authorized."}`; `404 {"detail":"<resource> not found."}`; `409 {"detail":"<code>"}` with a fixed code; `400` for `invalid_request`; `422` for schema errors; `429` and `503` with `Retry-After`. `_translated` gains one explicit table from each retention code to its status (section 3.4); an unknown code stays a 500.
- **Free text and references.** `reason`: 1 to 500 characters, no control characters. Every `*_ref` and hold `reference`: `^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$`, an opaque identifier of a record kept outside SaaS OS, never a name or personal data.

### 3.2 Routes

Paths are relative to `/v1/platform/permission-grant-ledger`. "report" is `platform.security_retention:report`; "hold" is `platform.security_retention_hold:manage`; "authority" is `platform.authority:manage`; "audit" is `platform.audit:read`.

| # | Method and path | Permission | Operation (`permission_grant_ledger.*`) | Fresh |
|---|---|---|---|---|
| R1 | `POST /retention-report` | report | `retention_report` (existing) | no |
| R2 | `GET /holds` | hold | `hold_read` (new) | no |
| R3 | `POST /holds` | hold | `hold_place` (existing) | no |
| R4 | `POST /holds/{hold_id}/release` | hold | `hold_release` (existing) | **yes** |
| R5 | `POST /deletion-requests` | report | `deletion_request` (new) | no |
| R6 | `GET /deletion-requests` | report | `deletion_read` (new) | no |
| R7 | `GET /deletion-requests/{request_id}` | report | `deletion_read` | no |
| R8 | `POST /deletion-requests/{request_id}/approve` | report | `deletion_approve` (new) | **yes** |
| R9 | `POST /deletion-requests/{request_id}/execution-authorizations` | report | `deletion_execution_authorize` (new) | **yes** |
| R10 | `GET /approver-register` | audit | `approver_register_read` (new) | no |
| R11 | `GET /approver-register/eligibility` | audit | `approver_eligibility_read` (new) | no |
| R12 | `POST /approver-register/representatives/{user_id}/proposals` | authority | `representative_propose` (new) | **yes** |
| R13 | `POST /approver-register/representatives/{user_id}/proposals/{entry_id}/confirm` | hold | `representative_confirm` (new) | **yes** |
| R14 | `POST /approver-register/representatives/{user_id}/designations/{entry_id}/revoke` | authority | `representative_revoke_by_owner` (new) | **yes** |
| R15 | `POST /approver-register/representatives/{user_id}/designations/{entry_id}/security-revoke` | hold | `representative_revoke_by_security` (new) | **yes** |
| R16 | `POST /approver-register/approvers/{user_id}/enrolments` | report | `approver_enrol` (new) | **yes** |
| R17 | `POST /approver-register/approvers/{user_id}/enrolments/{entry_id}/revoke` | report | `approver_revoke_by_representative` (new) | **yes** |
| R18 | `POST /approver-register/approvers/{user_id}/enrolments/{entry_id}/security-revoke` | hold | `approver_revoke_by_security` (new) | **yes** |

A route has one permission, so each (act, permission) pair has its own operation row: an approver enrolment can be revoked by a representative (R17) or by an independent security operator (R18), a designation by a platform owner (R14) or by an independent security operator (R15). There is no route for the deletion itself (section 5) and no command that releases a hold or approves anything.

### 3.3 Schemas

All UUIDs are lowercase strings; all times are RFC 3339 UTC from the DB clock. Every request object is `additionalProperties: false`.

- **R1** `{"tenant_ids": [...], "all_purged": false, "after": null, "limit": 1000, "reason": "..."}` → the report: `as_of`, `more`, `eligible_ledger_rows`, `eligible_digest`, `tenants[]` (`tenant_id`, `status`, `ledger_rows`, `active_holds`, `purged_at`, `expires_at`). `as_of` is not accepted over HTTP.
- **R2** query `tenant_id`, `active`, `cursor`, `limit` → `{"holds": [{"id", "tenant_id", "reference", "placed_at", "released_at", "release_authenticated"}], "next_cursor"}`; `release_authenticated` is `null` while active, otherwise `true` only for a release with authenticated evidence (section 4.2).
- **R3** `{"tenant_id", "reference", "reason"}`; **R4** `{"reason"}` → `{"hold_id", "tenant_id", "reference", "placed_at", "released_at", "platform_audit_id", "replay"}`.
- **R5** `{"tenant_ids": [...1 to 1000], "eligible_ledger_rows": 1, "eligible_digest": "64 hex", "reason"}`. Core sorts and de-duplicates; every tenant must be eligible with at least one row (`scope_not_eligible`; §9.10); the count and digest are recomputed under lock (`confirmation_mismatch`).
- **R5, R7, R8 response** `{"id", "tenant_ids", "scope_digest", "eligible_ledger_rows", "eligible_digest", "requested_at", "request_expires_at", "requested_by_user_id", "state": "pending|approved|consumed|expired|invalidated", "approval": null | {"id", "approved_by_user_id", "approved_at", "expires_at", "consumed_at", "invalidated_at"}, "replay"}`. The user ids are read from the records, never request inputs. **R6** `{"requests": [...], "next_cursor"}`, query `cursor`, `limit`.
- **R8** `{"eligible_ledger_rows", "eligible_digest", "reason"}`: the approver restates what they verified.
- **R9** `{"reason"}` → `{"id", "approval_id", "request_id", "authorized_by_user_id", "authorized_at", "expires_at", "eligible_ledger_rows", "eligible_digest", "scope_digest", "replay"}`; the `id` is what the operator passes to the migrations-role command.
- **R10** query `subject_user_id`, `entry_type`, `cursor`, `limit` → `{"entries": [{"id", "entry_type", "subject_user_id", "recorded_by_user_id", "designation_ref", "natural_person_ref", "verification_ref", "authorisation_ref", "ticket_ref", "proposal_entry_id", "authorised_by_entry_id", "revokes_entry_id", "renews_entry_id", "valid_until", "eligible_from", "proposal_expires_at", "recorded_at", "recorded_by_platform_audit_id"}], "next_cursor"}`. This JSON is the export for the independent reviewer.
- **R11** query `cursor`, `limit` → `{"approvers": [{"entry_id", "subject_user_id", "natural_person_ref", "state": "eligible|waiting|expired|revoked|suspended", "eligible_from", "valid_until", "authorised_by_entry_id"}], "as_of", "next_cursor"}`, one row per enrolment, decided with the DB clock from the register alone (a use also re-checks the person's current permissions). `suspended` means the enrolment's designation was revoked or has expired (F-2).
- **R12** `{"designation_ref", "ticket_ref", "valid_until", "reason"}`; **R13** `{"ticket_ref", "reason"}`; **R14, R15, R17, R18** `{"ticket_ref", "reason"}`; **R16** `{"natural_person_ref", "verification_ref", "authorisation_ref", "ticket_ref", "valid_until", "renews_entry_id": null, "reason"}` → the written entry (R10's shape) plus `"replay"`.

### 3.4 Status and error codes

| Code | HTTP | Raised by |
|---|---|---|
| (unknown body field, bad type, out of range) | 422 | FastAPI / pydantic |
| `invalid_request` | 400 | Core validation (`valid_until` beyond 12 months or not after the 120-day delay, a malformed reference) |
| `not_authorized` | 403 | route or Core authorisation |
| `session_not_fresh`, `multi_factor_required` | 401 | dependency chain |
| `tenant_not_found`, `hold_not_found`, `request_not_found`, `register_entry_not_found`, `subject_not_found` | 404 | R3, R4, R7–R9, R13–R18, R12/R16 |
| `hold_already_active`, `hold_already_released` | 409 | R3, R4 (a different caller or content; the same is a replay) |
| `multi_factor_not_enforced`, `session_evidence_invalid` | 409 | R4 (evidence only), R8, R9, R12–R18 |
| `confirmation_mismatch` | 409 | R5, R8, R9, execution |
| `scope_not_eligible` | 409 | R5, R8, R9, execution |
| `overlapping_request` | 409 | R5 |
| `request_expired`, `request_already_approved` | 409 | R8 |
| `approver_is_requester`, `approver_released_hold`, `approver_linked_to_requester` | 409 | R8, R9, execution |
| `unauthenticated_release_in_scope` | 409 | R5, R8, R9, execution (§9.2) |
| `approval_missing`, `approval_expired`, `approval_consumed`, `approval_invalidated` | 409 | R9, execution |
| `authorizer_is_approver`, `authorizer_released_hold`, `authorizer_linked_to_approver` | 409 | R9, execution |
| `approver_not_eligible`, `authorizer_not_eligible`, `same_natural_person` | 409 | R8 / R9, execution |
| `party_holds_hold_manage` | 409 | R8, R9, execution (an approver or authoriser who holds hold management; checked after the releaser rules; implemented in #203 after its review) |
| `execution_already_authorized` | 409 | R9 (a live authorisation of the approval exists and this is not its identical retry by the same caller; idempotent recovery, section 3.1; a new one may follow its expiry) |
| `proposal_already_pending` | 409 | R12 (an unconfirmed, unexpired proposal for the subject exists and this is not its identical retry by the same owner; section 3.1) |
| `party_holds_authority_manage` | 409 | R5, R8, R9, execution; R13, R15–R18 (the caller) |
| `not_a_representative` | 409 | R16, R17 (no active designation) |
| `subject_linked_to_representative` | 409 | R16 (a provenance link between representative and subject, defence in depth) |
| `register_subject_is_caller`, `subject_holds_authority_manage`, `subject_holds_hold_manage`, `subject_is_representative`, `subject_is_approver` | 409 | R12, R13, R16 |
| `proposal_expired`, `proposal_already_confirmed`, `confirmer_is_proposer` | 409 | R13 |
| `approver_already_enrolled`, `natural_person_already_enrolled`, `invalid_renewal` | 409 | R16 |
| `verification_not_fresh` | 409 | R16 (the `verification_ref` of an enrolment suspended by its designation's expiry or revocation, reused; F-2) |
| `entry_already_revoked` | 409 | R14, R15, R17, R18 |
| `execution_authorization_not_found`, `_expired`, `_consumed`, `_invalidated`, `approval_no_longer_authorized`, `deletion_disabled` | (command, exit 1) | execution |
| lock timeout, deadlock, serialization failure | 503 | `_translated` (existing) |

Each code is the `code` of a `PermissionGrantLedgerRetentionError` (or a `PlatformRefusalError`) and is the `reason` of the `denied` row. *Exceptions (implementation of #203):* a body or query that fails the schema (`422`), a malformed `reason` (`400`, `InvalidPlatformRequestError`) or a page request refused before the oversight read starts (`400`) writes no `denied` row; every refusal after the caller and the input are known does. Opaque references are compared exactly, case included: one external record has one spelling.

**Fresh verification and pending proposals (implementation of #203).** `verification_not_fresh` compares reference strings only: SaaS OS cannot tell whether a new `verification_ref` names a new verification, so fresh verification after a suspension is procedural, and the quarterly review must reconcile each re-enrolment's `verification_ref` with a **new** external verification record. `proposal_already_pending` refuses any other proposal for a subject while an unconfirmed proposal is pending (up to 72 hours); to recover from a mistaken proposal, wait for it to expire, or have it confirmed and then revoke the designation (R14 or R15).

---

## 4. Authorisation matrix

### 4.1 New operation rows (permissions unchanged: 28)

| Key (`permission_grant_ledger.*`) | Permission | System purposes | Audit action (`platform.permission_grant_ledger.*`) |
|---|---|---|---|
| `hold_read` | hold | none | `hold_read` |
| `deletion_read` | report | none | `deletion_read` |
| `deletion_request` | report | none | `deletion_request` |
| `deletion_approve` | report | none | `deletion_approve` |
| `deletion_execution_authorize` | report | none | `deletion_execution_authorize` |
| `approver_register_read` | audit | none | `approver_register_read` |
| `approver_eligibility_read` | audit | none | `approver_eligibility_read` |
| `representative_propose` | authority | none | `representative_propose` |
| `representative_confirm` | hold | none | `representative_confirm` |
| `representative_revoke_by_owner` | authority | none | `representative_revoke_by_owner` |
| `representative_revoke_by_security` | hold | none | `representative_revoke_by_security` |
| `approver_enrol` | report | none | `approver_enrol` |
| `approver_revoke_by_representative` | report | none | `approver_revoke_by_representative` |
| `approver_revoke_by_security` | hold | none | `approver_revoke_by_security` |

The existing rows (`retention_report`, `hold_place`, `hold_release`, `expired_delete`) are unchanged. The table goes from 38 to 52 rows. Every new row requires a person; no system purpose is accepted (the earlier `approver_register_write` row under `PLATFORM_BOOTSTRAP` is withdrawn). The three reads follow the oversight convention (an attempt row, then a completion row).

**Separation is by operation, person and register, not by permission.** Request, approval and execution authorisation all require report; the permission separates nothing between them. Separation comes from the distinct operation rows, the person rules and, for the approver and the authoriser, the register, which alone speaks to distinct *humans*, procedurally.

### 4.2 Matrix

| Operation | Permission | Who may | Who may **not** |
|---|---|---|---|
| Report (R1, or the command) | report | Any operator holding report | Service accounts; system callers |
| Place hold (R3, or the command) | hold | Hold manager | Everyone else, the platform owner included |
| Release hold (R4) | hold, fresh | Hold manager, through the authenticated route only | Any command (removed); a stale session |
| Request (R5) | report | A reporter who does not hold authority | Authority holders (`party_holds_authority_manage`); anyone while a scope tenant has an unauthenticated release |
| Approve (R8) | report, fresh, MFA, **eligible enrolment** | A registered approver, not authority, not the requester, not an authenticated releaser in scope, not provenance-linked to the requester | The requester; unregistered accounts (bootstrap and break-glass accounts included); authority holders; releasers in scope |
| Authorise execution (R9) | report, fresh, MFA, **eligible enrolment** | A registered approver, not authority, not the approver, a different `natural_person_ref` from the approver's, not a releaser in scope; may be the requester (§9.5) | The approver; any account of the same verified person; unregistered accounts; authority holders; releasers in scope; anyone once the approval expired, was consumed or was invalidated |
| Execute (command) | none at the runner; the authoriser's report and both parties' eligibility re-checked | Whoever holds the migrations credential and the authorisation id. **The runner is not authenticated** | A runner without the migrations role; any invalid, expired, consumed, invalidated or rebound record |
| Propose a representative (R12) | authority, fresh, MFA | A platform owner; the subject is someone else, holds no authority and no eligible-or-waiting enrolment | Anyone without authority |
| Confirm a designation (R13) | hold, fresh, MFA | An independent security operator who is neither the proposer nor the subject, within 72 hours of the proposal | Authority holders (`party_holds_authority_manage`); the proposer; the subject |
| Enrol an approver (R16) | report, fresh, MFA, **active designation** | A representative who does not hold authority; the subject is someone else, holds neither authority nor hold management, is not a representative | The subject; anyone without an active designation |
| Revoke an enrolment (R17 / R18) | report + active designation / hold (independent) | Any active representative, or an independent security operator | Authority holders |
| Revoke a designation (R14 / R15) | authority / hold (independent) | A platform owner, or an independent security operator | — |
| Read the register and eligibility (R10, R11) | audit | Holders of `platform.audit:read` | — |

**How a releaser is resolved.** `released_by_platform_audit_id` → that platform audit row → `actor_user_id`. A release counts as **authenticated** only when the row has `actor_type = 'user'`, its metadata has `channel = "platform_http"` and a `session_id`, and that session was verified in the release's own transaction (the caller's, unrevoked, unexpired). The verification is made at release time because expired session rows are later deleted by session retention; use-time checks read the audit row only. A release without that evidence (every release made by the removed command) is *unauthenticated* and blocks its tenant (section 4.3). The lookup goes through a helper in `saas_os.core.platform_authority`, the only package that touches the platform models. Releases of every hold on every tenant in scope count, from any time. **These checks do not stop a holder of the application credential**, who can write the audit row directly (T6).

**Provenance link (defence in depth only).** The approver and the authoriser are refused (`approver_linked_to_requester`, `authorizer_linked_to_approver`) when one enrolled the other's operator (`enrolled_by_user_id`) or granted the other's report permission (`granted_by_user_id`), checked both ways. `NULL` provenance is not evaluated: such an account is ineligible unless it has its own enrolment.

**No authority holders in the chain.** At R5, R8, R9 and execution, Core refuses (`party_holds_authority_manage`) when the requester, the approver or the authoriser currently holds `platform.authority:manage`. With the register's refusal to enrol authority holders, this keeps the platform owner's accounts out of every step except reporting and proposing a representative.

### 4.3 Releases made under declared ids (§9.2, adopted as recommended; implemented in PR #203 (open, not merged))

A release made by the former command `release-permission-grant-ledger-hold` records a declared `actor_user_id` and no `channel`. **Option A** applies: any unauthenticated release on a tenant in scope blocks request, approval, authorisation and execution for that tenant (`unauthenticated_release_in_scope`); its rows stay retained. Lifting the block is a separate owner-approved change. The command is removed (§9.3, decided by the owner on 2026-11-03), so no new unauthenticated release can be made; options B to D of the first version are not adopted.

### 4.4 Callers that are always refused

`ServiceAccountCaller` and every `SystemCaller` (every new row has `_NONE` purposes). An unauthenticated request gets `401`; a non-operator `404`.

### 4.5 Approver eligibility register (§9.13; authenticated writes, O-6)

**Principle.** Separate accounts never prove separate human identities. The control is an **out-of-band verification of a distinct natural person**, recorded by a representative in an **append-only, independently reviewable register** through authenticated API writes. Eligibility to approve (R8) or authorise execution (R9) comes only from that register. Its strength is **procedural**.

**Why designation is two-party.** Any in-product permission the platform owner holds, the owner can grant to a second account of their own; a check of the form "holds permission P" never separates a person from the owner. The only in-product identity the owner cannot create is the holder of `platform.security_retention_hold:manage`: withheld at bootstrap, granted only by the break-glass `recover --grant` after an independently approved written request (runbook "Granting legal-hold management"). So:

- **`representative_designation_proposal`** (R12): an authenticated platform owner (holds `platform.authority:manage`), fresh session, MFA. Subject (the future representative) in the path. Body: `designation_ref` (the governing body's resolution or appointment record, O-4), `ticket_ref`, `valid_until` (at most 12 months; O-1), `reason`. An unconfirmed proposal expires 72 hours after it is recorded (`proposal_expires_at`).
- **`representative_designation`** (R13, the confirmation): an authenticated independent security operator (holds `platform.security_retention_hold:manage`, does **not** hold `platform.authority:manage`), fresh, MFA, neither the proposer nor the subject. It names the proposal (path), copies its subject, `designation_ref` and `valid_until`, and records its own `ticket_ref`. **Neither the owner alone nor the security operator alone can designate.**
- **`approver_enrolment`** (R16): an authenticated, currently designated representative (an active designation; route permission report; not an authority holder), fresh, MFA. Subject ≠ caller. The subject must not hold `platform.authority:manage` or `platform.security_retention_hold:manage` (on a non-revoked operator) and must not have an active designation. Body: `natural_person_ref`, `verification_ref`, `authorisation_ref`, `ticket_ref`, `valid_until` (at most 12 months, and after the delay), optional `renews_entry_id`, `reason`. `eligible_from = recorded_at + 120 days`, forced by the trigger (O-8). No second active enrolment for the same subject or `natural_person_ref`, except exactly one renewal of the current entry, made while both records remain valid (O-8). An enrolment whose designation expired or was revoked is suspended: it is not active, cannot be renewed, and is never revived by a new designation; the subject is enrolled again under the new designation, with fresh verification: a `verification_ref` that no suspended enrolment of the same subject or `natural_person_ref` carries (`verification_not_fresh`), and its own 120-day delay (F-2).
- **Disjointness.** A designation is refused for anyone with an active (eligible or waiting) enrolment, and an enrolment for anyone with an active designation. Representatives and approvers stay disjoint, so nobody enrols themselves, directly or mutually (O-9).
- **`approver_revocation`** (R17 by an active representative; R18 by an independent security operator) and **`representative_revocation`** (R14 by a platform owner; R15 by an independent security operator): either side of the dual control can withdraw. Each names the revoked entry in the path, records `ticket_ref`, and is refused for an entry already revoked.
- **Invalidation (O-2).** A revocation transaction invalidates, in the same transaction, every outstanding (unconsumed, unexpired, not yet invalidated) approval and execution authorisation made by the affected approvers: the enrolment's subject, or for a designation the subjects of every enrolment it authorised (those enrolments are suspended). Invalidation sets one-way `invalidated_at` and `invalidated_by_platform_audit_id` (the revocation's audit row), trigger-enforced and mutually exclusive with consumption. The use-time eligibility checks remain as a second line.

**Eligibility at use** (`approver_eligibility`, a pure decision over register entries, applied at R8, R9 and execution with the DB clock `t`): an `approver_enrolment` of the user with `eligible_from <= t < valid_until`, not revoked, whose authorising designation is neither revoked nor expired at `t` (F-2, final closure 2026-11-03: a designation's expiry suspends its enrolments immediately, as its revocation does; this reverses the earlier design choice under which an enrolment could outlive an expired designation). Expiry is not an event, so nothing is invalidated when it passes: approvals and authorisations already given by such an approver fail at their next use (R9 or execution), because both re-check the approver's and the authoriser's eligibility at `t`. Plus, read separately, an active operator holding report and not holding `platform.authority:manage`. Approver and authoriser must name different `natural_person_ref`. The registered entry used is recorded in the audit metadata.

**Usable eligibility.** With a 120-day delay and at most 12 months of validity, one enrolment is usable for about 245 days (365 - 120). To keep an approver eligible without a gap, the one permitted renewal must be recorded at least 120 days before the current enrolment ends.

**Times.** The request, approval, authorisation, consume and invalidate times are stamped by the triggers from the wall clock (`clock_timestamp()`), after the caller's locks: a revocation whose transaction began before an approval or authorisation committed still stamps a later `invalidated_at` (found by the review of #203). The register's own times use the transaction time under the register lock.

**Serialisation.** Every register write takes an exclusive transaction-level advisory lock on the register (also taken by the insert trigger, so a direct insert serialises too); R8, R9 and execution take it shared, **before** their tenant locks. A revocation therefore either commits before an approval checks eligibility (and the approval is refused) or waits until the approval commits (and then invalidates it).

**How each requirement is met.**

| # | Requirement | Design |
|---|---|---|
| 1 | The approver is independently verified as a distinct natural person | Outside SaaS OS; the register records only `natural_person_ref`, `verification_ref` and the representative's `authorisation_ref`. **Never personal data** (O-10) |
| 2 | The platform owner cannot enrol a second account of their own | A report grant confers nothing. An enrolment needs an active representative; a representative needs an owner's proposal **and** an independent security operator's confirmation; authority holders cannot be representatives, approvers, confirmers or enrolling representatives. **Met procedurally**: it holds while owner, representative and security operator do not collude (T14) and no platform owner holds a database credential alone (T15) |
| 3 | Enrolment is authorised by a designated representative other than the platform owner | The governing body designates (O-4); recorded as proposal plus confirmation; each enrolment names its designation (`authorised_by_entry_id`) and the representative's signed authorisation (`authorisation_ref`). SaaS OS records the designation; it cannot verify it |
| 4 | Append-only, independently reviewable register | Insert-only for every role (triggers refuse `UPDATE` and `DELETE`); one audit row per entry in the same transaction (ADR-0053 digests); readable and exportable as JSON through R10 (`platform.audit:read`); per-enrolment state through R11 |
| 5 | Nobody approves their own enrolment or eligibility | The trigger and Core refuse a self-enrolment, an enrolment by a non-representative, a confirmation by the proposer or the subject, and keep representatives and approvers disjoint |
| 6 | Checked at use; revocable; expiring | Section above; revocation is immediate and invalidates outstanding approvals and authorisations (O-2); an expired designation suspends its enrolments at once, and only a freshly verified enrolment under a new designation restores eligibility (F-2) |
| 7 | Blank-provenance accounts ineligible until enrolled | Eligibility comes only from the register; `NULL` provenance neither grants nor blocks |
| 8 | Bootstrap and break-glass accounts not automatically eligible | Their report grant gives no entry (O-3); they follow the same enrolment; the bootstrap owner is refused as an authority holder |
| 9 | Residual risks with detection | T8, T14, T15, T16, and both database credentials (section 2) |

**Register DDL (summary; implemented in PR #203 (open, not merged) by migration `c3f9e1a7b5d2`, not part of #198).**

```sql
CREATE TABLE core.permission_grant_ledger_approver_register (
    id                             uuid PRIMARY KEY,
    entry_type                     varchar(40) NOT NULL CHECK (entry_type IN (
        'representative_designation_proposal', 'representative_designation',
        'representative_revocation', 'approver_enrolment', 'approver_revocation')),
    subject_user_id                uuid NOT NULL REFERENCES core.users (id),
    recorded_by_user_id            uuid NOT NULL REFERENCES core.users (id), -- the session's user
    designation_ref                varchar(100) NULL,  -- proposal and designation
    natural_person_ref             varchar(100) NULL,  -- enrolment
    verification_ref               varchar(100) NULL,  -- enrolment
    authorisation_ref              varchar(100) NULL,  -- enrolment
    ticket_ref                     varchar(100) NOT NULL,
    proposal_entry_id              uuid NULL REFERENCES ... (id), -- designation: its proposal
    authorised_by_entry_id         uuid NULL REFERENCES ... (id), -- enrolment: its designation
    revokes_entry_id               uuid NULL REFERENCES ... (id), -- revocation
    renews_entry_id                uuid NULL REFERENCES ... (id), -- enrolment renewal
    valid_until                    timestamptz NULL,   -- proposal, designation, enrolment (<= 12 months)
    eligible_from                  timestamptz NULL,   -- enrolment: forced to recorded_at + 120 days
    proposal_expires_at            timestamptz NULL,   -- proposal: forced to recorded_at + 72 h
    recorded_at                    timestamptz NOT NULL, -- forced to now()
    recorded_by_platform_audit_id  uuid NOT NULL UNIQUE
    -- plus: a CHECK per reference (the opaque pattern), a shape CHECK per entry type,
    -- one confirmation per proposal, one revocation per entry and one renewal per entry
    -- (partial unique indexes).
);
```

- **`BEFORE INSERT` trigger** (not `SECURITY DEFINER`; `SET search_path = pg_catalog`; `check_violation`): takes the register advisory lock; forces `recorded_at`, `eligible_from` and `proposal_expires_at` from `now()`; refuses `valid_until` beyond 12 months or (enrolment) not after `eligible_from`; and enforces the relational rules above (proposal unexpired and unconfirmed; designation copies its proposal and its recorder is neither the proposer nor the subject nor an authority holder; enrolment by the subject of an active designation, never the subject itself, with disjointness, authority and hold-management refusals, the provenance-link refusal, uniqueness by subject and `natural_person_ref` (an enrolment whose designation expired or was revoked no longer counts) and the single renewal of a current entry under a live designation, and the fresh-verification rule of F-2; revocation of an unrevoked entry of the matching kind with the same subject).
- **`BEFORE UPDATE` and `BEFORE DELETE`** refuse everything, for every role. A downgrade refuses while any row exists.
- **Deferred constraint trigger**: the entry's `recorded_by_platform_audit_id` must name a `success` platform audit row of a `user` actor equal to `recorded_by_user_id`, written in the same transaction (at commit). It makes "an entry without its audit row" impossible for the application path; it is not authenticity (T6).
- **RLS**: `tenant_context_exclusion_statements` (ADR-0045 section 9b).
- **Grants**: the runtime role keeps `SELECT` and `INSERT`; `UPDATE` and `DELETE` are revoked.

**Identity lookup (O-5; PR #196, not built here).** The reference lookup of #196 must require `platform.security_retention:report` **and** independent register eligibility (`approver_eligibility` at the DB clock), with no new runtime permission. The bootstrap owner's report permission grants neither eligibility nor lookup (O-3).

**Independent review (O-7).** At least quarterly, and before the gate PR (section 8.6, where the stricter independence of §9.8 applies), a reviewer who is neither a platform owner, nor a representative, nor an approver exports the register (R10), reconciles every entry with its external designation, authorisation and verification records, confirms each entry's audit row is in the ADR-0053 digest chain, and checks every approval and authorisation audit row against the register as it stood then. The 120-day delay guarantees that at least one review cycle passes before an enrolment can be used; that the review happens and catches a forgery is procedural. Findings go to the governing body.

---

## 5. Execution model

### 5.1 Principles

- The runtime role never receives `DELETE` on the ledger. Deletion stays in `expire_permission_grant_ledger_rows` on `migrations_role_session_scope`; no route, job or purge step reaches it.
- The command presents the execution authorisation:

  ```text
  python -m saas_os.ops.permission_grant_ledger_expiry \
      --execution-authorization <id> --reason "TICKET-9: retention expiry" [--apply] [--confirm-production]
  ```

  `--operator`, `--tenant`, `--all-purged`, `--after`, `--confirm-rows` and `--confirm-digest` are refused with it: scope and binding come only from the records. **Without `--apply` it verifies everything below under the locks, writes one audit row (`phase: "verify"`) and deletes nothing.** The existing report form (`--operator` and a scope, no `--apply`) stays. `--apply` without `--execution-authorization` is refused, and `--apply` is refused with `deletion_disabled` while the gate is off.
- The run's caller is `UserCaller(<the authorisation's authorized_by_user_id>)`, read from the database and never typed. Its audit rows state `runner: "migrations_role_unauthenticated"`.

### 5.2 Binding

| Bound value | Fixed at | Checked at |
|---|---|---|
| Scope: sorted, distinct tenant ids, `scope_digest` (SHA-256 of the canonical JSON array) | Request (trigger); copied into the approval (trigger) | R8, R9, execution |
| `eligible_ledger_rows`, `eligible_digest` | Request; equal in the approval | R8 (restated), R9, execution |
| Single use | `consumed_*` on approval and authorisation | execution |
| Not invalidated | `invalidated_*` (revocation) | R9, execution |
| Expiry | `approved_at + 72 h`; authorisation `least(authorized_at + 60 min, approval.expires_at)`; DB clock (triggers) | R9, execution |

### 5.3 The execution transaction

One transaction on the migrations role:

1. Validate the input. With `apply`, refuse `deletion_disabled` before the run connects while `_DELETION_ENABLED` is `False`.
2. Read the authorisation, approval and request without locks (ids only).
3. Take the register advisory lock (shared).
4. **Lock the tenant rows in scope `FOR UPDATE`, in id order** (the lock that hold placement and, after 5.4, hold release take first).
5. Lock the approval row, then the authorisation row, `FOR UPDATE`.
6. Take `t = clock_timestamp()` after the locks. Refuse `*_consumed`, `*_invalidated`, `*_expired` (`t >= expires_at`).
7. Re-authorise the authoriser for `expired_delete` (`not_authorized`) and the approver's report (`approval_no_longer_authorized`); refuse `party_holds_authority_manage` for requester, approver and authoriser; re-check both enrolments at `t` (`approver_not_eligible`, `authorizer_not_eligible`) and `same_natural_person`.
8. Recompute eligibility of exactly the bound scope with `t`: every tenant `ELIGIBLE` with rows; count, digest and scope digest equal (`scope_not_eligible`, `confirmation_mismatch`).
9. Re-check the people: approver ≠ requester; authoriser ≠ approver; neither is an authenticated releaser in scope; no unauthenticated release in scope; provenance links.
10. Without `apply`: write the `verify` audit row and commit. With `apply`: delete per tenant inside `bind_tenant_scope`, by id (a tenant losing other than exactly the counted rows rolls everything back); write the run, tenant and consume audit rows; set `consumed_at = t` and `consumed_by_platform_audit_id` on the approval and the authorisation; commit.

### 5.4 Change to the existing hold release (§9.12, adopted as recommended; implemented in PR #203 (open, not merged))

`release_permission_grant_ledger_hold` locks the hold's tenant row `FOR UPDATE` **before** the hold row, and it requires the session evidence of the authenticated route. A release racing with steps 4 to 10 either commits first (step 9 sees it) or waits until the deletion commits. The lock order is the same everywhere: register (where taken), tenants, request or approval, authorisation.

### 5.5 Approval and authorisation tables (summary; implemented in PR #203 (open, not merged) by migration `c3f9e1a7b5d2`, not part of #198)

```sql
CREATE TABLE core.permission_grant_ledger_deletion_requests (
    id uuid PRIMARY KEY,
    tenant_ids uuid[] NOT NULL,            -- trigger: sorted, distinct, 1..1000, no NULL
    scope_digest char(64) NOT NULL,        -- trigger: equals SHA-256 of the canonical JSON of tenant_ids
    eligible_ledger_rows integer NOT NULL CHECK (eligible_ledger_rows > 0),
    eligible_digest char(64) NOT NULL,
    requested_by_user_id uuid NOT NULL REFERENCES core.users (id),
    requested_at timestamptz NOT NULL,     -- forced to now()
    expires_at timestamptz NOT NULL,       -- forced to now() + 72 h
    requested_by_platform_audit_id uuid NOT NULL UNIQUE);

CREATE TABLE core.permission_grant_ledger_deletion_approvals (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL UNIQUE REFERENCES core.permission_grant_ledger_deletion_requests (id),
    tenant_ids, scope_digest, eligible_ledger_rows, eligible_digest,  -- trigger: equal to the request's
    approved_by_user_id uuid NOT NULL REFERENCES core.users (id),
    approved_at timestamptz NOT NULL,      -- forced to now(); the request must be unexpired
    expires_at timestamptz NOT NULL,       -- forced to now() + 72 h
    approved_by_platform_audit_id uuid NOT NULL UNIQUE,
    consumed_at timestamptz NULL, consumed_by_platform_audit_id uuid NULL UNIQUE,
    invalidated_at timestamptz NULL, invalidated_by_platform_audit_id uuid NULL);
    -- pairing CHECKs; never both consumed and invalidated

CREATE TABLE core.permission_grant_ledger_deletion_execution_authorizations (
    id uuid PRIMARY KEY,
    approval_id uuid NOT NULL REFERENCES core.permission_grant_ledger_deletion_approvals (id),
    authorized_by_user_id uuid NOT NULL REFERENCES core.users (id),
    authorized_at timestamptz NOT NULL,    -- forced to now(); the approval must be live
    expires_at timestamptz NOT NULL,       -- forced to least(now() + 60 min, approval.expires_at)
    authorized_by_platform_audit_id uuid NOT NULL UNIQUE,
    consumed_at timestamptz NULL, consumed_by_platform_audit_id uuid NULL,
    invalidated_at timestamptz NULL, invalidated_by_platform_audit_id uuid NULL);
-- At most one consumed authorisation per approval (partial unique index).
```

**Triggers** (not `SECURITY DEFINER`; `SET search_path = pg_catalog`; `check_violation`): `BEFORE INSERT` forces the times and checks the copies; `BEFORE UPDATE` refuses everything on requests and, on approvals and authorisations, admits only the one-way transition of exactly the consume pair or exactly the invalidate pair from both `NULL`, never both; `BEFORE DELETE` refuses everything. A deferred constraint trigger requires each row's audit row (same actor, same transaction). A downgrade refuses while any row exists.

**RLS**: the exclusion policy on all three tables. **Grants**: the runtime role keeps `SELECT` and `INSERT` on the three tables and `UPDATE (invalidated_at, invalidated_by_platform_audit_id)` on approvals and authorisations (revocation runs on the runtime role); `UPDATE` otherwise and `DELETE` are revoked. Only the migrations role (the owner) consumes, and only the consume transition passes the trigger.

---

## 6. Audit

Every act writes platform audit rows through `record_platform_event_in_transaction`, in the act's own transaction; each state row records the pre-chosen id of its act's audit row. Refusals write one `denied` row (`recording_platform_refusal` / `record_platform_refusal`) after the rollback, best effort, with the code as `reason`. **Metadata holds ids, counts, digests, times, opaque references and fixed labels only**, under 8192 bytes; a scope is recorded as a count and `scope_digest`. Metadata common to every HTTP act: `channel: "platform_http"`, `session_id`, `session_age_seconds`; a replay adds `replay: true`.

| Act | Action (`platform.permission_grant_ledger.*`) | Target | Metadata (beyond the common keys) |
|---|---|---|---|
| Report (R1) | `retention_report` | `permission_grant_ledger` | as today |
| Hold read (R2) | `hold_read_attempt`, `hold_read` | `permission_grant_ledger_hold` | `returned` |
| Hold place / release (R3, R4) | `hold_place`, `hold_release` | the hold | `hold_id`, `reference` |
| Request (R5) | `deletion_request` | the request | `request_id`, `tenants`, `scope_digest`, `eligible_ledger_rows`, `eligible_digest`, `expires_at` |
| Read (R6, R7) | `deletion_read_attempt`, `deletion_read` | the request | `returned` |
| Approve (R8) | `deletion_approve` | the request | `request_id`, `approval_id`, counts and digests, `expires_at`, `approver_entry_id` |
| Authorise (R9) | `deletion_execution_authorize` | the request | `request_id`, `approval_id`, `execution_authorization_id`, `expires_at`, `authorizer_entry_id` |
| Register reads (R10, R11) | `approver_register_read*`, `approver_eligibility_read*` | `permission_grant_ledger_approver_register` | `returned` |
| Register write (R12–R18) | the operation's action | the entry | `entry_id`, `entry_type`, `subject_user_id`, the linked entry ids, the opaque refs, `valid_until`, `eligible_from`; a revocation adds `invalidated_approvals`, `invalidated_execution_authorizations`, `suspended_enrolments` |
| Execution: verify | `expired_delete` | `permission_grant_ledger` | `phase: "verify"`, ids, counts, digests, `runner` |
| Execution: run, tenant, consume | `expired_delete` | as before | `phase` `run` / `tenant` / `consume`, plus `approval_id`, `execution_authorization_id`, `request_id`, `scope_digest`, `runner` |
| Any refusal | the operation's action | as above | `reason` = code |

---

## 7. Failure and recovery model

| Situation | Behaviour | Recovery |
|---|---|---|
| Interrupted API call (timeout, lost response) | The act committed or did not | Retry with the same body: the same caller with identical content gets the existing record (`replay: true`); nothing is duplicated |
| Crash between approval and execution | The approval stays unconsumed until it expires | Authorise again (R9) while valid; afterwards a new request |
| Expired approval or authorisation | R9 or execution refuses | A new request, or a new R9 |
| Revocation of an approver or a designation | The same transaction invalidates every outstanding approval and authorisation of the affected approvers | A new approval by an eligible approver |
| Expiry of a designation (F-2) | Its enrolments are suspended from that instant (DB clock). Nothing is rewritten; an outstanding approval or authorisation by an affected approver is refused at its next use (`approver_not_eligible`, `authorizer_not_eligible`) | A new designation (proposal and confirmation), then a new enrolment with fresh verification, eligible after its own 120 days |
| Concurrent requests or approvals | Tenant locks in id order; `overlapping_request`; `request_id UNIQUE` on approvals (`request_already_approved`) | Wait for expiry or consumption |
| Concurrent revocation and approval | Serialised by the register advisory lock (section 4.5) | None needed |
| Hold placed or released during execution | Serialised by the tenant lock (5.3, 5.4) | Re-request if still needed |
| Partial failure | One transaction: everything rolls back, including the consumption | Re-run with the same unconsumed authorisation |
| Audit write failure | Success rows are in the act's transaction (fail closed); refusal rows best effort, logged | Investigate |
| Clock skew | Only the DB clock (`now()` in triggers, `clock_timestamp()` after locks in execution) | None |
| Replay of a consumed record | Refused; the trigger refuses a second consume even for the migrations role | None |
| Permission or operator status changed | Use-time checks at R9 and execution | A new approval |
| Deadlock or serialization failure | Fixed lock order; otherwise `503` with `Retry-After`, nothing committed | Retry |
| Disabled gate | `--apply` refused `deletion_disabled` before the run connects | An owner-approved change, after review |

---

## 8. Test plan

### 8.1 Unit
- Scope canonicalisation and `scope_digest`; the eligibility decision over register entries (eligible, waiting, expired, revoked, suspended, renewal overlap); the error-code table (every code exactly one status, an unknown code a 500); the command's argument rules; the operation table (52 rows, 28 permissions, the fourteen new rows with `_NONE`); `PLATFORM_ROUTES` (45 routes with permission, operation and freshness).

### 8.2 PostgreSQL integration (disposable database; rows created are removed)
- The full path: report → R5 → R8 → R9 → execution dry run (verify row) → `--apply` refused `deletion_disabled` → with the constant switched in-process: deletion of exactly the bound rows, both records consumed, run, tenant and consume rows.
- Each refusal with its `denied` row; concurrency with real locks, both orderings (hold placement and release against execution; two R8 on one request; revocation against approval); expiry by the DB clock; triggers (times, copies, one-way consume and invalidate, append-only register for both roles); grants; RLS; the migration up, down, up, and the downgrade refused while rows exist; revocation invalidation; the 120-day delay; renewal overlap; bootstrap and break-glass accounts ineligible until enrolled; designation expiry suspending approval, authorisation and execution, a new designation alone not restoring eligibility, and a freshly verified enrolment under it restoring it only after its own delay (F-2); the four provenance-link branches in the register trigger; the hold release's tenant lock taken before the hold row, observed in `pg_locks`.

### 8.3 API (TestClient)
- Identity fields in any body → `422`, the Core function never called (spy); the audit actor is the session's user; route gates.

### 8.4 Negative controls
Each protection removed in isolation (extra-forbid, the person rules, eligibility at R8 and at execution, natural-person distinctness, invalidation, the register append-only and self-enrolment rules, the tenant lock in release, the consume trigger, the same-transaction audit check); the named test fails for the intended reason; the file is restored byte-identically.

### 8.5 Architecture tests
- Every retention request model forbids extra fields and has no identity-named field; no module but the router calls the release, approval, authorisation or register-write functions; no `saas-os-operator` command releases a hold or approves; the migrations-role boundary is unchanged (only `expiry` opens it); `_DELETION_ENABLED` is the literal `False`; 28 permissions.

### 8.6 The gate

**Deletion remains disabled until this mechanism is implemented, independently reviewed and tested.** A *separate* PR, approved by the owner, sets `_DELETION_ENABLED = True` only after: (1) the implementation merged with its tests passing in CI; (2) an independent review (§9.8, F-4) by a natural person different from the implementer, the platform owner, the representative proposer, the representative, every approver and the migrations credential custodian, who inspected the **exact final head** of the gate PR and the relevant security evidence (a review of an earlier commit is insufficient), including a first independent review of the register; (3) the negative controls recorded; (4) the runbook procedure rehearsed once against a disposable database; (5) the deployment enforces dual control of the migrations credential (§9.9, F-5): two separately authorised people, no shared personal accounts, independently authorised and audited credential access and use, no substitution by a declared operator id. If the deployment cannot enforce (5), deletion stays disabled. SaaS OS checks none of (2) or (5); they are procedural and infrastructure conditions recorded with the gate PR.

---

## 9. Decisions

1. **HTTP routes for retention.** *Decided (owner, 2026-11-03): authorised for implementation as a separate PR*, identity from the OIDC session only.
2. **Releases under declared ids.** *Adopted as recommended (option A); implemented in PR #203 (open, not merged); the owner may change it.* An unauthenticated release blocks its tenant.
3. **Command-line hold commands.** *Decided (owner, 2026-11-03):* a command may place an emergency hold; `release-permission-grant-ledger-hold` is removed; a hold is released only through the authenticated route.
4. **Validity windows.** *Adopted as recommended; implemented in PR #203 (open, not merged); the owner may change it:* request 72 h, approval 72 h after approval, execution authorisation 60 min and never past the approval. DB clock.
5. **Number of accounts.** *Adopted as recommended; implemented in PR #203 (open, not merged); the owner may change it:* the authoriser may be the requester; approver and authoriser are always two procedurally verified persons.
6. **Session strength.** *Adopted as recommended; implemented in PR #203 (open, not merged); the owner may change it:* fresh session on R4, R8, R9; R8 and R9 refuse `multi_factor_not_enforced` unless the deployment requires MFA. The same applies to the register writes R12 to R18, which did not exist when the recommendation was written.
7. **Re-checking authority at execution.** *Adopted as recommended; implemented in PR #203 (open, not merged); the owner may change it:* the approver and the authoriser, not the requester (the requester's authority-manage status is re-checked).
8. **Independent review before the gate PR.** *Decided (owner, 2026-11-03, final closure, F-4):* the reviewer is a natural person different from the implementer, the platform owner, the representative proposer, the representative, every approver and the migrations credential custodian, and inspects the exact final head of the gate PR and the relevant security evidence; a review of an earlier commit is insufficient. Procedural: SaaS OS records nothing that proves it.
9. **Two-person database credential.** *Decided (owner, 2026-11-03, final closure, F-5):* the migrations credential (`MIGRATIONS_DATABASE_URL`) is under dual control: two separately authorised people; no shared personal accounts; credential access independently authorised; credential access and use audited; no substitution by a declared operator id. If the deployment environment cannot enforce dual control, deletion stays disabled. This is infrastructure and procedure: SaaS OS cannot enforce or verify it and adds nothing that pretends to. Dual control of `DATABASE_URL`, which can write the register (T6), remains recommended practice.
10. **Request scope.** *Adopted as recommended; implemented in PR #203 (open, not merged); the owner may change it:* every tenant eligible with rows.
11. **Timing.** *Decided (owner, 2026-11-03):* implement now; the gate stays off.
12. **Release locking (5.4).** *Adopted as recommended; implemented in PR #203 (open, not merged); the owner may change it.*
13. **One person with several accounts (T4a).** *Decided: option A (2026-11-02), detailed on 2026-11-03:*
    - 13a. Validity: designations and enrolments at most 12 months; one overlapping renewal (O-1, O-8).
    - 13b. Revoking a designation suspends its enrolments; every revocation invalidates outstanding approvals and authorisations (O-2).
    - 13c. The bootstrap report permission stays and grants neither eligibility nor identity lookup (O-3).
    - 13d. The governing body designates the representative; the register holds references only (O-4, O-10).
    - 13e. Register read: `platform.audit:read` (R10, R11). *A design choice, adopted; implemented in PR #203 (open, not merged); the owner may change it.*
    - 13f. Register write path: *superseded (O-6):* authenticated API writes; the migrations-role procedure is withdrawn.
    - 13g. Independent review: quarterly (O-7), by someone who is neither a platform owner, nor a representative, nor an approver.
    - 13h. Eligibility delay: 120 days (O-8).
    - 13i. Two-party designation: *accepted by the owner (F-1, final closure 2026-11-03)*.
    - 13j. Designation expiry suspends its approvers immediately; a new designation does not revive them; fresh verification and re-enrolment, with its own 120-day delay, are required (F-2, final closure 2026-11-03; reverses the earlier design choice).
