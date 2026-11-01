# Architecture decision brief: permission upgrades, system actor, versioning

**Status: decision brief, 2026-11-01. Decides nothing.** Prepared on `main` `6fd2dfd` (v0.6.0 is `d980e73`). It lays out the open choices in two proposed ADRs and a proposed versioning policy, with a recommendation for each, so the owner can decide them. It does not change the ADRs themselves.

**Where the ADRs are.** The two ADRs discussed in sections 2 and 3 are proposed in pull request #187 (head `b095b4f`, not merged), as numbers 0060 and 0061; this brief quotes them from that head and refers to them as "ADR 0060" and "ADR 0061" because they do not yet exist on `main`. The versioning policy of section 4 is ADR-0062, proposed by the same pull request as this brief. Nothing here modifies pull request #187.

**Owner direction already given (2026-11-01)**, which this brief applies and does not reopen:

- ADR 0060: append-only permission-grant migrations are the preferred direction; no automatic privilege escalation; tenant-admin decisions never overwritten; deny grants never changed; idempotent; permission change and audit atomic; tenant isolation kept; no generic system-permission workaround.
- ADR 0061: a `SystemActor` records who or what acted and grants no authorization; actor identity and caller authorization stay distinct.
- `PROVISIONING` is narrowed in phases: implement ADR 0060, inventory uses, migrate tenants, move consumers by separately approved pin changes, then narrow, with regression tests against cross-tenant escalation.
- Embeddings are deferred.

## 1. Summary of recommendations

| Decision | Recommendation | Confidence |
|---|---|---|
| ADR 0060 Q1 (option) | **Option C** | High: the only option that satisfies "never overwrite tenant-admin decisions" on a re-run |
| ADR 0060 Q2 (operator identity) | **Require a named operator holding a new platform permission** for the operator command | Medium: a policy choice; evidence below |
| ADR 0060 Q3 (`SUSPENDED` tenants) | **Allow** grants on `SUSPENDED` tenants | High: a suspended tenant authorizes nothing, and excluding it strands the tenant on reactivation |
| ADR 0060 Q4 (narrowing schedule) | **Cannot be dated yet**; recommend a rule instead of a date | Needs evidence (section 5) |
| ADR 0061 Q1 (option) | **Option B** | High |
| ADR 0061 Q2 (kind list) | **Closed list owned by Core; products choose `name` only** | High |
| ADR 0061 Q3 (`record()` timetable) | **Cannot be dated yet**; recommend an inventory first | Needs evidence (section 5) |
| Versioning and support (ADR-0062) | **Accept after one decision**: how a fix reaches the previous minor (section 4.3) | A conflict with ADR-0015's release rules must be resolved first |

## 2. ADR 0060: permission grant migrations for existing tenants

### 2.1 The alternatives (exact headings)

| Option | ADR heading |
|---|---|
| A | "document `PROVISIONING` as the supported path" |
| B | "a narrow system purpose and one additive Core function" |
| C | "declared, append-only permission grant migrations (B plus a ledger)" |
| D | "implicit upgrade (grant a new permission to every role that holds a related one)" |

### 2.2 The unresolved questions (verbatim)

- Q1. "Option C (recommended) or Option B (smaller, issue #88 as written)?"
- Q2. "Must the operator command name an operator who holds a platform permission (a new `platform.permission_grant:apply` in ADR-0045's closed vocabulary, with a platform audit row), or is the deployment's own identity enough, as for Alembic migrations?"
- Q3. "May a migration add a permission to a role in a `SUSPENDED` tenant (open, but frozen), or only in `ACTIVE` and `PENDING` ones?"
- Q4. "Schedule for narrowing `PROVISIONING` after this ships (rule 8)."

### 2.3 Security and migration consequences

| Option | Security | Migration and data | Fits the owner's direction? |
|---|---|---|---|
| A | Keeps ambient tenant-administrator authority (`PROVISIONING` can create roles, grant any permission, add memberships and assign roles on any open tenant; `saas_os/core/rbac/service.py`, `saas_os/core/authority/caller.py`) as the documented path; a mistake grants anything to anyone | None | **No**: it is the "generic system permission workaround" the direction excludes |
| B | Narrow purpose: one registered, non-authority permission to one existing role; cannot create or assign roles. But a re-run re-grants a permission a tenant administrator revoked after the first run | None (no table) | **Partly**: violates "never overwrite tenant-admin decisions" on a re-run |
| C | B's narrowness, plus a per-tenant ledger so a migration applies once and a later revocation stands; per-grant same-transaction audit | One additive migration: a tenant-owned table under the canonical RLS policy, in the isolation registry and retention classification; downgrade drops only the ledger (grants stay) | **Yes** |
| D | Privilege escalation by inference | None | **No**: "no automatic privilege escalation" |

Option C's migration is not authorized by this brief; it needs its own approval.

### 2.4 Compatibility for existing consumers

- None of the options changes an existing public function. B and C add a function, a `SystemAuthority` value and (C) a declaration type; the public-surface snapshot (`tests/architecture/public_api_snapshot.txt`) changes additively.
- A consumer that today uses `PROVISIONING` on existing tenants keeps working until the separately scheduled narrowing (Q4). The first consumer's `crm_app.role_upgrade` is such a use.
- Under C, the first run on an existing installation records, per tenant, the migrations it applies; a consumer that already granted the permission by its workaround gets `already_present`, not a duplicate.

### 2.5 Recommendations

- **Q1: Option C.** It is the only option that meets every principle the owner set, and its cost (one tenant-owned table) is the price of "never overwrite tenant-admin decisions": without a record of what was applied, a re-run cannot tell "never granted" from "revoked on purpose".
- **Q2: a named operator with a new platform permission.** A run with `--all-tenants` changes authority in every tenant of an installation, which is installation-scoped authority in ADR-0045's sense. The existing operator command that changes state across tenants for maintenance, `replay-outbox-events`, names an operator who must hold `platform.outbox:replay` and writes a platform audit row (ADR-0050 and the outbox replay brief). Alembic is not a precedent for authority: it changes schema, not who may do what. Cost: an ADR-0045 amendment to its closed vocabulary, and a deployment pipeline needs an enrolled operator identity to run the command.
- **Q3: allow `SUSPENDED`.** A membership or role held at a suspended tenant "authorizes nothing" (`saas_os/core/rbac/authorization.py`, the tenant-accessibility check under the share lock), so a grant there confers nothing while the tenant is suspended. Excluding suspended tenants would leave them without the permission on reactivation, and no member could grant it then (the anti-amplification rule: nobody holds a new permission). `require_open_tenant()` already treats `SUSPENDED` as open.
- **Q4: see section 5.**

## 3. ADR 0061: system actor attribution in the audit trail

### 3.1 The alternatives (exact headings)

| Option | ADR heading |
|---|---|
| A | "new `SystemAuthority` values per actor kind (`WORKER`, `WEBHOOK`, ...)" |
| B | "an attribution-only `SystemActor`, recorded in validated metadata" |
| C | "Option B with dedicated nullable columns" |

### 3.2 The unresolved questions (verbatim)

- Q1. "Option B (recommended) or C?"
- Q2. "Is the closed `kind` list right, and may products extend it (recommendation: no; products choose `name`, Core owns `kind`)?"
- Q3. "Timetable for refusing purpose-less successful system rows through `record()` (rule 5)."

### 3.3 Security and migration consequences

| Option | Security | Migration and data | Fits the owner's direction? |
|---|---|---|---|
| A | Each actor kind becomes a purpose some operation accepts: attribution turns into authority | None | **No**: "SystemActor must not grant additional authorization" |
| B | Attribution only; `SystemActor` is not a `Caller`, so no Core mutation accepts it | None; the audit digest format (ADR-0053) is unchanged because metadata is already digested | **Yes** |
| C | As B | A migration on an append-only audit table, and a new digest-format version with its verifier | **Yes**, at higher cost |

### 3.4 Compatibility for existing consumers

- B and C are additive. Existing rows keep their meaning; existing `record()` calls keep working until the separately scheduled refusal (Q3).
- C changes the digest format, so a deployment's external verification (`python -m saas_os.ops.audit_digest verify`) and stored digests would need to handle two formats.

### 3.5 Recommendations

- **Q1: Option B.** Both B and C meet the principles; B does it with no migration and no digest-format change. C can follow if querying by actor becomes a need, at the cost the ADR records.
- **Q2: closed list, owned by Core.** A product-extensible `kind` would let attribution vocabulary drift per product and invite kinds that read like authorities; products already choose `name`, which carries their specifics.
- **Q3: see section 5.**

## 4. Versioning and support policy (ADR-0062, proposed)

The owner's policy is written up as ADR-0062 (Proposed). Its relation to ADR-0015:

### 4.1 Consistent with ADR-0015

- Before 1.0, ADR-0015's release-labels amendment stays authoritative: `0.Y.0` for "a migration, a removed or changed public signature, or a new required deployment step"; `0.Y.Z` "for fixes and documentation only". ADR-0062 keeps that, so a security fix that needs a migration is a `0.Y.0` release before 1.0, not a patch.
- Pins stay exact SHAs (ADR-0015 rule 8); tags are labels and never move; no consumer updates automatically.

### 4.2 What ADR-0062 adds

ADR-0015 leaves the support window open twice ("No support window is promised for earlier releases (still open, as above)"; "Not decided here. ... a support window"). ADR-0062 decides it: the newest minor fully supported, the previous minor at least 90 days of security and critical bug fixes, older best-effort, separate assessment of high-impact issues for older versions. That decides an open item; it reverses nothing.

### 4.3 Conflict that must be decided first

Supporting the previous minor means releasing `0.(Y-1).Z` after `0.Y.0` exists. ADR-0015's accepted release process cannot do that today:

- a release tag must be on "a first-parent commit of `main`", and `scripts/release.py` validates "the release pull request's merge commit, the previous release and its full SHA in the changelog" against the linear release history on `main` (ADR-0015 amendment of 2026-10-20);
- one pull request per release, merged into `main` (amendment of 2026-10-19).

A back-ported `0.6.1` built from `v0.6.0` would not be a first-parent commit of `main`, and its previous release would not be the newest changelog entry. ADR-0062 lists two options; one must be chosen before it is accepted:

- **Option 1: maintenance branches** (`release/0.Y`), protected like `main`, with the same CI and an extension of `scripts/release.py` and its tests to validate a tag on a maintenance branch. Keeps the 90-day promise; more process and code.
- **Option 2: fix forward only** (users of the previous minor get the fix in the newest minor, with an upgrade note). No change to the release tooling; does not meet "the previous minor release receives at least 90 days of security and critical bug-fix support" as written.

Recommendation: Option 1, built only when the first back-port is actually needed, with the policy accepted now so consumers can plan.

## 5. Decisions that cannot be recommended without more evidence

| Decision | Evidence needed | How to get it |
|---|---|---|
| ADR 0060 Q4: when to refuse `PROVISIONING` on tenants that are not `PENDING` | Which consumers call `PROVISIONING` on existing tenants, from which code, and on which pinned SaaS OS versions | The inventory step of the owner's phased direction: a search of each consumer repository, plus a deprecation warning (naming the calling module) in the release that ships ADR 0060, observed for one release cycle. Recommended rule: refuse no earlier than the first minor after every known consumer's pin includes ADR 0060 and the consumer has moved off `PROVISIONING` |
| ADR 0061 Q3: when `record()` refuses successful `system` rows | Every Core and control-plane call site that writes a successful `system` row through `record()`; on `main` `6fd2dfd`, `ActorType.SYSTEM` appears at about twenty sites outside the audit module itself (`saas_os/core/billing/`, `saas_os/core/tenancy/`, `saas_os/api/tenant_bootstrap.py`, `saas_os/core/api_keys/`, the control plane), not all through `record()` | Classify each site (a denial keeps `record()`; a success moves to the ADR 0061 function) before choosing a release. Recommended rule: warn in the release that ships ADR 0061; refuse once Core itself has no remaining success-through-`record()` site |
| ADR-0062 section 4.3 | Whether the owner will operate maintenance branches | Owner decision |

## 6. Not covered here

- Embeddings: deferred by owner decision; no ADR change proposed.
- The raw-SQL and RLS question (finding F6): assessed separately in `docs/architecture/RAW-SQL-RLS-THREAT-MODEL.md`.
- Implementation of either ADR: not authorized.
