"""`control_plane.self_learning` -- Self-Learning / Continuous Improvement
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.1, 9.2, 9.3; docs/AI-CONTROL-PLANE.md
section 12).

**Phase 9.1** (`__init__.py`'s `SELF_LEARNING_MARKER`/`SCHEMA_NAME`)
established package/schema ownership and conceptual documentation only.
**Phase 9.2** (`models.py`, `service.py`) added the Learning Authorization
gate (ADR-0014, Accepted). **Phase 9.3** (`evaluation/*`) adds the
Evaluation Foundation -- baseline-vs-candidate comparison against a
shared benchmark, consuming an already-ALLOW Learning Authorization
decision per subject. Still no candidate generation, no L1/L2/L3 runtime
behavior, and no database table/migration/model (see "Non-goals" below):
`SCHEMA_NAME` remains a plain string constant, not a mapped ORM schema,
exactly as Phase 9.1 left it.

**Layer**: AI Control Plane, never SaaS Core (docs/ARCHITECTURE.md
sections 1-2). Self-Learning observes and adapts the behavior of AI
Control Plane agents/tools (prompts, routing, tool selection,
retrieval/response strategy) and has no meaning independent of that
layer -- the same reasoning that places `control_plane.approvals` here
rather than in `core`. SaaS Core, Infrastructure, and every Product must
continue to function correctly with the AI Control Plane and
Self-Learning both disabled; `core` must never acquire a dependency on
this package (enforced by the existing "core MUST NOT import
`control_plane`" import-linter contract, docs/IMPLEMENTATION-ROADMAP.md
Phase 1.3 -- unchanged by this phase).

**Schema/table-prefix ownership**: per docs/DATA-ARCHITECTURE.md section 1
("each layer/module owns a distinct namespace... schema-per-owner"),
`control_plane.self_learning` reserves its own schema, `SCHEMA_NAME`
below -- distinct from `core.*` (docs/SECURITY.md section 8's
`core.audit_log`) and distinct from `control_plane`'s own schema
(`control_plane.approvals`'s `approval_requests` table,
docs/IMPLEMENTATION-ROADMAP.md Phase 7.2). This is a naming reservation
only; no table is created against it in this phase.

**Learning Ledger (conceptual only, not implemented)**: the future
lineage record --

    Observation -> Learning Event -> Hypothesis -> Experiment ->
    Evaluation -> Candidate -> Approval -> Deployment -> Outcome ->
    Rollback/Promotion

-- is a distinct concept from `core.audit_log` and must never replace or
weaken it (docs/AI-CONTROL-PLANE.md section 12, "not a second
`core-audit-log`"). `core.audit_log` remains the platform's one
append-only security/audit trail; every learning-related privileged
action will, once any such action exists, *additionally* be recorded
through `core.audit_log`'s existing interface, the same way
`core.api_keys` and `core.feature_flags` already do -- never via a
parallel audit mechanism. Illustrative future record fields (conceptual
only; the eventual implementation derives its exact schema from the
architecture at that time, not from this list): `learning_event_id`,
`tenant_scope`, `source`, `purpose`, `data_policy`, `input_reference`,
`hypothesis`, `candidate_change`, `evaluation_result`, `baseline_version`,
`candidate_version`, `risk_level`, `approval_state`, `deployment_state`,
`deployment_version`, `rollback_reference`, `created_at`, `updated_at`.
The lineage record reserves an explicit `tenant_scope` field from this
phase onward so no later phase can retrofit tenant scoping onto an
already-shipped tenant-less schema.

**Learning Authorization (ADR-0014, Accepted; Phase 9.2)**: a third,
independent authorization gate distinct from Tool Authorization
(ADR-0004, `control_plane.orchestration`) and Data Authorization
(ADR-0013, `control_plane.data_authorization`) -- "can data already
cleared for one external-provider call also be retained or reused to
shape future behavior?" Default is **DENY**, implemented in
`service.evaluate_learning_authorization()`: every non-ALLOW branch
returns a specific `LearningDenialReason`; the one ALLOW path is reached
only after (1) an already-ALLOW `DataAuthorizationDecision` for the same
tenant, (2) cross-tenant reuse being either not requested or covered by
an exactly-matching `CrossTenantLearningPolicy`, and (3) an explicit
`TenantLearningPolicy` permitting the request's purpose, model/provider,
and retention. `request.evidence` (a `LearningEvidence`) is accepted but
never read by any decision branch -- the literal code-level enforcement
of "external input is evidence, not trusted policy." No policy object is
persisted (no table, no migration -- callers supply
`TenantLearningPolicy`/`CrossTenantLearningPolicy` explicitly, mirroring
`control_plane.data_authorization`'s own no-persistence discipline).
`authorize_learning_use()` wraps the pure evaluator with exactly one
`core.audit_log` entry per decision (`learning.data_access_approved` /
`learning.data_access_denied`) -- this package has no path that mutates
`core.rbac`, `infra.secrets`, or any autonomy-tier policy (ADR-0014
Decision, "Learning Authorization does not grant policy authority").

**Three learning levels** (docs/AI-CONTROL-PLANE.md section 12) -- none
implemented in this phase:

- Level 1, Adaptive Learning -- versioned, reversible adaptations
  (prompts, routing, tool selection, retrieval/response strategy).
- Level 2, System Learning -- discovers recurring problems and produces a
  structured improvement *proposal*; never applies it automatically.
- Level 3, Autonomous Improvement -- bounded autonomous improvement
  behind a full evaluation/policy-gate/canary/rollback pipeline; tier 3
  (fully autonomous, no standing checkpoint) remains not enabled for
  anything, including this.

**Non-goals (through Phase 9.3)**: no database migration, no table, no
model, no Learning Ledger runtime implementation (still conceptual only),
no candidate generation, no L1/L2/L3 runtime behavior (9.4-9.5, 9.8), no
experimentation (9.6), no autonomy/policy-gate promotion (9.7), no
autonomous deployment, no new tool registered in
`control_plane.orchestration` or `control_plane.tools`, no HTTP route, no
external AI/LLM provider call, no autonomy-tier promotion.

**Unlocks**: docs/IMPLEMENTATION-ROADMAP.md Phase 9.4 (Level 1 -- Adaptive
Learning) and, indirectly, every later Phase 9 phase (all require the
Evaluation Foundation, per Phase 9.3's own "Unlocks").
"""

from control_plane import CONTROL_PLANE_MARKER
from control_plane.self_learning.models import (
    VALID_EVIDENCE_TYPES,
    CrossTenantLearningPolicy,
    EvidenceType,
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
    LearningAuthorizationRequest,
    LearningDenialReason,
    LearningEvidence,
    TenantLearningPolicy,
)
from control_plane.self_learning.service import (
    authorize_learning_use,
    evaluate_learning_authorization,
)

SELF_LEARNING_MARKER = "self_learning"

# Reserved schema/table-prefix for this module's future Learning Ledger
# tables (docs/DATA-ARCHITECTURE.md section 1). Deliberately distinct from
# `core.*` and from `control_plane`'s own schema (used today by
# `control_plane.approvals`). No table is created against this schema in
# this phase -- see module docstring, "Non-goals".
SCHEMA_NAME = "self_learning"

__all__ = [
    "CONTROL_PLANE_MARKER",
    "SELF_LEARNING_MARKER",
    "SCHEMA_NAME",
    "EvidenceType",
    "VALID_EVIDENCE_TYPES",
    "LearningAuthorizationOutcome",
    "LearningDenialReason",
    "LearningEvidence",
    "TenantLearningPolicy",
    "CrossTenantLearningPolicy",
    "LearningAuthorizationRequest",
    "LearningAuthorizationDecision",
    "evaluate_learning_authorization",
    "authorize_learning_use",
]
