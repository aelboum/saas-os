"""L3 Autonomous Improvement: create -> start -> monitor -> promote OR
roll back (docs/IMPLEMENTATION-ROADMAP.md Phase 9.8).

**This module never re-implements an upstream gate -- it composes with
five, in a fixed order, none of which implies the next**:

1. `Experiment` (Phase 9.6) must be `COMPLETED` with a `PASS`
   `evaluation_outcome` -- a `REGRESSION`/`FAIL`/`INVALID` experiment (or
   one never completed) refuses canary creation entirely
   (`ExperimentNotEvaluatedForCanaryError`). This is the literal,
   non-vacuous enforcement of this phase's own Tests bullet: "a
   deliberately-failed regression suite is proven to block promotion."
2. `Adaptation` (Phase 9.4) must still be `CANDIDATE` with a `PASS`
   `evaluation_outcome`, and must be the *exact* row
   `Experiment.candidate_source_id` names
   (`AdaptationNotCandidateForCanaryError` /
   `InvalidCanaryCandidateError`).
3. `PolicyGateDecision` (Phase 9.7) must be an `ALLOW` for the canary's
   own tenant, for `RequestedAction.ACTIVATE_ADAPTATION`, at exactly
   `requested_autonomy_tier == 2` -- never 0, 1, or 3
   (`UnauthorizedCanaryPolicyDecisionError`). Phase 9.8's own Non-Goal,
   verbatim: "canary + monitoring + promote/rollback is tier 2 at most";
   tier 3 is refused here redundantly -- `evaluate_policy_gate()` itself
   (Phase 9.7) already refuses it unconditionally, so a real
   `PolicyGateDecision` can never actually carry `outcome=ALLOW` and
   `requested_autonomy_tier=3` together, but this module does not trust
   that invariant blindly against a hand-built/forged decision object.
4. Learning Authorization (ADR-0014) and Data Authorization (ADR-0013)
   were already required, independently, to reach a `PASS`ed
   `Experiment` in the first place (Phase 9.6's own Data-Authorization
   Requirement) -- this module never re-derives either.
5. Tenant identity is checked at every step against the *same* value:
   `tenant_id == experiment.tenant_id == adaptation.tenant_id ==
   policy_gate_decision.tenant_id`. There is no code path in this module
   that ever activates or rolls back an `Adaptation` belonging to a
   tenant other than the one that produced the `Experiment`/`Adaptation`
   themselves -- see `models.py`'s own docstring for why no
   platform-wide/multi-tenant canary path exists at all.

**The canary *is* the activation, monitored**: `Adaptation` has no
built-in partial-traffic/percentage mechanism (Phase 9.4 never built
one) -- "a scoped, monitored, reversible partial rollout" (Phase 9.8's
own Scope) is realized as exactly one tenant's `Adaptation` row being
activated by `start_canary()` (which calls
`control_plane.self_learning.adaptive.service.activate_adaptation()`
directly), monitored via `record_canary_observation()`, and either
confirmed (`promote_canary()`, a bookkeeping/audit transition -- the
adaptation is already active) or reverted
(`rollback_canary()`/an automatic trigger from
`record_canary_observation()`, which calls
`adaptive.service.rollback_adaptation()`).

**Why calling `activate_adaptation()`/`rollback_adaptation()` directly
here does not bypass Phase 9.4's own tier-1 approvals discipline**:
`adaptive/service.py`'s own docstring describes those two functions as
"only reachable through `control_plane.approvals`' propose -> approve ->
execute workflow ... never invoked directly by an agent" -- true for
*that* call path, which remains the only sanctioned tier-1 route. Tier 2
("auto-execute + audit," `docs/AI-CONTROL-PLANE.md` section 5) is, by
definition, a *different*, independently-authorized route to the same
underlying, tier-agnostic domain functions: `create_canary()` requires a
real, already-evaluated `PolicyGateDecision.outcome == ALLOW` at
`requested_autonomy_tier == 2` before this module ever calls either
function -- the Policy Gate is the standing checkpoint tier 2 requires in
place of a human approval, not an absence of one.

**CP-03 (Phase J audit, remediation 2) -- create-time authorization is not
enough, and re-checking the ORIGINAL decision's own provenance is not
enough either**: `create_canary()`'s `PolicyGateDecision` check runs
exactly once, before the `Canary` row (status `CONFIGURED`) is ever
persisted. An arbitrary amount of real time -- and, in principle, an
arbitrary change to the tenant's own Learning Authorization -- can pass
before `start_canary()` or `rollback_canary()`/`_rollback()` is actually
called. Remediation 1 re-ran `verify_policy_gate_provenance()` against
the *original* `policy_gate_decision_id` at execution time; a Phase-J
experiment proved this only re-confirms the old decision's audit record
still exists (authenticity), never that a *fresh* evaluation, right now,
would still say ALLOW -- an already-audited ALLOW is permanent and never
expires by construction (`verify_policy_gate_provenance()`'s own
documented scope: "no replay prevention, expiry, or single-use
semantics"), so a tenant whose Learning Authorization has since been
revoked could still have its stale canary activated.

Remediation 2 replaces that check with `_require_fresh_canary_authorization()`,
which calls `policy_gate.service.evaluate_and_record_policy_gate_decision()`
-- the exact same pure evaluator `create_canary()` itself relies on --
*again*, right now, producing a genuinely new `PolicyGateDecision` (a new
`decision_id`, a new `core.audit_log` row) rather than re-checking an old
one. Every input to that fresh request is either an immutable domain fact
already persisted on `Canary`/`Adaptation` and re-read from the database
at call time (`tenant_id`, `Adaptation.lineage_key`, `Adaptation
.evaluation_outcome` -- never mutated once `record_adaptation_evaluation()`
first sets it -- `Canary.baseline_version`/`candidate_version`), a fixed
structural constant `create_canary()` itself already required before this
canary could ever exist (`RequestedAction.ACTIVATE_ADAPTATION`,
`AutonomyTier.TIER_2_AUTO_EXECUTE_AUDITED`, the tier-2-eligible-action set,
a fixed reference to this platform's own Phase 9.8 design doc whose
*content* `evaluate_policy_gate()` never inspects, only its presence), or
`learning_authorization_decision` -- the one genuine "authorization state"
input, which `self_learning` maintains no ambient/persisted table for by
design (ADR-0014: "Learning Authorization does not grant policy
authority", ADR-0014's Option C explicitly rejected folding this into
`core.rbac`) and therefore *must* come from the caller re-running
`authorize_learning_use()` against today's policy, exactly as every other
production entrypoint in this package
(`propose_adaptation()`/`create_experiment()`/`create_canary()`) already
requires. `start_canary()`/`rollback_canary()`/`record_canary_observation()`
each now take this one caller-supplied parameter -- never a caller-supplied
verdict (there is still no `authorized`/`approved`/`safe` field anywhere;
the caller supplies the same typed, independently-auditable decision
object every other entrypoint already requires, and
`evaluate_and_record_policy_gate_decision()` still requires
`verify_learning_authorization_provenance()` to confirm it was genuinely
produced, CP-02, on top of evaluating it fresh, CP-03). This still never
imports `core.rbac`.

Rollback deliberately reuses the *same* `ACTIVATE_ADAPTATION` tier-2
action a canary was created under, never a second policy action -- this
module's own Non-Goal already treats "canary + monitoring +
promote/rollback" as one authorized capability (see above); a distinct
rollback-specific `RequestedAction` is unsupported by the Policy Gate's
current vocabulary and out of this fix's scope. The residual consequence
-- rollback (a safety/risk-reduction action) can now be blocked by a
Learning Authorization that denies for reasons unrelated to safety -- is a
real tension inherited from that same architectural choice, not
introduced here; see this module's own test suite for the case this
produces (a `RUNNING` canary that cannot roll back because current
Learning Authorization denies) and the CP-03 remediation report for why
it was not resolved by inventing a second policy action.

Actor identity: the fresh evaluation's `actor_user_id` is always the
actor *causing this mutation now* (`started_by_user_id`/
`rolled_back_by_user_id`/`recorded_by_user_id`), never
`Canary.created_by_user_id` -- the security question is "who is
authorized to cause this mutation now," not "was the original creator
once authorized." `record_canary_observation()`'s automatic-rollback
trigger carries no separate machine-principal type -- it reuses this
package's own existing convention (`core.audit_log`'s own docstring:
`ActorType.USER` covers "a `core.identity.User` row -- human or an AI
agent") via whatever `core.identity.User` the calling job/monitor already
attributes its own actions to, passed through as `recorded_by_user_id`
exactly as before.

**Residual TOCTOU window**: the fresh evaluation and the
`activate_adaptation()`/`rollback_adaptation()` mutation it gates are two
separate calls/transactions (`_require_fresh_canary_authorization()`
opens and closes its own `tenant_session_scope()` read, then
`activate_adaptation()`/`rollback_adaptation()` opens its own separate
write transaction) -- there is no single atomic "check-and-mutate"
transaction, and the existing Policy Gate architecture provides no
locking primitive for this. A Learning Authorization revocation landing
in the narrow window between the fresh ALLOW and the mutation actually
committing would not be caught by this call. This mirrors every other
check-then-act gate already in this codebase (e.g. `_execute_tool()`'s
own RBAC check before its handler runs) and is not a new or wider gap
than those already accepted elsewhere; closing it fully would require
redesigning transaction boundaries across `self_learning`/`adaptive`,
which is out of this fix's scope.

**Monitoring reuses Phase 9.3's typed metric vocabulary, never a second
one**: `_violated_metrics()` checks an `EvaluationMetrics` snapshot
against a canary's own `EvaluationRules` thresholds' *absolute* bars only
(`minimum_absolute`/`maximum_absolute`) -- there is no live baseline
during canary monitoring to regress against, so `maximum_regression` is
never evaluated here; a `None` metric value is never treated as passing
or failing any threshold that names it, mirroring
`control_plane.self_learning.evaluation.service.evaluate_candidate()`'s
own "a metric missing ... is never silently skipped or treated as
passing" discipline.

Every one of this phase's own new pipeline-stage audit events
(`learning.canary_created` / `.started` / `.observation_recorded` /
`.succeeded` / `.promoted` / `.rolled_back` / `.rollback_failed` /
`.cancelled`) is written through `core.audit_log`'s existing interface --
this module has no second audit mechanism. Every upstream stage
(learning authorization, evaluation, experiment lifecycle, policy-gate
decision, and `activate_adaptation()`/`rollback_adaptation()`'s own
`learning.adaptation_activated`/`.rolled_back` events) is *already*
audited by its own owning module -- Phase 9.8 never re-audits another
phase's own stage, only its own.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from control_plane.self_learning.adaptive.errors import (
    AdaptationNotActiveError,
    NoPreviousVersionError,
)
from control_plane.self_learning.adaptive.models import Adaptation, AdaptationStatus
from control_plane.self_learning.adaptive.service import activate_adaptation, rollback_adaptation
from control_plane.self_learning.autonomous_improvement.errors import (
    AdaptationNotCandidateForCanaryError,
    CanaryAlreadyTerminalError,
    CanaryAuthorizationDeniedError,
    CanaryNotConfiguredError,
    CanaryNotFoundError,
    CanaryNotRunningError,
    CanaryNotSucceededError,
    CanaryRollbackFailedError,
    ExperimentNotEvaluatedForCanaryError,
    InvalidCanaryCandidateError,
    UnauthorizedCanaryPolicyDecisionError,
)
from control_plane.self_learning.autonomous_improvement.models import (
    TERMINAL_CANARY_STATUSES,
    Canary,
    CanaryStatus,
)
from control_plane.self_learning.evaluation.models import (
    EvaluationComparison,
    EvaluationMetrics,
    EvaluationOutcome,
    EvaluationRules,
    MetricDirection,
    MetricThreshold,
)
from control_plane.self_learning.experiments.models import Experiment, ExperimentCandidateSourceKind
from control_plane.self_learning.models import LearningAuthorizationDecision
from control_plane.self_learning.policy_gate.models import (
    AutonomyTier,
    PolicyGateDecision,
    PolicyGateOutcome,
    PolicyGateRequest,
    PolicyGateScope,
    RequestedAction,
    Tier2PromotionEvidence,
)
from control_plane.self_learning.policy_gate.service import (
    evaluate_and_record_policy_gate_decision,
    verify_policy_gate_provenance,
)
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from infra.db import tenant_session_scope

_AUDIT_RESOURCE_TYPE = "self_learning_canary"


def _audit(
    *,
    tenant_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    action: str,
    canary_id: uuid.UUID,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    metadata: dict[str, object],
) -> None:
    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(canary_id),
        outcome=outcome,
        metadata=metadata,
    )


def _serialize_rules(rules: EvaluationRules) -> dict:
    return {
        "thresholds": [
            {
                "metric_name": t.metric_name,
                "direction": t.direction.value,
                "minimum_absolute": t.minimum_absolute,
                "maximum_absolute": t.maximum_absolute,
                "maximum_regression": t.maximum_regression,
            }
            for t in rules.thresholds
        ]
    }


def _deserialize_rules(data: dict) -> EvaluationRules:
    return EvaluationRules(
        thresholds=tuple(
            MetricThreshold(
                metric_name=t["metric_name"],
                direction=MetricDirection(t["direction"]),
                minimum_absolute=t["minimum_absolute"],
                maximum_absolute=t["maximum_absolute"],
                maximum_regression=t["maximum_regression"],
            )
            for t in data["thresholds"]
        )
    )


def _violated_metrics(metrics: EvaluationMetrics, rules: EvaluationRules) -> tuple[str, ...]:
    """Absolute-bar violations only -- see module docstring. Returns the
    names of every threshold whose absolute bar the observed `metrics`
    fail to clear; a metric the observation never measured (`None`) is
    never treated as passing."""
    violated: list[str] = []
    for threshold in rules.thresholds:
        value = getattr(metrics, threshold.metric_name, None)
        if value is None:
            violated.append(threshold.metric_name)
            continue
        if threshold.direction is MetricDirection.HIGHER_IS_BETTER:
            if threshold.minimum_absolute is not None and value < threshold.minimum_absolute:
                violated.append(threshold.metric_name)
        else:
            if threshold.maximum_absolute is not None and value > threshold.maximum_absolute:
                violated.append(threshold.metric_name)
    return tuple(violated)


# CP-03 (Phase J audit, remediation 2): the two structural facts every
# fresh canary-lifecycle Policy Gate request carries, identically to what
# `create_canary()` itself already required before this canary could ever
# exist -- never attacker- or caller-influenceable, and never inspected
# for *content* by `evaluate_policy_gate()` (only presence/membership).
_TIER2_PROMOTION_EVIDENCE = Tier2PromotionEvidence(
    adr_reference="docs/IMPLEMENTATION-ROADMAP.md Phase 9.8",
    reliability_summary=(
        "create_canary() already required a COMPLETED, PASS-evaluated "
        "Experiment and a CANDIDATE, PASS-evaluated Adaptation naming "
        "this exact candidate before this canary could ever be created "
        "-- see ExperimentNotEvaluatedForCanaryError / "
        "AdaptationNotCandidateForCanaryError."
    ),
)
_TIER2_ELIGIBLE_ACTIONS: frozenset[str] = frozenset({RequestedAction.ACTIVATE_ADAPTATION.value})


def _require_fresh_canary_authorization(
    tenant_id: uuid.UUID,
    canary: Canary,
    *,
    actor_user_id: uuid.UUID,
    learning_authorization_decision: LearningAuthorizationDecision,
) -> None:
    """CP-03 (Phase J audit, remediation 2): a genuinely FRESH Policy Gate
    evaluation, immediately before `start_canary()`/`_rollback()` calls
    `activate_adaptation()`/`rollback_adaptation()` -- see module
    docstring for the full rationale and the experiment that proved
    remediation 1's provenance-only re-check insufficient.

    Every field below except `learning_authorization_decision` is
    reconstructed from already-persisted, RLS-scoped, immutable domain
    facts, read fresh from the database in this same call -- never a
    cached value, never a caller-supplied claim:
      - `tenant_id` / `Adaptation.lineage_key`: define `scope`, exactly
        the one-adaptation-per-canary invariant `create_canary()` already
        enforces (see models.py's own "never a cross-tenant path at all"
        docstring).
      - `Adaptation.evaluation_outcome`: read fresh via
        `tenant_session_scope()` right here, not from any cached
        `Adaptation` object a caller might pass in. This column is never
        mutated once `record_adaptation_evaluation()` first sets it (no
        code path "un-evaluates" an `Adaptation`), so re-reading it now
        re-reads an immutable historical fact, not stale cached state.
      - `Canary.baseline_version`/`candidate_version`: copied onto
        `Canary` once, at creation, and never mutated afterward (models.py's
        own "a later mutation of the source Experiment/Adaptation can
        never retroactively change what an already-created Canary
        claims" docstring).
      - `requested_action`/`requested_autonomy_tier`/`tier2_eligible_actions`/
        `tier2_promotion_evidence`: the fixed constants above.

    `learning_authorization_decision` is the one genuine "authorization
    state" input this function cannot derive from persisted `Canary`/
    `Adaptation` columns -- `self_learning` maintains no ambient/persisted
    policy table by design (see module docstring), so it must come from
    the caller re-running `authorize_learning_use()` against today's
    policy. It is never trusted merely for being well-typed:
    `evaluate_and_record_policy_gate_decision()` below still requires
    `verify_learning_authorization_provenance()` to confirm it was
    genuinely produced (CP-02), on top of being evaluated fresh (CP-03).

    Raises `CanaryAuthorizationDeniedError` -- never silently skipping the
    caller's mutation -- if this fresh evaluation is not itself an ALLOW."""
    with tenant_session_scope(tenant_id) as session:
        adaptation = session.get(Adaptation, canary.adaptation_id)
        if adaptation is None or adaptation.tenant_id != tenant_id:
            raise CanaryNotFoundError(tenant_id, canary.id)
        lineage_key = adaptation.lineage_key
        evaluation_outcome = adaptation.evaluation_outcome

    comparison = EvaluationComparison(
        outcome=EvaluationOutcome(evaluation_outcome),
        baseline_version=canary.baseline_version,
        candidate_version=canary.candidate_version,
        benchmark=None,
        invalid_reason=None,
        failed_metrics=(),
        regressed_metrics=(),
    )

    request = PolicyGateRequest(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
        requested_autonomy_tier=AutonomyTier.TIER_2_AUTO_EXECUTE_AUDITED.value,
        scope=PolicyGateScope(
            authorized=frozenset({lineage_key}), requested=frozenset({lineage_key})
        ),
        learning_authorization_decision=learning_authorization_decision,
        evaluation_comparison=comparison,
        tier2_promotion_evidence=_TIER2_PROMOTION_EVIDENCE,
        tier2_eligible_actions=_TIER2_ELIGIBLE_ACTIONS,
    )
    decision = evaluate_and_record_policy_gate_decision(request)
    if not decision.is_allowed:
        raise CanaryAuthorizationDeniedError(canary.id, reason=decision.reason)


def create_canary(
    *,
    tenant_id: uuid.UUID,
    experiment: Experiment,
    adaptation: Adaptation,
    policy_gate_decision: PolicyGateDecision,
    monitoring_rules: EvaluationRules,
    created_by_user_id: uuid.UUID,
) -> Canary:
    """Create one `CONFIGURED` canary. See module docstring for the fixed,
    five-part authority-composition check order -- every `raise` below is
    a default-deny branch, not an incidental validation."""
    if experiment.tenant_id != tenant_id or adaptation.tenant_id != tenant_id:
        raise InvalidCanaryCandidateError(
            f"Experiment {experiment.id} / Adaptation {adaptation.id} must both belong to "
            f"tenant {tenant_id}."
        )
    if (
        experiment.candidate_source_kind != ExperimentCandidateSourceKind.ADAPTATION.value
        or experiment.candidate_source_id != adaptation.id
    ):
        raise InvalidCanaryCandidateError(
            f"Experiment {experiment.id} does not name Adaptation {adaptation.id} as its "
            "candidate (or is not an adaptation-sourced experiment)."
        )
    if experiment.status != "completed" or experiment.evaluation_outcome != "pass":
        raise ExperimentNotEvaluatedForCanaryError(
            f"Experiment {experiment.id} is not a completed, PASS-evaluated experiment "
            f"(status={experiment.status!r}, evaluation_outcome={experiment.evaluation_outcome!r})."
        )
    if (
        adaptation.status != AdaptationStatus.CANDIDATE.value
        or adaptation.evaluation_outcome != "pass"
    ):
        raise AdaptationNotCandidateForCanaryError(
            f"Adaptation {adaptation.id} is not a CANDIDATE, PASS-evaluated adaptation "
            f"(status={adaptation.status!r}, evaluation_outcome={adaptation.evaluation_outcome!r})."
        )
    if (
        policy_gate_decision.outcome is not PolicyGateOutcome.ALLOW
        or policy_gate_decision.tenant_id != tenant_id
        or policy_gate_decision.requested_action != RequestedAction.ACTIVATE_ADAPTATION.value
        or policy_gate_decision.requested_autonomy_tier != AutonomyTier.TIER_2_AUTO_EXECUTE_AUDITED
    ):
        raise UnauthorizedCanaryPolicyDecisionError(
            "A tier-2 ALLOW PolicyGateDecision for this tenant and RequestedAction."
            "ACTIVATE_ADAPTATION is required to create a canary."
        )

    # CP-02 (Phase J, third pass): the field checks above are necessary
    # but no longer sufficient -- a `PolicyGateDecision` is same-process,
    # non-persisted, non-cryptographically-bound (this module's own
    # docstring point 3: "this module does not trust that invariant
    # blindly against a hand-built/forged decision object"). See
    # `control_plane.self_learning.policy_gate.service
    # .verify_policy_gate_provenance()`'s own docstring. A forged decision
    # with a fresh, never-audited `decision_id` is rejected here, before
    # it can ever be persisted as this canary's `policy_gate_decision_id`.
    if not verify_policy_gate_provenance(policy_gate_decision, tenant_id=tenant_id):
        raise UnauthorizedCanaryPolicyDecisionError(
            "A tier-2 ALLOW PolicyGateDecision for this tenant and RequestedAction."
            "ACTIVATE_ADAPTATION is required to create a canary."
        )

    with tenant_session_scope(tenant_id) as session:
        canary = Canary(
            tenant_id=tenant_id,
            status=CanaryStatus.CONFIGURED.value,
            experiment_id=experiment.id,
            adaptation_id=adaptation.id,
            candidate_version=str(adaptation.version),
            baseline_version=experiment.baseline_version,
            policy_gate_decision_id=policy_gate_decision.decision_id,
            monitoring_rules=_serialize_rules(monitoring_rules),
            created_by_user_id=created_by_user_id,
        )
        session.add(canary)
        session.flush()
        session.refresh(canary)
        session.expunge(canary)

    _audit(
        tenant_id=tenant_id,
        actor_user_id=created_by_user_id,
        action="learning.canary_created",
        canary_id=canary.id,
        metadata={
            "experiment_id": str(experiment.id),
            "adaptation_id": str(adaptation.id),
            "candidate_version": canary.candidate_version,
            "baseline_version": canary.baseline_version,
            "policy_gate_decision_id": str(policy_gate_decision.decision_id),
        },
    )
    return canary


def get_canary(tenant_id: uuid.UUID, canary_id: uuid.UUID) -> Canary:
    with tenant_session_scope(tenant_id) as session:
        canary = session.get(Canary, canary_id)
        if canary is None or canary.tenant_id != tenant_id:
            raise CanaryNotFoundError(tenant_id, canary_id)
        session.expunge(canary)
        return canary


def start_canary(
    tenant_id: uuid.UUID,
    canary_id: uuid.UUID,
    *,
    started_by_user_id: uuid.UUID,
    learning_authorization_decision: LearningAuthorizationDecision,
) -> Canary:
    """`CONFIGURED` -> `RUNNING`. Activates the underlying `Adaptation`
    for this canary's own tenant (`adaptive.service.activate_adaptation()`)
    -- see module docstring, "The canary *is* the activation, monitored".

    `learning_authorization_decision` (CP-03, Phase J audit, remediation
    2) must be a *freshly*-produced decision -- the caller's own current
    `authorize_learning_use()` result, not a value cached from
    `create_canary()` time -- fed into a genuinely fresh Policy Gate
    evaluation before `activate_adaptation()` is ever reached; see module
    docstring and `_require_fresh_canary_authorization()`."""
    canary = get_canary(tenant_id, canary_id)
    if canary.status != CanaryStatus.CONFIGURED.value:
        raise CanaryNotConfiguredError(canary_id, canary.status)

    _require_fresh_canary_authorization(
        tenant_id,
        canary,
        actor_user_id=started_by_user_id,
        learning_authorization_decision=learning_authorization_decision,
    )

    activate_adaptation(tenant_id, canary.adaptation_id, activated_by_user_id=started_by_user_id)

    with tenant_session_scope(tenant_id) as session:
        row = session.get(Canary, canary_id)
        if row is None or row.tenant_id != tenant_id:
            raise CanaryNotFoundError(tenant_id, canary_id)
        row.status = CanaryStatus.RUNNING.value
        row.started_by_user_id = started_by_user_id
        row.started_at = datetime.now(UTC)
        session.flush()
        session.refresh(row)
        session.expunge(row)
        canary = row

    _audit(
        tenant_id=tenant_id,
        actor_user_id=started_by_user_id,
        action="learning.canary_started",
        canary_id=canary.id,
        metadata={"adaptation_id": str(canary.adaptation_id)},
    )
    return canary


def _rollback(
    tenant_id: uuid.UUID,
    canary: Canary,
    *,
    actor_user_id: uuid.UUID,
    reason: str,
    triggered_automatically: bool,
    learning_authorization_decision: LearningAuthorizationDecision,
) -> Canary:
    """Shared rollback path for both the automatic
    (`record_canary_observation()`) and manual (`rollback_canary()`)
    triggers. Always leaves the canary in a real, audited terminal state
    -- `ROLLED_BACK` on success, `ROLLBACK_FAILED` (then re-raised) if
    `adaptive.service.rollback_adaptation()` itself fails -- never a
    silent failure (Phase 9.8's own Rollback Strategy).

    CP-03 (Phase J audit, remediation 2): runs a genuinely fresh Policy
    Gate evaluation immediately before calling `rollback_adaptation()` --
    see `_require_fresh_canary_authorization()`. A fresh-evaluation denial
    here is an authorization denial, not a rollback *attempt* that
    failed, so it is raised directly (mirroring `create_canary()`'s own
    `UnauthorizedCanaryPolicyDecisionError` handling) rather than driving
    the canary into `ROLLBACK_FAILED` -- that state is reserved for a
    real, attempted `rollback_adaptation()` call that itself raised."""
    _require_fresh_canary_authorization(
        tenant_id,
        canary,
        actor_user_id=actor_user_id,
        learning_authorization_decision=learning_authorization_decision,
    )

    try:
        rollback_adaptation(tenant_id, canary.adaptation_id, rolled_back_by_user_id=actor_user_id)
    except (AdaptationNotActiveError, NoPreviousVersionError) as exc:
        with tenant_session_scope(tenant_id) as session:
            row = session.get(Canary, canary.id)
            if row is None or row.tenant_id != tenant_id:
                raise CanaryNotFoundError(tenant_id, canary.id) from exc
            row.status = CanaryStatus.ROLLBACK_FAILED.value
            row.rollback_reason = reason
            session.flush()
            session.refresh(row)
            session.expunge(row)

        _audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            action="learning.canary_rollback_failed",
            canary_id=canary.id,
            outcome=AuditOutcome.FAILURE,
            metadata={
                "adaptation_id": str(canary.adaptation_id),
                "reason": reason,
                "triggered_automatically": triggered_automatically,
                "cause": type(exc).__name__,
            },
        )
        raise CanaryRollbackFailedError(canary.id, exc) from exc

    with tenant_session_scope(tenant_id) as session:
        row = session.get(Canary, canary.id)
        if row is None or row.tenant_id != tenant_id:
            raise CanaryNotFoundError(tenant_id, canary.id)
        row.status = CanaryStatus.ROLLED_BACK.value
        row.rolled_back_by_user_id = actor_user_id
        row.rolled_back_at = datetime.now(UTC)
        row.rollback_reason = reason
        session.flush()
        session.refresh(row)
        session.expunge(row)
        rolled_back = row

    _audit(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        action="learning.canary_rolled_back",
        canary_id=rolled_back.id,
        metadata={
            "adaptation_id": str(rolled_back.adaptation_id),
            "reason": reason,
            "triggered_automatically": triggered_automatically,
        },
    )
    return rolled_back


def record_canary_observation(
    tenant_id: uuid.UUID,
    canary_id: uuid.UUID,
    metrics: EvaluationMetrics,
    *,
    recorded_by_user_id: uuid.UUID,
    learning_authorization_decision: LearningAuthorizationDecision,
) -> Canary:
    """Check `metrics` against the canary's own `monitoring_rules`. A
    threshold violation triggers **automatic** rollback in this same call
    -- Phase 9.8's own Tests bullet, verbatim: "a canary that fails its
    monitored threshold is proven to roll back automatically, not merely
    flagged." No violation leaves the canary `RUNNING`, unchanged --
    concluding the monitoring window is a separate, explicit
    `conclude_canary_monitoring()` call.

    `learning_authorization_decision` (CP-03, Phase J audit, remediation
    2): the monitoring caller's own current `authorize_learning_use()`
    result -- required on every call, not only a violating one, so a
    fresh Policy Gate evaluation is always ready the instant `_rollback()`
    actually needs it; see module docstring for why automatic rollback
    carries no separate machine-principal type -- `recorded_by_user_id`
    already identifies whichever `core.identity.User` the monitoring
    job/agent attributes its own actions to, exactly as before."""
    canary = get_canary(tenant_id, canary_id)
    if canary.status != CanaryStatus.RUNNING.value:
        raise CanaryNotRunningError(canary_id, canary.status)

    rules = _deserialize_rules(canary.monitoring_rules)
    violated = _violated_metrics(metrics, rules)

    _audit(
        tenant_id=tenant_id,
        actor_user_id=recorded_by_user_id,
        action="learning.canary_observation_recorded",
        canary_id=canary.id,
        outcome=AuditOutcome.FAILURE if violated else AuditOutcome.SUCCESS,
        metadata={"violated_metrics": list(violated)} if violated else {},
    )

    if violated:
        return _rollback(
            tenant_id,
            canary,
            actor_user_id=recorded_by_user_id,
            reason=f"monitoring threshold violated: {', '.join(violated)}",
            triggered_automatically=True,
            learning_authorization_decision=learning_authorization_decision,
        )
    return canary


def conclude_canary_monitoring(
    tenant_id: uuid.UUID, canary_id: uuid.UUID, *, concluded_by_user_id: uuid.UUID
) -> Canary:
    """`RUNNING` -> `SUCCEEDED`: the monitoring window elapsed with no
    threshold violation. Does not itself promote anything -- promotion is
    the separate, explicit `promote_canary()` call (Phase 9.8's own
    Promotion requirement: never merely because monitoring/the canary
    started)."""
    canary = get_canary(tenant_id, canary_id)
    if canary.status != CanaryStatus.RUNNING.value:
        raise CanaryNotRunningError(canary_id, canary.status)

    with tenant_session_scope(tenant_id) as session:
        row = session.get(Canary, canary_id)
        if row is None or row.tenant_id != tenant_id:
            raise CanaryNotFoundError(tenant_id, canary_id)
        row.status = CanaryStatus.SUCCEEDED.value
        row.concluded_by_user_id = concluded_by_user_id
        row.concluded_at = datetime.now(UTC)
        session.flush()
        session.refresh(row)
        session.expunge(row)
        canary = row

    _audit(
        tenant_id=tenant_id,
        actor_user_id=concluded_by_user_id,
        action="learning.canary_succeeded",
        canary_id=canary.id,
        metadata={"adaptation_id": str(canary.adaptation_id)},
    )
    return canary


def promote_canary(
    tenant_id: uuid.UUID, canary_id: uuid.UUID, *, promoted_by_user_id: uuid.UUID
) -> Canary:
    """`SUCCEEDED` -> `PROMOTED`. A bookkeeping/audit transition only --
    the underlying `Adaptation` is already `ACTIVE` since `start_canary()`;
    nothing further mutates production state here. Preserves candidate/
    baseline identity, experiment provenance, and the policy-gate decision
    in its own audit metadata (Phase 9.8's own Promotion requirement)."""
    canary = get_canary(tenant_id, canary_id)
    if canary.status != CanaryStatus.SUCCEEDED.value:
        raise CanaryNotSucceededError(canary_id, canary.status)

    with tenant_session_scope(tenant_id) as session:
        row = session.get(Canary, canary_id)
        if row is None or row.tenant_id != tenant_id:
            raise CanaryNotFoundError(tenant_id, canary_id)
        row.status = CanaryStatus.PROMOTED.value
        row.promoted_by_user_id = promoted_by_user_id
        row.promoted_at = datetime.now(UTC)
        session.flush()
        session.refresh(row)
        session.expunge(row)
        canary = row

    _audit(
        tenant_id=tenant_id,
        actor_user_id=promoted_by_user_id,
        action="learning.canary_promoted",
        canary_id=canary.id,
        metadata={
            "experiment_id": str(canary.experiment_id),
            "adaptation_id": str(canary.adaptation_id),
            "candidate_version": canary.candidate_version,
            "baseline_version": canary.baseline_version,
            "policy_gate_decision_id": str(canary.policy_gate_decision_id),
        },
    )
    return canary


def rollback_canary(
    tenant_id: uuid.UUID,
    canary_id: uuid.UUID,
    *,
    rolled_back_by_user_id: uuid.UUID,
    reason: str,
    learning_authorization_decision: LearningAuthorizationDecision,
) -> Canary:
    """Explicit, operator/agent-triggered rollback from `RUNNING` or
    `SUCCEEDED` (e.g. a decision not to promote after all). See
    `_rollback()` for the shared, always-audited terminal-state
    discipline. `learning_authorization_decision` (CP-03, Phase J audit,
    remediation 2): the caller's own current `authorize_learning_use()`
    result, fed into a fresh Policy Gate evaluation before any mutation --
    see module docstring."""
    canary = get_canary(tenant_id, canary_id)
    if canary.status not in (CanaryStatus.RUNNING.value, CanaryStatus.SUCCEEDED.value):
        raise CanaryNotRunningError(canary_id, canary.status)
    return _rollback(
        tenant_id,
        canary,
        actor_user_id=rolled_back_by_user_id,
        reason=reason,
        triggered_automatically=False,
        learning_authorization_decision=learning_authorization_decision,
    )


def cancel_canary(
    tenant_id: uuid.UUID,
    canary_id: uuid.UUID,
    *,
    cancelled_by_user_id: uuid.UUID,
    reason: str | None = None,
) -> Canary:
    """`CONFIGURED` -> `CANCELLED` only -- a canary that has already
    started (`RUNNING`/`SUCCEEDED`) has a live, activated `Adaptation`
    and must go through `rollback_canary()` instead, never a bare status
    flip that would leave production state and canary bookkeeping out of
    sync."""
    canary = get_canary(tenant_id, canary_id)
    if canary.status != CanaryStatus.CONFIGURED.value:
        if canary.status in TERMINAL_CANARY_STATUSES:
            raise CanaryAlreadyTerminalError(canary_id, canary.status)
        raise CanaryNotConfiguredError(canary_id, canary.status)

    with tenant_session_scope(tenant_id) as session:
        row = session.get(Canary, canary_id)
        if row is None or row.tenant_id != tenant_id:
            raise CanaryNotFoundError(tenant_id, canary_id)
        row.status = CanaryStatus.CANCELLED.value
        row.cancelled_by_user_id = cancelled_by_user_id
        row.cancelled_at = datetime.now(UTC)
        row.cancellation_reason = reason
        session.flush()
        session.refresh(row)
        session.expunge(row)
        canary = row

    _audit(
        tenant_id=tenant_id,
        actor_user_id=cancelled_by_user_id,
        action="learning.canary_cancelled",
        canary_id=canary.id,
        metadata={"adaptation_id": str(canary.adaptation_id)},
    )
    return canary
