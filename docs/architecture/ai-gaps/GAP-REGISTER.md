# AI platform gap register (Gaps 20, 21, 22)

This register did not exist in the repository when the proposals were written (searched 2026-11-09). It is the tracking record for these three gaps. It is not a substitute for the deferred-issue ledger in `docs/P-ROADMAP.md`, which carries a pointer row.

Status vocabulary: **Proposed** (document submitted, not approved), **Approved** (owner decision recorded), **In progress**, **Implemented** (merged), **Released** (tag, verified), **Closed** (released and verified through governance). Only the owner moves a gap to Approved. Nothing is beyond Proposed today.

| Gap | Title | Proposal | Status | Existing coverage | Missing | Depends on | Blocks | Label if built |
|---|---|---|---|---|---|---|---|---|
| 20 | Tenant AI enablement and model selection | [GAP-20](GAP-20-WORKSPACE-AI-CONFIGURATION.md) | Proposed 2026-11-09 | tenant policy (default off), allowlist grants, preferences, audit, RLS, shared-credential model | eligibility read, ranking, grant-time validation, platform hold, exposed API | owner decisions (surface, hold permission) | 21 (optional hold), 22 (settings summary) | 0.Y.0 |
| 21 | Monetary AI spending limits | [GAP-21](GAP-21-MONETARY-AI-SPENDING-LIMITS.md) | Proposed 2026-11-09 | soft monthly token quota, `ai_model_prices`, `estimated_cost` per attempt | monetary budget, plan limits, overrides, reservation, thresholds, staleness, other billable units | 20a (selected model), ADR-0054 Q8 decision | 22 (budget block) | 0.Y.0 |
| 22 | Tenant AI usage visibility | [GAP-22](GAP-22-WORKSPACE-AI-USAGE-VISIBILITY.md) | Proposed 2026-11-09 | Core `/usage` (tokens), platform `read_ai_usage_totals`, attempts table | tenant AI report, cost totals, remaining limits, permission tier, descendant rule, read audit, retention | 21 for budget fields only | none | additive or 0.Y.0 |

## Progress log

| Date | Event |
|---|---|
| 2026-11-09 | Audit of `main` at `0f9bf4d` (v0.10.0); three proposals and the sequencing document written; submitted as a docs-only pull request. No code, migration, ADR, version or pin changed. No provider configured or called; no AI activated in any tenant. |

## What is verified versus not

Verified by reading code at `0f9bf4d`: everything cited with `file:line` in the proposals. Not verified: behaviour with any live provider; production-sized performance; whether Core billing exposes active plan codes; whether an index on attempts by tenant and start time exists; the body of ADR-0037; `core/rbac/principal.py` beyond the grep hit for "workspace". The proposals were produced from a read-only audit, then spot-checked by the author for the quota and tenant-policy claims; they were not run.

## Out of scope and unchanged

Voice AI; tenant-owned provider credentials (separate pending owner decision, ADR-0054/AI roadmap); streaming (`stream_inference` is disabled, issue #206); sending-domain management (#225); the LeadStack version pin (unchanged).
