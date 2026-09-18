# ADR-0020: Sensitive-value redaction boundary for logging and audit

Status: Accepted
Date: 2026-09-17
Supersedes / Superseded by: —

## Context

BANK-SEC-01 (the Open Banking security readiness audit) identified finding S-03 (MED-HIGH): sensitive values could reach audit/logging fields through free-form or insufficiently validated metadata, with no centralized scrubbing/filtering guarantee. This ADR is BANK-SEC-04: the remediation for S-03 only.

Re-reading the actual implementation (`core/audit_log/metadata.py`, `infra/observability/logging.py`) rather than trusting the original finding's description verbatim (this phase's own directive: "do not assume the audit model or logging stack described in BANK-SEC-01 still has the exact same implementation") found the exposure smaller, and shaped differently, than S-03's original text implied:

- **`core/audit_log`'s side was already strong.** `record()` unconditionally calls `validate_metadata()` before any database write — a recursive, case-insensitive-ish (`.strip().lower()`), fixed-denylist check across every key at every nesting depth (dict and list), that **rejects** the whole write (`ForbiddenMetadataKeyError`) rather than persisting a corrupted or partially-scrubbed record. This is a real, non-bypassable, already-tested boundary — not developer convention.
- **`infra/observability`'s side had no equivalent mechanism at all.** `JsonFormatter` serialized every `extra=` field a caller passed to `logger.info(..., extra={...})` verbatim — no key classification, no recursion, no redaction. This was the genuine, unremediated gap.

This ADR's actual scope, given that discovery: extend the *logging* side to match the *audit* side's existing rigor, using a shared, centrally-defined sensitive-key classification — without redesigning or duplicating the audit-log mechanism's own (already-correct, already-tested) reject-based semantics.

## Options Considered

### Option A — A new `infra/observability/redaction.py` primitive (key classification + recursive scrub), wired into `JsonFormatter` as the one central structured-logging boundary

- Advantages: exactly one place (`JsonFormatter.format()`) every `extra=` field from every logger in the codebase passes through — no per-call-site opt-in needed; reuses the existing "fixed, explicit denylist, never a generic scanner" design `core/audit_log/metadata.py` already established as this codebase's accepted approach to this class of problem; `infra` cannot depend on `core` (docs/ARCHITECTURE.md section 2), so the classification list is independently maintained here rather than imported, which is a real but small and already-precedented cost (mirrors how `infra/secrets` and `core/identity` each independently define their own non-secret validation, not a new pattern).
- Disadvantages: two denylists (`core/audit_log/metadata.py`'s `_FORBIDDEN_KEYS` and this ADR's `SENSITIVE_KEYS`) must be reviewed together if either changes — documented explicitly in both modules' docstrings as the mitigation, rather than solved by a code-level shared import that would require weakening the Core/Infra dependency direction.

### Option B — Move `core/audit_log`'s classification logic into `infra/observability` and have `core/audit_log` import it

- Advantages: single source of truth for the sensitive-key list.
- Disadvantages: unrelated refactoring of an already-correct, already-tested, currently-shipping module for no functional gain (this ADR's own directive: "do not... unrelated refactoring"); the audit-log's reject-and-fail-closed semantics and the logging boundary's redact-and-continue semantics are deliberately different (section below) — merging their implementations risks conflating two systems this ADR explicitly says to keep distinct ("the same underlying redaction primitive may be shared, but the two systems should retain their distinct semantics"). Rejected: out of proportion to the actual gap found.

### Option C — A generic regex/entropy-based secret scanner over all log output

- Advantages: could theoretically catch an unknown, unnamed secret shape.
- Disadvantages: explicitly rejected by this phase's own directive ("do not introduce an expensive or unreliable regex engine across arbitrary application logs... do not claim that arbitrary unknown secrets are mathematically impossible to log") and by `core/audit_log/metadata.py`'s own established precedent ("Deliberately NOT a generic secret-detection engine"). Unreliable (false negatives on anything not matching a guessed pattern, false positives on ordinary high-entropy-looking data like UUIDs) and expensive on a hot logging path.

## Recommendation

Option A.

## Decision

**Accepted.** `infra/observability/redaction.py` is a new module providing:

1. **`SENSITIVE_KEYS`** — a fixed, explicit denylist (password, secret, token, access_token, refresh_token, id_token, api_key, authorization, proxy_authorization, cookie, set_cookie, client_secret, private_key, encryption_key, credential, credentials, and related entries) — never a heuristic or regex-over-values.
2. **`is_sensitive_key(key)`** — case/separator-insensitive matching: a key is normalized (lowercased, non-alphanumeric characters stripped) before comparison against a similarly-normalized denylist, so `access_token`, `AccessToken`, `ACCESS_TOKEN`, and `Access-Token` are all recognized as one classification — still an *exact* match on the normalized form, never a substring rule (`password_hint` is correctly left alone).
3. **`redact(value)`** — returns a sanitized **copy** (never mutates the input) of a `dict`/`list`/`tuple`, recursing through nested structures and replacing any value whose dict key is sensitive with `"[REDACTED]"`. An `Authorization`/`Proxy-Authorization`-shaped value keeps its scheme (`"Bearer [REDACTED]"`) rather than being fully opaque, since the scheme alone is useful and never secret.
4. **`safe_exception_type(exc)`** — returns `type(exc).__name__` only, never `str(exc)`. Mirrors the already-established `infra/health/results.py::CheckResult.detail` pattern ("restricted to a failing exception's type name only, never its message") rather than inventing a new convention.

**Wired into `infra/observability/logging.py`'s `JsonFormatter`**: every `extra=` field passed to any `logger.*()` call, across the entire codebase, is redacted via `redact()` before JSON serialization — this is the "one central structured logging configuration" this phase's directive asks for; no per-call-site opt-in, no new logger wrapper.

## Audit versus Logging: Deliberately Distinct Semantics

| | `core/audit_log` | `infra/observability` (this ADR) |
|---|---|---|
| Failure mode | **Reject** the whole write (`ForbiddenMetadataKeyError`) | **Redact** and continue emitting the record |
| Rationale | An audit record is a durable security/business artifact — a partially-redacted one could misrepresent what happened; better to force the caller to fix the metadata than persist a silently-altered record | A log line is an operational/debugging record emitted at high volume from many call sites the audit-log's "fail the caller" discipline is not appropriate for — losing the whole line to a formatting-time exception would be worse for operability than redacting one field |
| Where enforced | `core.audit_log.service.record()`, unconditionally, before any database write | `infra.observability.logging.JsonFormatter.format()`, unconditionally, before JSON serialization |

Both share the same *kind* of classification (a fixed, explicit, case-insensitive key denylist) but are independently maintained per the Core/Infra dependency direction (`infra` cannot import `core`) — not a redesign of either, a parallel application of the same accepted pattern.

## Coverage and Explicit Limitations

**Covered**: any `extra={...}` mapping passed to `logging.getLogger(__name__).info/warning/error/exception(...)`, including arbitrarily nested dicts/lists/tuples within it, across every module in the codebase that logs through `infra.observability.configure_logging()`'s configured formatter (which is all of them — `docs/OBSERVABILITY.md` section 1 already mandates this as the only supported logging pattern).

**Not covered, deliberately, and documented rather than silently assumed away**:

1. **The flattened `%s`-formatted message string.** `logger.info("token=%s", value)` interpolates `value` directly into `record.getMessage()`'s output *before* `JsonFormatter` ever sees a key to classify — there is no key at that point, only already-flattened text. Scrubbing arbitrary message text for unknown secret shapes is exactly the regex-engine approach this ADR's own Option C rejected. **Developer guidance**: pass sensitive-shaped context through `extra=` keys, never string interpolation — `tests/infra/observability/test_logging_redaction_unit.py::test_message_string_interpolation_is_an_explicitly_uncovered_path` enforces this remains a documented, intentional gap rather than a silently-assumed one (it asserts the canary value *does* leak through this specific path, so the test itself fails loudly if anyone changes this expectation without updating this ADR).
2. **`logging.Formatter`'s own exception-traceback text** (`record.exc_info` → `self.formatException()`, when a caller uses `logger.exception(...)` inside an `except` block). The full traceback, including `str(exc)`, is stdlib behavior this ADR does not intercept — modifying global traceback formatting risks breaking legitimate local-development debugging and is a much larger surface than a targeted fix warrants. **Mitigation provided, not automatic**: `safe_exception_type(exc)` is available for call sites handling a sensitive operation (an outbound credential-bearing request, an auth flow) that want failure detail in a log without risking `str(exc)`'s contents — the one real `logger.exception()` call site in this codebase today (`api/middleware.py`'s unhandled-request-error handler) already only logs non-sensitive `extra` fields (`http_method`, `http_path`), so no current call site is known to leak through this path; this is a forward-looking mitigation for future call sites, not a retrofit of an existing leak.

**This ADR does not claim**: "no secret can ever appear in any log line under any circumstance." It documents the actual, verified boundary (structured `extra=` fields, recursively) and its two known, explicit exclusions above.

**Observations from this ADR's own post-implementation review, explicitly out of its scope**:

- `core.audit_log.__init__`'s public surface exports the `AuditLogEntry` ORM model itself (needed so `record()`/`get()`/`list()`'s return types are usable by callers). A caller could, in principle, import `AuditLogEntry` and `infra.db.tenant_session_scope` directly and persist an entry without going through `record()`/`validate_metadata()` — no import-linter contract prevents this specific combination (only direct `sqlalchemy`/`psycopg` imports from Core are forbidden, and this path uses neither directly). No such caller exists anywhere in the current codebase today (verified: `AuditLogEntry(` is constructed in exactly one place, `core/audit_log/service.py`'s own `record()`). This is a pre-existing characteristic of how every Core module exports its ORM entities for type-annotation purposes, not something this ADR introduced or is scoped to fix — noted here for completeness, not as an S-03 gap.
- `infra/jobs/dead_letter.py` (a different subsystem, already reviewed and accepted under a prior security initiative, RA-12-7) formats a dead-lettered job's error as `f"{type(error).__name__}: {error}"` — including the exception's own message — into a persisted Redis record. That module's own docstring already documents the accepted mitigation ("job producers are responsible for never putting a secret value into a payload or raising an error that embeds one"). This is not a logging or audit-log path and was not in this phase's scope to change; noted here only because it is the same *class* of concern (exception text reaching a persisted record) this ADR addresses for logging specifically.

## Tests

`tests/infra/observability/test_redaction_unit.py` (standalone primitive: basic key redaction, case/separator variants, nested dicts, lists/tuples, header handling including scheme preservation, false-positive safety, no-mutation) and `tests/infra/observability/test_logging_redaction_unit.py` (wired-in `JsonFormatter` behavior via the existing `captured_logs`/`capsys` pattern `test_logging.py` already establishes, including a `BANKSEC_CANARY_*`-named security-regression test searching *raw* captured stdout, and the explicit uncovered-path test above). `core/audit_log`'s own existing `tests/core/audit_log/test_metadata_validation.py` already proves the audit-persistence side of S-03 independently — not duplicated here.

## Performance

`is_sensitive_key()`'s denylist is normalized once at module import time (`_SENSITIVE_KEYS_NORMALIZED`), so each call is an O(1) set lookup, not a re-normalization of the whole list. Recursion in `redact()` is bounded to 10 levels deep as a defensive cap against pathological input on a logging hot path — not a realistic depth for an ordinary `extra=` payload. No network calls, no database calls, no repeated serialization.

**Depth limit fails safe, not open** (found during this ADR's own post-implementation security review, fixed before checkpoint): the first version returned an unexamined `dict`/`list`/`tuple` unchanged once the depth limit was reached — a sensitive key nested past level 10 would have passed through verbatim, silently defeating the boundary for pathologically deep input. Fixed so a still-unexamined container at the depth limit is replaced with a `"[REDACTION_DEPTH_EXCEEDED]"` marker instead; a primitive value at the limit is still returned as-is (it is a leaf with no further keys to classify). `tests/infra/observability/test_redaction_unit.py::test_depth_limit_fails_safe_not_open` proves this with a 15-level-deep canary payload.

**Supported data model, precisely**: `redact()` recurses through `dict`, `list`, and `tuple` only. Any other type — a `set`, `bytes`, a custom class instance, a Pydantic model, an exception object — passes through completely unexamined at whatever position it appears, by design (only a `dict` *key* carries the classification this module acts on; there is no attempt to inspect or serialize arbitrary objects). This is safe for this codebase's actual `extra=` usage, verified during this ADR's review by reading every `logger.*()` call site in `core/`, `infra/`, `api/`, and `control-plane/`: every current call passes either plain JSON-shaped values (str/int/dict/list) or `type(exc).__name__`, never an opaque object as a dict value. A future caller passing a non-JSON-shaped object inside `extra=` would not have that object's own internals redacted — this is the same class of limitation as the message-interpolation and traceback gaps above, and the same developer guidance applies: pass sensitive-shaped context as plain, JSON-shaped `extra=` values.

## What Would Be Difficult to Change Later

If a future module logs sensitive-shaped data through a path other than `extra=` on the standard logger (a custom handler, a third-party library's own logging, a print statement), it bypasses this boundary entirely and would need its own review — the same "any code path outside the sanctioned chokepoint is invisible to the abstraction" pattern already identified for `infra/secrets` (ADR-0012) and `infra/db` (ADR pending/implicit in `docs/MULTI-TENANCY.md` section 3). This is why `docs/OBSERVABILITY.md` section 1's "one supported logging pattern" rule matters beyond style consistency.

## Related

`docs/SECURITY.md` section 4; `core/audit_log/metadata.py` (the pre-existing, independently-maintained audit-side mechanism this ADR extends the pattern of, not replaces); `infra/health/results.py` (the pre-existing safe-exception-detail precedent `safe_exception_type()` follows); `docs/ADR/0012-secrets-management.md` (the chokepoint-bypass risk pattern referenced above); the BANK-SEC-01 audit (finding S-03) and BANK-SEC-04 (this remediation)'s own directive.
