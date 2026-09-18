"""S-03 (BANK-SEC-01/04) -- the generic sensitive-value redaction
primitive for `infra.observability`'s structured logging boundary.

**Threat model and boundary** (`docs/SECURITY.md` section 4;
`docs/ADR/0019-application-level-field-encryption.md`'s own "redaction is
defense in depth" framing, restated here for logging specifically): the
goal is *"sensitive values must not be accidentally persisted or emitted
through ordinary logging paths"* -- ordinary meaning `logging.getLogger(
__name__).info(..., extra={...})`-style structured calls, the only
pattern `docs/OBSERVABILITY.md` section 1 asks application code to use.
This is **not** a claim that no secret can ever appear in any log line
under any circumstance -- see `infra/observability/logging.py`'s own
module docstring for the two paths this module does *not* cover
(the flattened `%s`-formatted message string, and `logging.Formatter`'s
own full exception-traceback text) and why covering them generically
would require exactly the "expensive/unreliable regex engine over
arbitrary text" this module's design deliberately avoids.

**Primary defense: key classification, not pattern-guessing** (mirrors
`core/audit_log/metadata.py`'s own deliberate, pre-existing choice --
"Deliberately NOT a generic secret-detection engine... a small, explicit,
deterministic set of checks", restated independently here rather than
imported from `core`, since `infra` must never depend on `core`,
docs/ARCHITECTURE.md section 2). `SENSITIVE_KEYS` is a fixed, named list
-- not a heuristic, not an entropy scan, not a regex over values.
`is_sensitive_key()` normalizes a key (lowercase, non-alphanumeric
characters stripped) before comparison, so `access_token`, `AccessToken`,
`ACCESS_TOKEN`, and `Access-Token` are all recognized as the same
classification without needing every literal spelling enumerated -- still
an *exact* match against the normalized denylist, never a substring rule
(a field like `password_hint` normalizes to `passwordhint`, which does
not equal `password`'s own normalized form, so it is correctly left
alone -- BANK-SEC-04's own "avoid excessively broad substring rules").
"""

from __future__ import annotations

REDACTED = "[REDACTED]"

# Fixed, explicit denylist (never a generic scanner -- see module
# docstring). Field/header names that are never a legitimate thing to
# retain verbatim in a log record. Deliberately broad enough to cover
# BANK-SEC-04's own named examples (credentials, tokens, authentication
# headers, cookies) plus this codebase's own precedent set
# (`core/audit_log/metadata.py`'s `_FORBIDDEN_KEYS`, independently
# maintained here for the Infra/Core dependency-direction reason above --
# both lists should be reviewed together if either changes).
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "session_token",
        "id_token",
        "bearer",
        "authorization",
        "proxy_authorization",
        "auth",
        "cookie",
        "set_cookie",
        "api_key",
        "apikey",
        "x_api_key",
        "credential",
        "credentials",
        "private_key",
        "signing_key",
        "encryption_key",
    }
)

# Normalized once, at import time -- `is_sensitive_key()` is on the
# structured-logging hot path (BANK-SEC-04 section 20: "avoid expensive
# regex processing... on frequent logging paths"), so this trades a
# one-time cost at module import for an O(1) set lookup per call instead
# of re-normalizing the whole denylist on every log record.
_SENSITIVE_KEYS_NORMALIZED: frozenset[str] = frozenset(
    "".join(ch for ch in key.lower() if ch.isalnum()) for key in SENSITIVE_KEYS
)

# Recursion is bounded defensively (BANK-SEC-04 section 20: no unbounded
# work on a logging path) -- ordinary application `extra=` payloads are a
# handful of levels deep at most; anything deeper is almost certainly a
# caller mistake (or hostile input) this module declines to spend
# unbounded time walking, not a real structured-logging use case.
_MAX_REDACTION_DEPTH = 10


def _normalize_key(key: str) -> str:
    return "".join(ch for ch in key.lower() if ch.isalnum())


def is_sensitive_key(key: str) -> bool:
    """Whether `key` (a dict key or an HTTP header name) matches
    `SENSITIVE_KEYS`, after case/separator-insensitive normalization.
    Exact match only -- never a substring check."""
    return _normalize_key(key) in _SENSITIVE_KEYS_NORMALIZED


def _redact_authorization_value(value: str) -> str:
    """`Authorization`/`Proxy-Authorization`-shaped values keep their
    scheme (`Bearer`, `Basic`, ...) -- operationally useful, never
    secret on its own -- and redact only the credential that follows
    (BANK-SEC-04 section 7: "preserve non-secret metadata such as
    scheme = Bearer without preserving the credential itself")."""
    scheme, sep, _credential = value.partition(" ")
    if sep and scheme.isalpha():
        return f"{scheme} {REDACTED}"
    return REDACTED


def redact(value: object, *, _depth: int = 0) -> object:
    """Return a sanitized **copy** of `value` -- the original is never
    mutated (BANK-SEC-04 section 11: "prefer returning a sanitized
    copy"). Recurses through `dict`/`list`/`tuple`; any other type
    (str/int/float/bool/None, or an opaque object) passes through
    unchanged, since only dict *keys* carry the classification this
    module acts on -- there is no attempt to inspect or guess at
    arbitrary values.

    A dict key matching `is_sensitive_key()` has its value replaced with
    `REDACTED` (or the scheme-preserving form for an
    authorization-shaped key) without recursing into it -- the whole
    value is untrusted once its key says so, not just parts of it.

    **Depth limit fails safe, not open**: at `_MAX_REDACTION_DEPTH`, an
    still-unexamined `dict`/`list`/`tuple` is replaced with a truncation
    marker rather than returned as-is -- returning an uninspected
    container verbatim would silently defeat the whole boundary for
    pathologically deep input (this module's own security review found
    the original version did exactly that; fixed here). A primitive
    (str/int/float/bool/None) at the depth limit is still returned
    unchanged -- it is a leaf with no further keys to classify, so
    truncating it would only discard safe information for no security
    benefit.
    """
    if _depth >= _MAX_REDACTION_DEPTH:
        if isinstance(value, (dict, list, tuple)):
            return "[REDACTION_DEPTH_EXCEEDED]"
        return value
    if isinstance(value, dict):
        result: dict[object, object] = {}
        for key, nested in value.items():
            if isinstance(key, str) and is_sensitive_key(key):
                normalized = _normalize_key(key)
                is_auth_key = normalized in ("authorization", "proxyauthorization")
                if is_auth_key and isinstance(nested, str):
                    result[key] = _redact_authorization_value(nested)
                else:
                    result[key] = REDACTED
            else:
                result[key] = redact(nested, _depth=_depth + 1)
        return result
    if isinstance(value, list):
        return [redact(item, _depth=_depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item, _depth=_depth + 1) for item in value)
    return value


def safe_exception_type(exc: BaseException) -> str:
    """The exception's type name only -- never `str(exc)`, which may
    embed request/response data (a header value, a URL with credentials
    in its query string, a provider's own error body) this module cannot
    safely inspect. Mirrors the already-established pattern
    `infra/health/results.py`'s `CheckResult.detail` uses for the same
    reason (that module's own docstring: "restricted to a failing
    exception's type name only, never its message"). Intended for call
    sites handling a sensitive operation (a credential-bearing outbound
    request, an auth flow) that want *some* failure detail in a log/audit
    record without risking whatever `str(exc)` might contain -- an
    opt-in convenience, not an automatic interception of every
    `logger.exception()` call (see module docstring's "what this does
    not cover")."""
    return type(exc).__name__
