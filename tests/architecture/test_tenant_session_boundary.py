"""S-04 (BANK-SEC-01/06) -- architecture enforcement for tenant-owned
database access (docs/ADR/0022-tenant-session-boundary-enforcement.md).

The security invariant: **tenant-owned database access must execute
through `saas_os.infra.db.tenant_session_scope()` unless the call site is an
explicitly reviewed, narrowly classified global/system operation.**
PostgreSQL's own Row-Level Security (`saas_os/infra/db/rls.py`,
`tests/core/tenancy/test_tenant_isolation_integration.py`) already fails
closed at the database layer -- an untenanted or wrongly-tenanted query
against an RLS-protected table returns zero rows, never another tenant's
rows. This file adds a second, independent, *static* control on top of
that: it catches the mistake at review/CI time, before a query is ever
run against a real database, rather than relying solely on RLS silently
returning nothing.

**Why an AST scan, not import-linter**: `session_scope()` and
`tenant_session_scope()` are both legitimately exported from the same
`saas_os.infra.db` module (`tests/infra/test_db_public_surface_unit.py`'s own
curated whitelist) -- import-linter's contracts reason about *module*
dependency edges (does module A import module B at all), not about
*which name* a module imports from an edge it is already allowed to
have. Distinguishing "saas_os/core/billing imports saas_os.infra.db" (always allowed)
from "saas_os/core/billing calls the untenanted entry point where a tenant-owned
one was required" needs to inspect actual `Call` nodes, which import-
linter's contract language cannot express. This file is therefore a
second, narrowly-scoped mechanism -- not a replacement for import-linter,
which still separately enforces "no module outside saas_os/infra/db constructs
its own SQLAlchemy session at all" (`tests/architecture/
test_layer_boundaries.py::test_only_infra_db_can_import_sqlalchemy_or_psycopg`,
`::test_forbidden_direct_sqlalchemy_import_from_core_is_actually_caught`
-- already proven, not duplicated here).

**The mechanism**: `_find_session_scope_call_sites()` walks every `.py`
file under `core/`, `saas_os/control_plane/`, `products/`, and
`api/` (excluding `tests/` and `__pycache__` -- and `saas_os/infra/db` itself is
never scanned: it is the trusted chokepoint implementation, not a caller
subject to this invariant; `tenant_session_scope()`'s own body legitimately
calls `session_scope()` internally) and records every `Call` whose callee
resolves to the exact name `session_scope` (never a substring match
against `tenant_session_scope`, which is a different identifier
entirely), together with its enclosing function name. `_ALLOWLIST` is a
curated, per-file, per-function registry -- every entry below was
individually verified against the actual table/model each function
queries and the actual RLS migration for that table (see the ADR's
inventory) before being added; none is a guess. Any call site the scan
finds that is *not* in `_ALLOWLIST` fails the test -- this is what makes
the control fail-closed for a *new* bypass: a new function that mistakenly
reaches for `session_scope()` where a tenant-owned table required
`tenant_session_scope()` shows up as an unclassified violation, not a
silent pass, and adding a genuinely new global/system exception requires
a deliberate, reviewed edit to this file (the same "audited baseline"
discipline `.secrets.baseline` already uses elsewhere in this repository).

**What this control does not do** -- stated once, precisely, rather than
left implicit: it does not itself prove that a `tenant_session_scope()`
call site passes the *correct* `tenant_id`, that a raw SQL string
embedded in an otherwise-compliant block is safe (already separately
guarded -- `text` is not exported from `saas_os.infra.db` at all,
`tests/infra/test_db_public_surface_unit.py`), or that RLS is actually
enabled on every table this repository believes is tenant-owned (that is
`tests/core/tenancy/test_tenant_isolation_integration.py`'s job, against
a real disposable PostgreSQL instance -- this file's checks are pure,
static, and need no database). Static analysis proves *which entry point
a call site reaches*; it cannot prove runtime correctness of what happens
once inside it. RLS remains the actual last line of defense; this file
is architecture-review automation sitting in front of it, not a
replacement for it.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_SCANNED_ROOTS = ("saas_os/core", "saas_os/control_plane", "products", "saas_os/api")
_EXCLUDED_PATH_PARTS = {"__pycache__", "tests", "migrations"}


@dataclass(frozen=True)
class SessionScopeCallSite:
    path: str
    lineno: int
    qualname: str


def _callee_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _walk_function_stack(
    node: ast.AST,
    stack: list[str],
    path: str,
    results: list[SessionScopeCallSite],
    callee: str = "session_scope",
) -> None:
    for child in ast.iter_child_nodes(node):
        next_stack = stack
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
            next_stack = [*stack, child.name]
        if isinstance(child, ast.Call) and _callee_name(child) == callee:
            qualname = ".".join(stack) if stack else "<module>"
            results.append(SessionScopeCallSite(path=path, lineno=child.lineno, qualname=qualname))
        _walk_function_stack(child, next_stack, path, results, callee)


def _find_call_sites(root: Path, callee: str) -> list[SessionScopeCallSite]:
    """Every call to the exact identifier `callee` under `root`'s scanned
    subtrees -- the one scanner behind both the `session_scope()` allowlist
    and the `bind_tenant_scope()` caller pin below."""
    results: list[SessionScopeCallSite] = []
    for root_name in _SCANNED_ROOTS:
        root_dir = root / root_name
        if not root_dir.exists():
            continue
        for py_file in sorted(root_dir.rglob("*.py")):
            if _EXCLUDED_PATH_PARTS & set(py_file.relative_to(root).parts):
                continue
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            rel_path = py_file.relative_to(root).as_posix()
            _walk_function_stack(tree, [], rel_path, results, callee)
    return results


def _find_session_scope_call_sites(root: Path) -> list[SessionScopeCallSite]:
    """Pure static analysis, no import/execution of the scanned files:
    every `session_scope(` call under `root`'s scanned subtrees, each
    tagged with the file (relative to `root`, POSIX-separated so the
    result is platform-independent) and its innermost enclosing function.
    Exactly the function under test in both the real-repository scan
    below and the synthetic positive/negative cases -- never duplicated
    logic, so a bug here shows up identically everywhere it is used.
    """
    results: list[SessionScopeCallSite] = []
    for root_name in _SCANNED_ROOTS:
        root_dir = root / root_name
        if not root_dir.exists():
            continue
        for py_file in sorted(root_dir.rglob("*.py")):
            if _EXCLUDED_PATH_PARTS & set(py_file.relative_to(root).parts):
                continue
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
            rel_path = py_file.relative_to(root).as_posix()
            _walk_function_stack(tree, [], rel_path, results)
    return results


# --- The curated allowlist ---------------------------------------------------
#
# Every entry is a (file, function) pair whose classification was verified
# against the actual table it queries and that table's actual migration
# (docs/ADR/0022's own inventory). Grouped by module; each group's comment
# is the classification + the one-line reason, not repeated per function.

_ALLOWLIST: dict[str, dict[str, str]] = {
    # saas_os.core.api_keys is deliberately NOT RLS-scoped (saas_os/infra/db/migrations/
    # versions/3a2522ccb9ea_create_core_api_keys_table.py): a bearer
    # credential must be resolvable by its hash before the caller's
    # tenant is known, and an untenanted query against an RLS-protected,
    # FORCE-enabled table always returns zero rows regardless of which
    # row would have matched. A composite FK onto core.tenant_memberships
    # is this table's substitute integrity guarantee instead. Every
    # function in this module -- not only the lookup -- was reviewed and
    # accepted to use the same untenanted entry point (module docstring).
    # Foundation Authority & Evidence (ADR-0031): the key mutations
    # (create/revoke/rotate) now run under `tenant_session_scope()` so the
    # audit entry -- RLS-scoped -- is written in the same transaction, and
    # are therefore no longer plain `session_scope()` call sites.
    "saas_os/core/api_keys/service.py": {
        "validate_api_key": "global-by-design: resolved by hash before tenant is known",  # pragma: allowlist secret
        "get_api_key": "global-by-design: core.api_keys is not RLS-scoped",  # pragma: allowlist secret
        "list_api_keys": "global-by-design: core.api_keys is not RLS-scoped",  # pragma: allowlist secret
        "purge_tenant_api_keys": "global-by-design: tenant_id is an explicit predicate here",  # pragma: allowlist secret
        "purge_user_api_keys_in_tenant": "global-by-design: core.api_keys not RLS-scoped",  # pragma: allowlist secret
    },
    # core.billing_plans is a non-RLS catalog (ADR-0022 amendment): owned
    # Catalog v2 plans are read and written only under tenant_session_scope()
    # in saas_os/core/billing/catalog.py, behind the eligibility predicate. These two
    # are the legacy key namespace (unowned plans), which has no tenant.
    # core.billing_subscriptions is the tenant-owned table and already uses
    # tenant_session_scope() throughout.
    "saas_os/core/billing/service.py": {
        "create_plan": "legacy catalog: an unowned legacy plan has no tenant",
        "get_plan": "legacy catalog: key lookup in the unowned legacy namespace",
        "entitlement_maps_for": "global catalog lookup only; subscription read is tenant-scoped",
    },
    # core.billing_provider_refs is global-by-design (ADR-0022 2026-10-01
    # amendment; ADR-0029): a provider object must be resolvable to its
    # owning tenant before that tenant is known. References only; the
    # local row is then read via tenant_session_scope() for the resolved
    # tenant (saas_os/core/billing/commercial.py::get_subscription_by_provider_ref).
    "saas_os/core/billing/provider_refs.py": {
        "register_provider_ref": "global-by-design: core.billing_provider_refs is not RLS-scoped",
        "_lookup": "global-by-design: provider ref resolved before the tenant is known",
        "find_provider_object_ref": "global-by-design: bounded recovery lookup, tenant-filtered",
    },
    # saas_os.core.feature_flags is a global flag-definition catalog (no
    # tenant_id) -- core.feature_flag_tenant_overrides is the tenant-owned
    # table and already uses tenant_session_scope() throughout.
    # ADR-0045 Phase C: platform operations run in one transaction opened
    # with no tenant bound. Platform tables are read and written there;
    # tenant-owned rows only inside a pinned `bind_tenant_scope` block
    # (ADR-0045 section 9c; `_BIND_TENANT_SCOPE_CALLERS` below).
    "saas_os/core/billing/oversight.py": {
        "commercial_overview": "platform oversight: authorize and audit untenanted, then bind per tenant",
    },
    "saas_os/core/identity/user_authority.py": {
        "revoke_user_sessions.body": "platform operation on global core.users/core.sessions",
        "revoke_user_api_keys.body": "platform operation on global core.users/core.api_keys",  # pragma: allowlist secret
        "deactivate_user.body": "platform operation: owners lock, registry scan, global core.users",
        "reactivate_user.body": "platform operation on global core.users and its credentials",
        "refuse_erasure_of_enrolled_operator": "ADR-0045 s6: operator enrollment, global platform tables",
    },
    "saas_os/core/tenancy/registry.py": {
        "list_tenant_registry": "platform oversight of the global registry: core.tenants has no RLS",
        "read_tenant_registry_entry": "platform oversight of the global registry: core.tenants has no RLS",
    },
    "saas_os/core/feature_flags/service.py": {
        "set_tenant_override._attempt": "platform operation: authorize and audit untenanted, then bind",
        "remove_tenant_override": "platform operation: authorize and audit untenanted, then bind",
        "create_flag": "global catalog: core.feature_flags has no tenant_id",
        "get_flag": "global catalog: core.feature_flags has no tenant_id",
        "list_flags": "global catalog: core.feature_flags has no tenant_id",
        "evaluate_flag": "global catalog lookup only; override read uses tenant_session_scope()",
    },
    # core.login_transactions has no tenant_id: an OIDC login transaction
    # exists before any user or tenant is known (saas_os/core/identity/
    # login_transactions.py's own module docstring).
    "saas_os/core/identity/login_transactions.py": {
        "begin_login_transaction": "global: no tenant_id (pre-authentication)",
        "consume_login_transaction": "global: no tenant_id (pre-authentication)",
        "purge_expired_login_transactions": "global: no tenant_id (pre-authentication)",
    },
    "saas_os/core/identity/service.py": {
        "create_user": "global identity: core.users has no tenant_id",
        "get_user": "global identity: core.users has no tenant_id",
        "find_external_identity": "global identity: core.external_identities has no tenant_id",
        "link_external_identity": "global identity: core.external_identities has no tenant_id",
        "purge_user_external_identities": "global identity: no tenant_id on this table",
    },
    # core.sessions has no tenant_id (docs/MULTI-TENANCY.md: "core.sessions
    # is global identity infrastructure, not tenant-owned data -- no
    # tenant_id column, no RLS policy").
    "saas_os/core/identity/session_retention.py": {
        "_delete_one_batch": "global identity: core.sessions has no tenant_id",
    },
    "saas_os/core/identity/sessions.py": {
        "issue_session": "global identity: core.sessions has no tenant_id",
        "validate_session": "global identity: core.sessions has no tenant_id",
        "revoke_session": "global identity: core.sessions has no tenant_id",
        "purge_user_sessions": "global identity: core.sessions has no tenant_id",
    },
    # core.tenants is the tenant registry itself -- it cannot be RLS-scoped
    # by app.tenant_id (a tenant cannot scope itself into existence).
    "saas_os/core/rbac/authorization.py": {
        "can": "global registry: reads core.tenants; per-tenant reads use tenant_session_scope()",
    },
    # core.permissions is a global permission catalog (no tenant_id) --
    # core.roles/core.role_permissions/core.membership_roles are the
    # tenant-owned tables and already use tenant_session_scope() throughout
    # (saas_os/core/rbac/service.py's own module docstring).
    "saas_os/core/rbac/service.py": {
        "register_permission": "global catalog: core.permissions has no tenant_id",
        "get_permission": "global catalog: core.permissions has no tenant_id",
        "get_permission_by_id": "global catalog: core.permissions has no tenant_id",
        "list_permissions": "global catalog: core.permissions has no tenant_id",
    },
    # core.tenants and core.tenant_ancestry are the tenant registry/
    # hierarchy structure itself -- "tenant management is itself a
    # platform-level operation, not scoped to 'the current tenant'"
    # (saas_os/core/tenancy/service.py's own module docstring). purge_tenant()'s
    # own tenant-*owned* business-data deletion (PURGE_STEPS) runs in a
    # separate, already tenant_session_scope()-scoped pass
    # (_run_purge_pass); these two call sites only ever touch the Tenant
    # row's own lifecycle bookkeeping.
    "saas_os/core/tenancy/service.py": {
        "get_ancestor_ids": "global registry: core.tenant_ancestry has no RLS",
        "get_ancestor_chain": "global registry: core.tenant_ancestry has no RLS",
        "get_descendant_ids": "global registry: core.tenant_ancestry has no RLS",
        "find_tenants_by_name": "global registry: core.tenants has no RLS",
        "create_tenant": "global registry: a tenant cannot scope itself into existence",
        "move_tenant": "global registry: core.tenants/core.tenant_ancestry have no RLS",
        "get_tenant": "global registry: core.tenants has no RLS",
        "transition_tenant_status": "global registry: lifecycle state on the tenant row itself",
        "purge_tenant": "global registry: tenant row bookkeeping; PURGE_STEPS are tenant-scoped",
        "list_open_tenant_ids": "global registry: core.tenants has no RLS",
    },
    # RE-2 (ADR-0033): the durable outbox dispatcher claims due events across
    # tenants in one transaction, but every core.outbox_events read and write
    # runs inside bind_tenant_scope(session, tenant_id) -- one tenant's RLS
    # scope at a time, the same shape as saas_os/core/rbac/authorization.py::can().
    "saas_os/core/outbox/dispatch.py": {
        "claim_due_events": "per-tenant RLS: each tenant's rows under bind_tenant_scope()",
    },
    # ADR-0045 (ADR-0022 amendment 2026-10-12): the platform-authority tables
    # are global and carry the tenant-context exclusion policy, so they are
    # reachable ONLY from an untenanted session -- inside tenant_session_scope()
    # the database hides them. None of these call sites touches a
    # tenant-owned table, and none enters a tenant scope (the bind_tenant_scope
    # pin below proves the package has no such caller). Reaching these rows is
    # not authorization: each operation authorizes its caller in Core.
    "saas_os/core/platform_authority/authorization.py": {
        "platform_can": "global platform authority: core.users + platform operators/grants only",
    },
    "saas_os/core/platform_authority/service.py": {
        "authority_transaction": "global platform authority: operators, grants, platform audit",
    },
    "saas_os/core/platform_authority/audit.py": {
        "record_platform_refusal": "global platform evidence: core.platform_audit_log only",
        "record_oversight_attempt": "oversight attempt row, committed before the read (ADR-0045 s9d)",
    },
}


def _allowlist_violations(call_sites: list[SessionScopeCallSite]) -> list[SessionScopeCallSite]:
    violations = []
    for site in call_sites:
        approved = _ALLOWLIST.get(site.path, {})
        if site.qualname not in approved:
            violations.append(site)
    return violations


# --- Positive case: the real repository ---------------------------------


def test_every_plain_session_scope_call_site_is_an_approved_global_or_system_operation() -> None:
    """The actual enforcement: scan the real, current repository. Any
    `session_scope()` call site under core/, saas_os/control_plane/,
    products/, or api/ that is not in `_ALLOWLIST` fails this test -- this
    is what makes a *new* tenant-owned access path that mistakenly reaches
    for the untenanted entry point a caught architecture violation, not a
    silent pass.
    """
    call_sites = _find_session_scope_call_sites(REPO_ROOT)
    violations = _allowlist_violations(call_sites)
    assert not violations, (
        "unapproved session_scope() call site(s) found -- either this is a "
        "genuine tenant-owned access path that must use tenant_session_scope() "
        "instead, or it is a legitimate new global/system operation that needs "
        "a reviewed entry added to _ALLOWLIST in this file "
        f"(docs/ADR/0022): {violations}"
    )


def test_allowlist_has_no_stale_entries() -> None:
    """The reverse direction of the same discipline `.secrets.baseline`
    already uses: every curated entry must correspond to a real call site
    in the current repository, so the allowlist cannot silently accumulate
    exceptions for code that no longer exists (which would hide the true
    shape of the exception surface from a future reviewer)."""
    call_sites = _find_session_scope_call_sites(REPO_ROOT)
    found: dict[str, set[str]] = {}
    for site in call_sites:
        found.setdefault(site.path, set()).add(site.qualname)

    stale: list[str] = []
    for path, functions in _ALLOWLIST.items():
        for qualname in functions:
            if qualname not in found.get(path, set()):
                stale.append(f"{path}::{qualname}")
    assert not stale, f"stale _ALLOWLIST entries with no matching call site: {stale}"


def test_lifecycle_and_purge_operations_are_explicitly_classified() -> None:
    """Existing legitimate lifecycle/purge/admin operations continue to
    work, and are not merely absent from the scan by accident: each is
    present in the allowlist with an explicit classification."""
    assert _ALLOWLIST["saas_os/core/tenancy/service.py"]["purge_tenant"]
    assert _ALLOWLIST["saas_os/core/api_keys/service.py"]["purge_tenant_api_keys"]
    assert _ALLOWLIST["saas_os/core/tenancy/service.py"]["transition_tenant_status"]


def test_control_plane_and_products_have_zero_plain_session_scope_call_sites() -> None:
    """Non-vacuous confirmation of the actual, current shape of the
    exception surface (docs/ADR/0022's inventory): every real
    `session_scope()` call site today lives under `core/`, in one of the
    ten files above -- `saas_os/control_plane` (every self-learning
    and approvals service already uses `tenant_session_scope()`
    exclusively), `products/` (currently empty), and `api/` (every route
    goes through a `core`/`control_plane` service, never `saas_os.infra.db`
    directly) contribute none. This would need to change, deliberately,
    in this file's own `_ALLOWLIST`, before a control-plane, product, or
    api call site could ever pass."""
    call_sites = _find_session_scope_call_sites(REPO_ROOT)
    non_core = [site for site in call_sites if not site.path.startswith("saas_os/core/")]
    assert non_core == [], (
        f"expected zero plain session_scope() call sites outside core/, found: {non_core}"
    )


# --- Negative cases: the static rule itself, proven directly ----------------


def test_new_unapproved_tenant_owned_bypass_is_rejected(tmp_path: Path) -> None:
    """A representative tenant-owned repository/service path that
    mistakenly reaches for the untenanted `session_scope()` instead of
    `tenant_session_scope()` must fail the check -- proven against the
    real checker function (`_find_session_scope_call_sites` +
    `_allowlist_violations`), not a reimplementation of its logic, so a
    bug in the real rule shows up here too."""
    fake_core = tmp_path / "saas_os" / "core"
    fake_core.mkdir(parents=True)
    (fake_core / "widgets_service.py").write_text(
        "from saas_os.infra.db import session_scope\n\n"
        "def get_widget(tenant_id, widget_id):\n"
        "    with session_scope() as session:\n"
        "        return session.get(Widget, widget_id)\n",
        encoding="utf-8",
    )

    call_sites = _find_session_scope_call_sites(tmp_path)
    violations = _allowlist_violations(call_sites)

    assert len(call_sites) == 1
    assert call_sites[0].qualname == "get_widget"
    assert violations == call_sites, (
        "a brand-new, never-reviewed session_scope() call site in a "
        "tenant-shaped function must be reported as a violation"
    )


def test_explicitly_approved_global_access_passes(tmp_path: Path) -> None:
    """The mirror image of the case above: a `session_scope()` call site
    that *has* been through review and added to the allowlist is accepted,
    proving the mechanism does not simply reject every use of
    `session_scope()` outright (that would be the "ban all AsyncSession"
    style overreach this phase's own instructions warn against)."""
    fake_core = tmp_path / "saas_os" / "core"
    fake_core.mkdir(parents=True)
    (fake_core / "catalog_service.py").write_text(
        "from saas_os.infra.db import session_scope\n\n"
        "def get_catalog_entry(key):\n"
        "    with session_scope() as session:\n"
        "        return session.get(CatalogEntry, key)\n",
        encoding="utf-8",
    )

    call_sites = _find_session_scope_call_sites(tmp_path)
    local_allowlist = {
        "saas_os/core/catalog_service.py": {"get_catalog_entry": "test fixture: global catalog"}
    }
    violations = [
        site for site in call_sites if site.qualname not in local_allowlist.get(site.path, {})
    ]

    assert len(call_sites) == 1
    assert violations == []


def test_tenant_session_scope_call_sites_are_never_flagged(tmp_path: Path) -> None:
    """A compliant tenant-owned access path -- using
    `tenant_session_scope()`, never the plain, untenanted entry point --
    produces zero findings, so this control never demands an allowlist
    entry for code that was already correct."""
    fake_core = tmp_path / "saas_os" / "core"
    fake_core.mkdir(parents=True)
    (fake_core / "widgets_service.py").write_text(
        "from saas_os.infra.db import tenant_session_scope\n\n"
        "def get_widget(tenant_id, widget_id):\n"
        "    with tenant_session_scope(tenant_id) as session:\n"
        "        return session.get(Widget, widget_id)\n",
        encoding="utf-8",
    )

    call_sites = _find_session_scope_call_sites(tmp_path)
    assert call_sites == []


def test_infra_db_itself_is_never_scanned(tmp_path: Path) -> None:
    """`tenant_session_scope()`'s own implementation legitimately calls
    `session_scope()` internally (`saas_os/infra/db/session.py`) -- this is the
    trusted chokepoint, not a caller subject to the invariant. Proven by
    constructing a synthetic `saas_os/infra/db` and confirming the scanner (whose
    `_SCANNED_ROOTS` never includes `infra`) finds nothing there."""
    fake_infra_db = tmp_path / "saas_os" / "infra" / "db"
    fake_infra_db.mkdir(parents=True)
    (fake_infra_db / "session.py").write_text(
        "def tenant_session_scope(tenant_id):\n"
        "    with session_scope() as session:\n"
        "        yield session\n",
        encoding="utf-8",
    )

    call_sites = _find_session_scope_call_sites(tmp_path)
    assert call_sites == []


def test_tests_directories_are_excluded_from_the_scan(tmp_path: Path) -> None:
    """Test fixtures legitimately use `session_scope()` directly (setup/
    teardown, seeding) without needing an allowlist entry -- this control
    is about production access paths, not test code."""
    fake_tests = tmp_path / "saas_os" / "core" / "tests"
    fake_tests.mkdir(parents=True)
    (fake_tests / "conftest.py").write_text(
        "from saas_os.infra.db import session_scope\n\n"
        "def seed():\n"
        "    with session_scope() as session:\n"
        "        pass\n",
        encoding="utf-8",
    )

    call_sites = _find_session_scope_call_sites(tmp_path)
    assert call_sites == []


# --- bind_tenant_scope(): the callers are pinned --------------------------
#
# ADR-0022 amendment (2026-10-12) left open whether this test should pin the
# callers of `bind_tenant_scope()`. Decided for ADR-0045 Phase B: it does.
#
# `bind_tenant_scope(session, tenant_id)` re-scopes a transaction that is
# already open to one tenant. From an untenanted `session_scope()` it is the
# only way code can reach tenant-owned rows without `tenant_session_scope()`,
# and the allowlist above does not see it. A new caller is therefore a
# reviewed decision, exactly like a new `session_scope()` call site.
#
# This is static evidence about which functions call it. It does not prove
# what they do inside the scope; the PostgreSQL isolation tests do that.

_BIND_TENANT_SCOPE_CALLERS: dict[str, dict[str, str]] = {
    # ADR-0045 Phase C (section 9c): a platform operation's one transaction
    # enters a tenant scope only for the tenant-owned rows it must touch --
    # the dual-evidence audit row, the fixed oversight projection, the
    # membership existence query of the deactivation scan -- and never
    # reads or writes a platform table inside the block.
    "saas_os/core/tenancy/authority.py": {
        "record_tenant": "dual evidence: one row in the affected tenant's own audit trail",
        "caller_is_member_of_any": "move_tenant: is the caller a member of the new parent's chain",
    },
    "saas_os/core/feature_flags/service.py": {
        "set_tenant_override._attempt": "the override row and its tenant audit row",
        "remove_tenant_override": "the override row and its tenant audit row",
    },
    "saas_os/core/api_keys/service.py": {
        "record_platform_key_revocations": "dual evidence: one row per revoked key, in its tenant",  # pragma: allowlist secret
    },
    "saas_os/core/identity/user_authority.py": {
        "_scan_active_memberships": "deactivate_user: membership existence, one tenant at a time",
    },
    "saas_os/core/billing/oversight.py": {
        "_tenant_subscriptions": "commercial overview: the fixed projection, one tenant at a time",
    },
    "saas_os/core/rbac/authorization.py": {
        "_tenant_grants_permission": "can(): role grants at one candidate tenant",
        "_tenant_grants_permission_for_service_account": "can(): service-account role grants",
        "_tenant_grants_permission_via_delegation": "can(): delegation grants",
        "_tenant_denies_permission": "can(): deny grants",
        "_tenant_grants_support_access": "can(): approved support-access requests",
    },
    "saas_os/core/rbac/administrators.py": {
        "find_administrator": "ADR-0043 guard: active members of one guarded tenant",
        "_is_active_member": "ADR-0043 guard: membership existence in one guarded tenant",
    },
    "saas_os/core/identity/service.py": {
        "lock_membership": "can(): the consulted membership row, FOR SHARE",
        "lock_service_account_status": "can(): the acting service account's status",
    },
    "saas_os/core/outbox/dispatch.py": {
        "claim_due_events": "outbox dispatcher: each tenant's own due events",
    },
    "saas_os/core/billing/catalog.py": {
        "evaluate_plan_eligibility": "catalog eligibility: the plan owner's offers",
    },
    "saas_os/core/billing/commercial.py": {
        "_commercial_context": "billing: payer and merchant rows of the commercial parties",
        "_cancellation_authority": "billing: the payer's account for a cancellation",
    },
    "saas_os/core/billing/projections.py": {
        "_canonical_snapshot": "billing projections: the service tenant's subscription",
    },
    "saas_os/core/usage/reporting.py": {
        "_usage_totals": "usage reporting: one tenant's usage events",
        "merchant_subscription_usage.sold": "usage reporting: the merchant's sold subscriptions",
    },
}


def _bind_callers() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for site in _find_call_sites(REPO_ROOT, "bind_tenant_scope"):
        found.setdefault(site.path, set()).add(site.qualname)
    return found


def test_every_bind_tenant_scope_caller_is_pinned() -> None:
    """A new function that enters a tenant scope from inside an open
    transaction fails here until it is reviewed and added."""
    unapproved = {
        path: sorted(names - set(_BIND_TENANT_SCOPE_CALLERS.get(path, {})))
        for path, names in _bind_callers().items()
        if names - set(_BIND_TENANT_SCOPE_CALLERS.get(path, {}))
    }
    assert not unapproved, (
        "unreviewed bind_tenant_scope() caller(s): entering a tenant scope inside an open "
        f"transaction needs a reviewed entry in _BIND_TENANT_SCOPE_CALLERS: {unapproved}"
    )


def test_bind_tenant_scope_pin_has_no_stale_entries() -> None:
    found = _bind_callers()
    stale = {
        path: sorted(set(names) - found.get(path, set()))
        for path, names in _BIND_TENANT_SCOPE_CALLERS.items()
        if set(names) - found.get(path, set())
    }
    assert not stale, f"pinned bind_tenant_scope() caller(s) no longer exist: {stale}"


def test_every_pinned_bind_caller_has_a_justification() -> None:
    for path, names in _BIND_TENANT_SCOPE_CALLERS.items():
        for name, reason in names.items():
            assert reason.strip(), (path, name)


def test_platform_authority_never_enters_a_tenant_scope() -> None:
    """ADR-0045 Phase B reads and writes platform tables only. It has no
    oversight read, no dual evidence and no deactivation scan, so nothing
    in the package may bind a tenant scope or open a tenant session. (The
    phases that add those callers must add them here, reviewed.)"""
    package = "saas_os/core/platform_authority/"
    for callee in ("bind_tenant_scope", "tenant_session_scope"):
        offenders = [
            (site.path, site.qualname)
            for site in _find_call_sites(REPO_ROOT, callee)
            if site.path.startswith(package)
        ]
        assert offenders == [], (callee, offenders)
    assert not any(path.startswith(package) for path in _BIND_TENANT_SCOPE_CALLERS)


def test_bind_caller_scan_detects_a_new_caller(tmp_path: Path) -> None:
    """Non-vacuousness: the real scanner finds a `bind_tenant_scope()` call
    in a synthetic tree, tagged with its enclosing function."""
    module = tmp_path / "saas_os" / "core" / "newthing" / "service.py"
    module.parent.mkdir(parents=True)
    module.write_text(
        "from saas_os.infra.db import bind_tenant_scope, session_scope\n\n\n"
        "def read_across_tenants(tenant_ids):\n"
        "    with session_scope() as session:\n"
        "        for tenant_id in tenant_ids:\n"
        "            with bind_tenant_scope(session, tenant_id):\n"
        "                pass\n",
        encoding="utf-8",
    )
    sites = _find_call_sites(tmp_path, "bind_tenant_scope")
    assert [(site.path, site.qualname) for site in sites] == [
        ("saas_os/core/newthing/service.py", "read_across_tenants")
    ]
    assert "saas_os/core/newthing/service.py" not in _BIND_TENANT_SCOPE_CALLERS
