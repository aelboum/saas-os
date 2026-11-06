"""Audit identity phase P1: who may touch the audit subject link tables, and
which platform writers may name a user target (owner decision O11 of
2026-11-03, interim: "API/code enforcement plus architecture tests are
acceptable temporarily"; owner decisions D6 and OD-2).

`core.platform_audit_subject_links` is the only place that turns a reference
in a platform audit row back into a user. The application role can read it
(the database does not restrict that), so the code that may name the tables
or import their models is a short, pinned list. A new module that needs the
tables, and a new platform writer that targets a user, must be added here
deliberately.

Two checks, each with a negative control that feeds a violating source to
the same scanner:

1. only the modules in `_LINK_TABLE_MODULES` import the link models or name
   the tables;
2. every platform audit call whose `target_type` is `user` passes
   `target_user_id` and never a `target_id`, at the call sites pinned in
   `_USER_TARGET_CALL_SITES`; and no platform writer builds a `target_id`
   from `str(<...user_id>)`, or puts a `user_id` key in operator-event
   metadata (it is `user_subject_ref`).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = REPO_ROOT / "saas_os"

# Modules (relative to the repository root) that may import the link-table
# models or name the tables, with the reason. The Alembic revisions are
# schema, not code that reads the table.
_LINK_TABLE_MODULES = {
    "saas_os/core/platform_authority/subject_models.py": "the models themselves",
    "saas_os/core/platform_authority/subjects.py": "get-or-create and the erasure step",
    "saas_os/core/tenancy/isolation.py": "the isolation classification registry (data)",
    "saas_os/core/tenancy/retention.py": "the retention classification registry (data)",
}
_LINK_TABLE_NAME = re.compile(
    r"platform_audit_subject_links|platform_audit_subject_erasures|platform_audit_identity_holds"
    r"|PlatformAuditSubjectLink|PlatformAuditSubjectErasure|PlatformAuditIdentityHold"
    r"|subject_models"
)
_MIGRATIONS = "saas_os/infra/db/migrations/"

# Every call in `saas_os` that records a platform audit row about a user, as
# (module, enclosing function). Each passes `target_user_id`.
_USER_TARGET_CALL_SITES = {
    ("saas_os/core/identity/user_authority.py", "_record_outcome"),
    ("saas_os/core/identity/user_authority.py", "_record_success"),
    ("saas_os/core/identity/user_authority.py", "remove_identity_links_unless_enrolled_operator"),
    ("saas_os/core/identity/user_authority.py", "resolve_user"),
    ("saas_os/core/platform_authority/service.py", "enroll_operator"),
}
_USER_TARGET_NAMES = {"_TARGET_USER", "USER_TARGET_TYPE"}


def _sources() -> dict[str, str]:
    return {
        path.relative_to(REPO_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(PACKAGE.rglob("*.py"))
    }


def link_table_violations(sources: dict[str, str]) -> list[str]:
    return sorted(
        f"{path}: names a link table or imports its models"
        for path, text in sources.items()
        if path not in _LINK_TABLE_MODULES
        and not path.startswith(_MIGRATIONS)
        and _LINK_TABLE_NAME.search(text)
    )


def test_only_the_reference_modules_name_the_link_tables() -> None:
    assert link_table_violations(_sources()) == []


def test_every_pinned_module_exists_and_uses_the_tables() -> None:
    sources = _sources()
    for path in _LINK_TABLE_MODULES:
        assert path in sources, f"{path} no longer exists: update the pin"
        assert _LINK_TABLE_NAME.search(sources[path]), f"{path} no longer needs the tables"


def test_negative_control_a_module_importing_the_models_is_reported() -> None:
    sources = dict(_sources())
    sources["saas_os/core/other/lookup.py"] = (
        "from saas_os.core.platform_authority.subject_models import PlatformAuditSubjectLink\n"
    )
    assert link_table_violations(sources) == [
        "saas_os/core/other/lookup.py: names a link table or imports its models"
    ]
    sources["saas_os/core/other/lookup.py"] = 'TABLE = "core.platform_audit_subject_links"\n'
    assert len(link_table_violations(sources)) == 1


# --- user targets ---------------------------------------------------------------


def _is_user_type(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return node.value == "user"
    return isinstance(node, ast.Name) and node.id in _USER_TARGET_NAMES


def _enclosing_functions(tree: ast.Module) -> dict[int, str]:
    owner: dict[int, str] = {}
    for function in ast.walk(tree):
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(function):
                owner[id(node)] = function.name  # the innermost wins (walk order)
    return owner


def user_target_findings(sources: dict[str, str]) -> tuple[set[tuple[str, str]], list[str]]:
    """`(call sites, problems)`: every call with `target_type` naming the
    user type, and what is wrong with each."""
    sites: set[tuple[str, str]] = set()
    problems: list[str] = []
    for path, text in sources.items():
        if path.startswith(_MIGRATIONS):
            continue
        tree = ast.parse(text)
        owner = _enclosing_functions(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            target_type = keywords.get("target_type")
            if target_type is None or not _is_user_type(target_type):
                continue
            site = (path, owner.get(id(node), "<module>"))
            sites.add(site)
            if "target_id" in keywords:
                problems.append(f"{site}: a user target passes target_id")
            if "target_user_id" not in keywords:
                problems.append(f"{site}: a user target passes no target_user_id")
    return sites, problems


def raw_user_id_findings(sources: dict[str, str]) -> list[str]:
    """Writers that build a `target_id` from `str(<...user_id>)`, and
    operator-event metadata carrying a `user_id` key, in the platform
    authority and identity modules."""
    problems: list[str] = []
    for path, text in sources.items():
        if not path.startswith(("saas_os/core/platform_authority/", "saas_os/core/identity/")):
            continue
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.keyword) and node.arg == "target_id":
                value = node.value
                if (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id == "str"
                    and value.args
                    and "user_id" in ast.unparse(value.args[0])
                ):
                    problems.append(f"{path}:{node.value.lineno}: target_id = {ast.unparse(value)}")
            if (
                path == "saas_os/core/platform_authority/service.py"
                and isinstance(node, ast.Dict)
                and any(isinstance(k, ast.Constant) and k.value == "user_id" for k in node.keys)
            ):
                problems.append(f"{path}:{node.lineno}: operator-event metadata has a user_id key")
    return problems


def test_the_user_target_call_sites_are_the_pinned_ones_and_pass_no_user_id() -> None:
    sites, problems = user_target_findings(_sources())
    assert problems == []
    assert sites == _USER_TARGET_CALL_SITES


def test_no_platform_writer_builds_a_target_id_from_a_user_id() -> None:
    assert raw_user_id_findings(_sources()) == []


def test_negative_control_the_scanners_report_a_raw_user_target() -> None:
    bad = {
        "saas_os/core/identity/other.py": (
            "def f(user_id):\n"
            "    record_platform_refusal(target_type=_TARGET_USER, target_id=str(user_id))\n"
        ),
        "saas_os/core/platform_authority/service.py": "METADATA = {'user_id': 'x'}\n",
    }
    sites, problems = user_target_findings(bad)
    assert sites == {("saas_os/core/identity/other.py", "f")}
    assert len(problems) == 2  # passes a target_id; passes no target_user_id
    findings = raw_user_id_findings(bad)
    assert len(findings) == 2  # str(user_id) as a target_id; a user_id metadata key


# --- permission grant writers -------------------------------------------------------

_GRANT_PLATFORM_WRITERS = (
    "saas_os/core/permission_grants/register.py",
    "saas_os/core/permission_grants/approvals.py",
    "saas_os/core/permission_grants/expiry.py",
    "saas_os/core/permission_grants/retention.py",
)
_REGISTER = "saas_os/core/permission_grants/register.py"


def grant_metadata_user_id_findings(sources: dict[str, str]) -> list[str]:
    """Metadata keys of the permission grant platform writers that end in
    `user_id`: dict literals and `metadata["..."] = ...` stores."""
    problems: list[str] = []
    for path in _GRANT_PLATFORM_WRITERS:
        if path not in sources:
            continue
        for node in ast.walk(ast.parse(sources[path])):
            keys: list[ast.expr | None] = []
            if isinstance(node, ast.Dict):
                keys = list(node.keys)
            elif isinstance(node, ast.Subscript):
                keys = [node.slice]
            for key in keys:
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and key.value.endswith("user_id")
                ):
                    problems.append(f"{path}:{key.lineno}: metadata key {key.value!r}")
    return problems


def register_records_a_reference(sources: dict[str, str]) -> bool:
    """The register's audit writer calls `platform_audit_subject_ref` and
    names the metadata key `user_subject_ref`."""
    tree = ast.parse(sources[_REGISTER])
    calls = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "platform_audit_subject_ref"
        for node in ast.walk(tree)
    )
    keyed = any(
        isinstance(node, ast.Constant) and node.value == "user_subject_ref"
        for node in ast.walk(tree)
    )
    return calls and keyed


def test_permission_grant_platform_writers_put_no_user_id_in_audit_metadata() -> None:
    sources = _sources()
    assert grant_metadata_user_id_findings(sources) == []
    assert "operator_user_id" in sources["saas_os/core/permission_grants/apply.py"], (
        "apply.py still writes tenant audit metadata with a raw id (P3): "
        "update the ledger row in docs/P-ROADMAP.md if that changes"
    )


def test_the_register_records_a_subject_reference() -> None:
    assert register_records_a_reference(_sources())


def test_negative_control_the_grant_scanners_report_a_raw_id_and_a_missing_reference() -> None:
    sources = dict(_sources())
    sources[_REGISTER] = sources[_REGISTER].replace(
        '"user_subject_ref": str(_subject_ref(session, entry.subject_user_id)),',
        '"subject_user_id": str(entry.subject_user_id),',
    )
    assert sources[_REGISTER] != _sources()[_REGISTER]
    assert len(grant_metadata_user_id_findings(sources)) == 2  # the entry row and the replay row
    sources[_REGISTER] = _sources()[_REGISTER].replace(
        "platform_audit_subject_ref(session, user_id=user_id)", "user_id"
    )
    assert not register_records_a_reference(sources)
    sources["saas_os/core/permission_grants/approvals.py"] += (
        "\nMETADATA = {}\nMETADATA['approver_user_id'] = 1\n"
    )
    assert len(grant_metadata_user_id_findings(sources)) == 1
