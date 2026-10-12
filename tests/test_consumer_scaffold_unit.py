"""Static checks on the consumer scaffold (`examples/consumer-scaffold/`,
docs/ADR/0039-..., docs/P-ROADMAP.md P3) and on the guide that quotes it.

The scaffold is copied into new products, so the rules the guide states
are checked on the scaffold itself. AST only: the scaffold is never
imported here (that would register its table on this process's shared
ORM metadata); its behavior is proven by
`tests/test_consumer_scaffold_integration.py` from an isolated install.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCAFFOLD = _REPO_ROOT / "examples" / "consumer-scaffold"
_PACKAGE = _SCAFFOLD / "my_product"
_GUIDE = _REPO_ROOT / "docs" / "CONSUMER-GUIDE.md"

# The import names the installed `saas-os` distribution owns (ADR-0038).
_SAAS_OS_ROOTS = {"saas_os"}
_FORBIDDEN_OUTSIDE_MIGRATIONS = {"sqlalchemy", "psycopg", "psycopg2"}


def _modules() -> list[Path]:
    return sorted(p for p in _PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)


def _imported_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


# --- The scaffold is outside the shipped package ---------------------------------


def test_scaffold_is_not_shipped_and_not_a_lint_root() -> None:
    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    shipped = pyproject["tool"]["setuptools"]["packages"]
    assert not [name for name in shipped if name.split(".")[0] == "my_product"]
    assert "my_product" not in pyproject["tool"]["importlinter"]["root_packages"]
    assert not (_SCAFFOLD.parent / "__init__.py").exists()
    assert not (_SCAFFOLD / "__init__.py").exists()


def test_scaffold_declares_no_top_level_package_that_saas_os_owns() -> None:
    top_level = {p.name for p in _SCAFFOLD.iterdir() if p.is_dir()} | {
        p.stem for p in _SCAFFOLD.glob("*.py")
    }
    assert not top_level & _SAAS_OS_ROOTS


# --- Layering ------------------------------------------------------------------------


@pytest.mark.parametrize("path", _modules(), ids=lambda p: p.relative_to(_PACKAGE).as_posix())
def test_scaffold_reaches_the_database_only_through_infra_db(path: Path) -> None:
    if "migrations" in path.relative_to(_PACKAGE).parts:
        return  # Alembic revisions and env.py use SQLAlchemy/Alembic DDL by design.
    assert not _imported_roots(_tree(path)) & _FORBIDDEN_OUTSIDE_MIGRATIONS


@pytest.mark.parametrize("path", _modules(), ids=lambda p: p.relative_to(_PACKAGE).as_posix())
def test_scaffold_never_reaches_into_the_source_tree(path: Path) -> None:
    """Ordinary imports of the installed package only: no `sys.path` edit,
    no import of this repository's `products`/`tests`/`examples`."""
    tree = _tree(path)
    assert not _imported_roots(tree) & {"products", "tests", "examples", "reference_consumer"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "path":
            assert not (isinstance(node.value, ast.Name) and node.value.id == "sys"), path


# --- Routes --------------------------------------------------------------------------


def _permission_dependencies(tree: ast.Module) -> set[str]:
    """Module-level names bound to a `require_permission(...)` call."""
    names: set[str] = set()
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "require_permission"
        ):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def _route_handlers(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    handlers = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and any(
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and isinstance(d.func.value, ast.Name)
            and d.func.value.id == "router"
            for d in node.decorator_list
        ):
            handlers.append(node)
    return handlers


def _depends_targets(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    targets: set[str] = set()
    for default in [*handler.args.defaults, *handler.args.kw_defaults]:
        if (
            isinstance(default, ast.Call)
            and isinstance(default.func, ast.Name)
            and default.func.id == "Depends"
            and default.args
            and isinstance(default.args[0], ast.Name)
        ):
            targets.add(default.args[0].id)
    return targets


def test_every_scaffold_route_is_gated_by_require_permission() -> None:
    tree = _tree(_PACKAGE / "routes.py")
    gates = _permission_dependencies(tree)
    handlers = _route_handlers(tree)
    assert gates and handlers
    for handler in handlers:
        assert _depends_targets(handler) & gates, f"{handler.name} declares no permission"


def test_scaffold_route_handlers_never_read_the_tenant_from_the_path() -> None:
    """The path's `tenant_id` is input to the ingress chain only; a handler
    that took it as a parameter could use it instead of the verified one."""
    for handler in _route_handlers(_tree(_PACKAGE / "routes.py")):
        assert "tenant_id" not in {a.arg for a in handler.args.args + handler.args.kwonlyargs}


# --- Jobs ----------------------------------------------------------------------------


def test_scaffold_jobs_are_registered_through_infra_jobs_with_a_product_prefix() -> None:
    tree = _tree(_PACKAGE / "jobs.py")
    registered = {
        node.args[0].id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"register_tenant_job", "register_system_job"}
        and isinstance(node.args[0], ast.Name)
    }
    assert registered
    assert all(name.startswith("my_product_") for name in registered), registered
    assert "arq" not in _imported_roots(tree)


def test_scaffold_worker_runs_the_platform_entrypoint() -> None:
    tree = _tree(_PACKAGE / "worker.py")
    imports = {
        (node.module, alias.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert ("saas_os.api.worker", "main") in imports
    assert not _imported_roots(tree) & {"arq", "redis"}


# --- Migration -----------------------------------------------------------------------


def test_scaffold_migration_uses_the_shared_rls_helper_and_narrow_grants() -> None:
    (migration,) = (_PACKAGE / "migrations" / "versions").glob("*.py")
    source = migration.read_text(encoding="utf-8")
    assert "tenant_rls_statements(" in source
    for too_wide in ("GRANT ALL", "TRUNCATE", "DEFAULT PRIVILEGES", "TO PUBLIC"):
        assert too_wide not in source, too_wide
    assert not re.search(r"CREATE POLICY|ENABLE ROW LEVEL SECURITY", source), (
        "RLS DDL must come from saas_os.infra.db.rls, not be hand-written"
    )


# --- The guide quotes the scaffold ---------------------------------------------------

_SAMPLE = re.compile(r"<!-- source: (?P<path>\S+) -->\n```python\n(?P<code>.*?)```", re.DOTALL)


def _guide_samples() -> list[tuple[str, str]]:
    return [(m["path"], m["code"]) for m in _SAMPLE.finditer(_GUIDE.read_text(encoding="utf-8"))]


def test_the_guide_has_a_tested_sample_for_every_topic_it_promises() -> None:
    sources = {Path(path).name for path, _ in _guide_samples()}
    assert sources >= {
        "0001_create_items_table.py",  # grants, RLS
        "migrate.py",  # migrations
        "models.py",
        "items.py",
        "permissions.py",
        "app.py",
        "routes.py",
        "jobs.py",
        "worker.py",
        "purge.py",
    }


@pytest.mark.parametrize(("path", "code"), _guide_samples(), ids=lambda v: str(v)[:60])
def test_guide_sample_is_copied_verbatim_from_the_scaffold(path: str, code: str) -> None:
    source_file = _REPO_ROOT / path
    assert _SCAFFOLD in source_file.parents, f"{path} is not a scaffold file"
    assert code in source_file.read_text(encoding="utf-8"), (
        f"docs/CONSUMER-GUIDE.md quotes {path}, but the quoted text is no longer in that file"
    )


def test_every_python_sample_in_the_guide_is_a_marked_scaffold_sample() -> None:
    text = _GUIDE.read_text(encoding="utf-8")
    assert text.count("```python\n") == len(_guide_samples())
