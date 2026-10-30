"""The public import surface of the `saas_os` package, as a reviewable snapshot.

    python scripts/public_api_snapshot.py           # compare with the snapshot
    python scripts/public_api_snapshot.py --write   # rewrite it after a reviewed change

Every `saas_os` package whose `__init__.py` declares `__all__` is public
(ADR-0015, ADR-0038). For each exported name the snapshot records what a
consumer can rely on: a function's signature, a class's bases and the
signatures of its public methods, or that the name is a value. It is built
statically from the source with `ast`, never by importing the package, so
reading it has no side effects (some packages register jobs on import).

`tests/architecture/test_public_api_snapshot.py` fails when the surface
changes. A changed or removed signature is a `0.Y.0` change under ADR-0015's
release labels and needs a changelog entry; an addition is still reviewed.
Update the snapshot only together with that review, never to make the test
pass.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "saas_os"
SNAPSHOT = REPO_ROOT / "tests" / "architecture" / "public_api_snapshot.txt"
# Names like `api_key` or `get_secret` look like credentials to detect-secrets;
# such lines carry its inline allowlist marker (the file holds no secret).
_PRAGMA = "  # pragma: allowlist secret"
_SECRET_WORDS = ("secret", "key", "password", "token", "credential")


def _module_file(module: str) -> Path | None:
    base = REPO_ROOT / Path(*module.split("."))
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(REPO_ROOT).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve(module: str, level: int, package: str) -> str:
    if level == 0:
        return module
    parts = package.split(".")
    base = parts[: len(parts) - level + 1]
    return ".".join([*base, module] if module else base)


def _exported_names(tree: ast.Module) -> list[str] | None:
    for node in tree.body:
        if "__all__" not in _assigned_names(node):
            continue
        value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
        if value is not None:
            return sorted(str(v) for v in ast.literal_eval(value))
    return None


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    returns = f" -> {ast.unparse(node.returns)}" if node.returns is not None else ""
    return f"{prefix} {node.name}({ast.unparse(node.args)}){returns}"


def _describe(node: ast.stmt) -> object:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return _signature(node)
    if isinstance(node, ast.ClassDef):
        bases = ", ".join(ast.unparse(b) for b in node.bases)
        methods = {
            item.name: _signature(item)
            for item in node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and (not item.name.startswith("_") or item.name == "__init__")
        }
        fields = sorted(
            item.target.id
            for item in node.body
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
        )
        described: dict[str, object] = {"class": f"class {node.name}({bases})"}
        if fields:
            described["fields"] = fields
        if methods:
            described["methods"] = dict(sorted(methods.items()))
        return described
    return "value"


def _assigned_names(node: ast.stmt) -> list[str]:
    if isinstance(node, ast.Assign):
        return [t.id for t in node.targets if isinstance(t, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    return []


def _definition(module: str, name: str, seen: set[tuple[str, str]]) -> object:
    """Follow `from x import name` chains to where `name` is defined."""
    if (module, name) in seen:
        return "value"
    seen.add((module, name))
    path = _module_file(module)
    if path is None:
        return "value"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    for node in tree.body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == name
        ):
            return _describe(node)
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if (alias.asname or alias.name) == name:
                    source = _resolve(node.module or "", node.level, package)
                    if not source.startswith("saas_os"):
                        return f"re-export of {source}.{alias.name}"
                    return _definition(source, alias.name, seen)
        if name in _assigned_names(node):
            return "value"
    if _module_file(f"{module}.{name}") is not None:
        return "module"
    return "value"


def build_snapshot() -> dict[str, dict[str, object]]:
    snapshot: dict[str, dict[str, object]] = {}
    for init in sorted(PACKAGE_ROOT.rglob("__init__.py")):
        if "__pycache__" in init.parts or "migrations" in init.parts:
            continue
        names = _exported_names(ast.parse(init.read_text(encoding="utf-8")))
        if names is None:
            continue
        module = _module_name(init)
        snapshot[module] = {name: _definition(module, name, set()) for name in names}
    return snapshot


def render(snapshot: dict[str, dict[str, object]]) -> str:
    """One line per exported name: `<module>.<name> = <JSON description>`."""
    lines = []
    for module in sorted(snapshot):
        for name in sorted(snapshot[module]):
            line = f"{module}.{name} = " + json.dumps(
                snapshot[module][name], sort_keys=True, ensure_ascii=False
            )
            if any(word in line.lower() for word in _SECRET_WORDS):
                line += _PRAGMA
            lines.append(line)
    return "\n".join(lines) + "\n"


def parse(text: str) -> dict[str, dict[str, object]]:
    """The inverse of `render()`."""
    snapshot: dict[str, dict[str, object]] = {}
    for line in text.splitlines():
        if not line:
            continue
        qualified, _, description = line.removesuffix(_PRAGMA).partition(" = ")
        module, _, name = qualified.rpartition(".")
        snapshot.setdefault(module, {})[name] = json.loads(description)
    return snapshot


def main(argv: list[str]) -> int:
    current = render(build_snapshot())
    if argv == ["--write"]:
        SNAPSHOT.write_bytes(current.encode("utf-8"))
        print(f"wrote {SNAPSHOT.relative_to(REPO_ROOT).as_posix()}")
        return 0
    if argv:
        print(__doc__)
        return 2
    committed = SNAPSHOT.read_text(encoding="utf-8") if SNAPSHOT.is_file() else ""
    if committed == current:
        print("public API unchanged")
        return 0
    print("public API differs from tests/architecture/public_api_snapshot.txt")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
