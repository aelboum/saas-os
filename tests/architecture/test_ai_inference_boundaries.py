"""Architecture boundaries of governed AI inference (ADR-0054; R2, Q11).

- The import-linter contracts added for AI inference are kept, and each one
  is shown to break when a forbidden import is written into a real module
  (non-vacuity, same discipline as test_layer_boundaries.py).
- Q11 (settled in AI-D): `saas_os.inference` is the public interface for
  products (F1) and a thin facade; nothing inside SaaS OS imports it (C1);
  products may import it, and may not import the internals directly.
- The inference package performs no network I/O of its own: provider calls go
  through `saas_os.infra.egress`, never a raw HTTP client or socket.
"""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INFERENCE = REPO_ROOT / "saas_os" / "control_plane" / "inference"

PRODUCTS_CONTRACT = "Products do not import the AI inference internals"
INTERNAL_CONTRACT = "Only the inference package uses the AI inference internals"
SDK_CONTRACT = "The AI Control Plane and products do not depend on AI or LLM frameworks"
FACADE_CONTRACT = "SaaS OS never invokes the public AI inference interface"
OPS_CONTRACT = "Operator commands do not use the AI provider adapters"
FACADE = REPO_ROOT / "saas_os" / "inference" / "__init__.py"


def _run_import_linter() -> subprocess.CompletedProcess[str]:
    script = Path(sys.executable).with_name(
        "lint-imports.exe" if sys.platform == "win32" else "lint-imports"
    )
    return subprocess.run(
        [str(script)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def test_ai_inference_contracts_are_kept() -> None:
    result = _run_import_linter()
    for name in (
        PRODUCTS_CONTRACT,
        INTERNAL_CONTRACT,
        SDK_CONTRACT,
        FACADE_CONTRACT,
        OPS_CONTRACT,
    ):
        assert f"{name} KEPT" in result.stdout, result.stdout


@pytest.mark.parametrize(
    ("target", "injected", "contract"),
    [
        (
            REPO_ROOT / "products" / "__init__.py",
            b"\nimport saas_os.control_plane.inference.adapters\n",
            PRODUCTS_CONTRACT,
        ),
        (
            REPO_ROOT / "saas_os" / "control_plane" / "orchestration" / "__init__.py",
            b"\nimport saas_os.control_plane.inference\n",
            INTERNAL_CONTRACT,
        ),
        (
            INFERENCE / "adapters" / "__init__.py",
            b"\nimport anthropic\n",
            SDK_CONTRACT,
        ),
        (
            REPO_ROOT / "products" / "__init__.py",
            b"\nimport openai\n",
            SDK_CONTRACT,
        ),
        (
            REPO_ROOT / "products" / "__init__.py",
            b"\nimport saas_os.control_plane.inference.service\n",
            PRODUCTS_CONTRACT,
        ),
        (
            REPO_ROOT / "saas_os" / "core" / "__init__.py",
            b"\nimport saas_os.inference\n",
            FACADE_CONTRACT,
        ),
        (
            REPO_ROOT / "saas_os" / "infra" / "__init__.py",
            b"\nimport saas_os.inference\n",
            FACADE_CONTRACT,
        ),
        (
            INFERENCE / "__init__.py",
            b"\nimport saas_os.inference\n",
            FACADE_CONTRACT,
        ),
        (
            REPO_ROOT / "saas_os" / "ops" / "__init__.py",
            b"\nimport saas_os.control_plane.inference.adapters\n",
            OPS_CONTRACT,
        ),
    ],
)
def test_each_new_contract_catches_a_forbidden_import(
    target: Path, injected: bytes, contract: str
) -> None:
    original = target.read_bytes()
    try:
        target.write_bytes(original + injected)
        result = _run_import_linter()
        assert result.returncode != 0, result.stdout
        assert f"{contract} BROKEN" in result.stdout, result.stdout
    finally:
        target.write_bytes(original)
    clean = _run_import_linter()
    assert clean.returncode == 0, f"{target} was not restored:\n{clean.stdout}"


def test_the_api_layer_cannot_reach_the_inference_internals() -> None:
    target = REPO_ROOT / "saas_os" / "api" / "__init__.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\nimport saas_os.control_plane.inference\n")
        result = _run_import_linter()
        assert "API does not depend on Products or the AI Control Plane BROKEN" in result.stdout
    finally:
        target.write_bytes(original)
    assert _run_import_linter().returncode == 0


def test_a_product_may_use_the_public_interface() -> None:
    """Positive control (Q11): a product importing the facade keeps every
    contract, although the facade reaches the internals indirectly."""
    target = REPO_ROOT / "products" / "__init__.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\nimport saas_os.inference\n")
        result = _run_import_linter()
        assert result.returncode == 0, result.stdout
    finally:
        target.write_bytes(original)
    assert _run_import_linter().returncode == 0


_FACADE_SOURCES = {
    "saas_os.control_plane.inference",
    "saas_os.control_plane.inference.capabilities",
    "saas_os.control_plane.inference.errors",
    "saas_os.control_plane.inference.permissions",
    "saas_os.control_plane.inference.types",
    "saas_os.control_plane.inference.use_cases",
}


def test_the_public_interface_is_a_thin_facade() -> None:
    """Q11 (F1): the facade imports only the consumer-facing internal
    modules, defines no class, and each function it defines is one
    delegating call with the caller's own arguments -- nothing that could
    skip a step of governed inference."""
    assert importlib.util.find_spec("saas_os.inference") is not None
    tree = ast.parse(FACADE.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module and node.module != "__future__":
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        assert not isinstance(node, ast.ClassDef), node.name
    assert imported - {"uuid"} <= _FACADE_SOURCES, imported
    functions = [n for n in tree.body if isinstance(n, ast.AsyncFunctionDef | ast.FunctionDef)]
    assert {f.name for f in functions} == {"run_inference", "stream_inference"}
    for function in functions:
        body = [
            s
            for s in function.body
            if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
        ]
        assert len(body) == 1, function.name
        statement = body[0]
        assert isinstance(statement, ast.Return | ast.Expr), function.name
        call = statement.value
        assert isinstance(call, ast.Await) and isinstance(call.value, ast.Call), function.name
        target = call.value.func
        assert isinstance(target, ast.Attribute) and target.attr == function.name, function.name
        assert [a.id for a in call.value.args if isinstance(a, ast.Name)] == ["caller"]
        assert {k.arg for k in call.value.keywords} == {"tenant_id", "request"}, function.name
        assert all(
            isinstance(k.value, ast.Name) and k.value.id == k.arg for k in call.value.keywords
        )


def test_the_facade_exposes_no_runtime_or_configuration_seam() -> None:
    import inspect

    import saas_os.inference as facade

    for name in ("run_inference", "stream_inference"):
        parameters = inspect.signature(getattr(facade, name)).parameters
        assert list(parameters) == ["caller", "tenant_id", "request"], name
    configuration = ("create_", "set_", "update_", "confirm_", "revoke_", "read_ai", "grant_")
    assert not any(name.startswith(configuration) for name in facade.__all__)


_NETWORK_ROOTS = {"httpx", "httpcore", "socket", "ssl", "urllib", "http", "aiohttp", "requests"}


# Pure parsing, no I/O: URL validation of the configuration (AI-C).
_NOT_NETWORK = {"urllib.parse"}


def _network_imports(source: str) -> list[str]:
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [
                a.name
                for a in node.names
                if a.name.split(".")[0] in _NETWORK_ROOTS and a.name not in _NOT_NETWORK
            ]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module.split(".")[0] in _NETWORK_ROOTS and node.module not in _NOT_NETWORK:
                found.append(node.module)
    return found


def test_inference_package_does_no_network_io_of_its_own() -> None:
    offenders = {
        str(path.relative_to(REPO_ROOT)): _network_imports(path.read_text(encoding="utf-8"))
        for path in INFERENCE.rglob("*.py")
    }
    assert {path: names for path, names in offenders.items() if names} == {}


def test_the_network_scan_would_catch_a_raw_client() -> None:
    sample = "import httpx\nfrom socket import create_connection\nimport urllib.request\n"
    assert _network_imports(sample) == ["httpx", "socket", "urllib.request"]
