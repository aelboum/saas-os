"""Infrastructure.

Technical plumbing with no business semantics: database access primitives,
job/queue runner, observability, health checks, deployment tooling,
migrations tooling, secrets access. See docs/ARCHITECTURE.md sections 1, 6.

Boundary rules (docs/ARCHITECTURE.md section 2, docs/ADR/0001-...):
- infra MUST NOT import from `products`, `control_plane`, or `core`.
- infra MUST NOT import AI/LLM/agent frameworks (e.g. openai, langchain).
- infra depends on nothing above it in the layer stack.

Enforced by import-linter (pyproject.toml `[tool.importlinter]`), proven
non-vacuous in tests/architecture/test_layer_boundaries.py.
"""

INFRA_MARKER = "infra"
