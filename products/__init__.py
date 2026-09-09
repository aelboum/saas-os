"""Products.

Everything specific to one SaaS product (Dograh, eventually others): domain
models, product UI, product business rules, product integrations. See
docs/ARCHITECTURE.md sections 1, 8.

Boundary rules (docs/ARCHITECTURE.md section 2, docs/ADR/0001-...):
- products MAY depend on `core` and `infra` (through their public interfaces).
- products MUST NOT depend on each other directly.
- product-specific code MUST remain under `products/`, never inside `core/`.

No product packages exist yet (Phase 1.1 is repository foundation only, per
docs/IMPLEMENTATION-ROADMAP.md Phase 1; Dograh onboarding is Phase 7+/later).
"""

from core import CORE_MARKER

PRODUCTS_MARKER = "products"

__all__ = ["PRODUCTS_MARKER", "CORE_MARKER"]
