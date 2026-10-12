"""Products.

The Product-layer boundary this repository defines but does not fill: where
one SaaS product's domain models, UI, business rules, and integrations would
live if built inside this repository. See docs/ARCHITECTURE.md sections 1, 8.

Boundary rules (docs/ARCHITECTURE.md section 2, docs/ADR/0001-...):
- products MAY depend on `core` and `infra` (through their public interfaces).
- products MUST NOT depend on each other directly.
- product-specific code MUST remain under `products/`, never inside `core/`.

Per docs/ADR/0015-... (Accepted), real business products (Dograh included)
are NOT built inside this repository: they live in their own repositories
and consume SaaS-OS as an external package dependency. This package remains
an empty placeholder that exists solely as an import-linter boundary target
(docs/IMPLEMENTATION-ROADMAP.md Phase 1.1) -- not a staging area for a
future in-repo product.
"""

from saas_os.core import CORE_MARKER

PRODUCTS_MARKER = "products"

__all__ = ["PRODUCTS_MARKER", "CORE_MARKER"]
