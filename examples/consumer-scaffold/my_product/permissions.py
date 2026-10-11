"""The permissions this product declares into SaaS OS's shared catalog.

A permission is a `(resource, action)` pair. Prefix every resource with
the product's own name so two products, or a product and Core, can never
claim the same pair. Registration is idempotent and is run once per
deployment by `my_product/migrate.py`, after migrations -- never at
import time, because it needs the database.

Registering a permission grants nothing: a tenant's roles receive it
through `saas_os.core.rbac.grant_permission()`, and `saas_os.core.rbac.can()` decides.
"""

from __future__ import annotations

from saas_os.core.rbac import register_permission

ITEMS_RESOURCE = "my_product.items"
READ = "read"

PERMISSIONS: tuple[tuple[str, str], ...] = ((ITEMS_RESOURCE, READ),)


def register_permissions() -> None:
    for resource, action in PERMISSIONS:
        register_permission(resource, action)
