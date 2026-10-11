"""This product's background jobs.

A tenant job is registered with `saas_os.infra.jobs.register_tenant_job`. The
worker then calls the handler only with a payload whose `tenant_id` is a
valid UUID, exposed as `context.tenant_id`; anything else is dead-lettered
without running the handler (ADR-0030). Failures are retried with backoff
and then dead-lettered. Delivery is at-least-once, so a handler must be
idempotent.

Enqueue with:

    await enqueue_job(
        MARK_ITEM_PROCESSED,
        TenantJobPayload(tenant_id=str(tenant_id), data={"item_id": str(item_id)}),
    )

Give every handler a name prefixed with the product's own name: the worker
refuses to start if a product job shares a name with a platform job.

Importing this module registers the jobs, which resolves `REDIS_URL`.
Import it from the worker entrypoint, not from `my_product/__init__.py`.
"""

from __future__ import annotations

import uuid

from my_product.items import mark_item_processed
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload, register_tenant_job


async def my_product_mark_item_processed(
    context: TenantJobContext, payload: TenantJobPayload
) -> None:
    # The tenant comes from the validated context. `payload.data` is
    # product data only and is never used to choose a tenant.
    item_id = uuid.UUID(str(payload.data["item_id"]))
    mark_item_processed(context.tenant_id, item_id)


MARK_ITEM_PROCESSED = my_product_mark_item_processed.__name__

JOB_FUNCTIONS = [register_tenant_job(my_product_mark_item_processed)]
