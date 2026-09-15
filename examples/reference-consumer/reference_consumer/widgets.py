"""The reference consumer's one data-access function (PRIV-03 P12, RA-08).

`get_widget()` is the single place the fixture reads its own table, and it
reads it the way every SaaS OS module reads tenant-owned rows: inside
`infra.db.tenant_session_scope(tenant_id)` (Row-Level Security keyed on the
session's tenant), through the ORM model, with an explicit ownership check
on top of RLS -- never a raw SQL string, never an unscoped session.

`tenant_id` must be a *verified* tenant context -- the `RequestContext`
the ingress chain established (`reference_consumer/routes.py`) or the
`ToolExecutionContext` the AI Control Plane authorized
(`reference_consumer/tools.py`) -- never a value taken from a URL or a
payload. A widget that belongs to another tenant, or does not exist,
yields `None`: the caller cannot tell the two apart, by design.
"""

from __future__ import annotations

import uuid

from infra.db import tenant_session_scope
from reference_consumer.models import Widget


def get_widget(tenant_id: uuid.UUID, widget_id: uuid.UUID) -> Widget | None:
    with tenant_session_scope(tenant_id) as session:
        widget = session.get(Widget, widget_id)
        if widget is None or widget.tenant_id != tenant_id:
            return None
        session.expunge(widget)
        return widget
