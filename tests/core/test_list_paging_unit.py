"""Core's paged lists refuse an invalid page before opening a session (no
database needed). The paging itself, against PostgreSQL, is
`tests/api/v1/test_capability_routers_integration.py::test_list_routes_page_in_the_database_in_a_stable_order`."""

from __future__ import annotations

import uuid

import pytest

from saas_os.core.api_keys import list_api_keys
from saas_os.core.identity.service import list_invitations_for_tenant, list_tenant_members

LISTS = (list_tenant_members, list_invitations_for_tenant, list_api_keys)


@pytest.mark.parametrize("list_function", LISTS)
@pytest.mark.parametrize(("limit", "offset"), [(-1, 0), (10, -1), (1.5, 0), (10, "0")])
def test_an_invalid_page_is_refused_before_any_query(list_function, limit, offset) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        list_function(uuid.uuid4(), limit=limit, offset=offset)
