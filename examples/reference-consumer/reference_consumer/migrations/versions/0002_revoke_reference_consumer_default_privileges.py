"""revoke the reference consumer's default table privileges

Revision ID: 0002_ref_consumer_no_default_acl
Revises: 0001_ref_consumer_widgets
Create Date: 2026-10-30 00:00:00.000000

`0001` also ran `ALTER DEFAULT PRIVILEGES IN SCHEMA reference_consumer GRANT
... ON TABLES`, which `docs/CONSUMER-GUIDE.md` advises against: every later
table in the schema would be readable and writable by the application role
before anyone decided it should be, and before it has an RLS policy. This
revision removes that default, so each table is granted explicitly, as
`widgets` already is. `0001` is not edited: a migration that has run is
never changed; a product in the same position adds a revision like this one.

The explicit grant on `widgets` is untouched.
"""

import os
import re
from collections.abc import Sequence

from alembic import op

revision: str = "0002_ref_consumer_no_default_acl"
down_revision: str | Sequence[str] | None = "0001_ref_consumer_widgets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DEFAULT_APP_ROLE = "saas_os_app"


def _app_role() -> str:
    role = os.environ.get("APP_DB_USER", _DEFAULT_APP_ROLE)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", role):
        raise ValueError(f"APP_DB_USER must be a plain SQL identifier, got: {role!r}")
    return role


def upgrade() -> None:
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA reference_consumer "
        f'REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM "{_app_role()}"'
    )


def downgrade() -> None:
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA reference_consumer "
        f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{_app_role()}"'
    )
