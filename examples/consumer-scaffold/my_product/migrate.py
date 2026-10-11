"""Apply every migration this deployment needs, in the one valid order.

    python -m my_product.migrate

1. SaaS OS's own history (`alembic_version_saas_os`), through the
   installed package -- never by pointing Alembic at a path inside
   `site-packages`.
2. This product's own history (`alembic_version`). It may reference
   `core.*` tables, so it always runs second (ADR-0016).
3. This product's permissions, registered into the shared catalog.

Steps 1 and 2 connect with `MIGRATIONS_DATABASE_URL` (the privileged
migration role). Step 3 connects with `DATABASE_URL` (the restricted
application role). Run this as a deployment step, before the application
and the worker start; it is safe to run again.
"""

from __future__ import annotations

import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

from my_product.permissions import register_permissions
from saas_os.infra.db import run_core_migrations

_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def migrate() -> None:
    run_core_migrations()
    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS_DIR))
    command.upgrade(config, "head")
    register_permissions()


if __name__ == "__main__":
    migrate()
    sys.exit(0)
