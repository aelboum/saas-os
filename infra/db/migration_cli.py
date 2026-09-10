"""`saas-os-migrate` -- the console-script convenience wrapper around
`infra.db.migration_runner` (docs/ADR/0016-independent-database-migration-histories.md,
Task 4 of the SaaS OS packaging implementation phase).

A consuming project's deploy pipeline runs `saas-os-migrate upgrade`
(ADR-0016's own worked example) instead of importing
`infra.db.migration_runner` itself -- this is the one genuinely public,
documented CLI surface; the importable functions remain the real
implementation (this module contains no migration logic of its own).
Only the operations ADR-0016 actually names are supported --
`upgrade`/`downgrade`/`current` -- not a general-purpose migration
framework (e.g. no `revision`/`stamp`/branch-management subcommands: those
are authoring-time operations for developing SaaS OS's own migrations,
never something a consumer needs).
"""

from __future__ import annotations

import argparse
import sys

from infra.db.migration_runner import (
    current_core_revision,
    downgrade_core_migrations,
    run_core_migrations,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="saas-os-migrate",
        description="Apply or inspect SaaS OS's own core/control_plane/self_learning "
        "migration history (docs/ADR/0016). Never touches a consuming project's own "
        "migrations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    upgrade_parser = subparsers.add_parser("upgrade", help="Apply migrations up to a revision.")
    upgrade_parser.add_argument(
        "revision", nargs="?", default="head", help="Target revision (default: head)."
    )

    downgrade_parser = subparsers.add_parser("downgrade", help="Roll back to a revision.")
    downgrade_parser.add_argument("revision", help='Target revision (e.g. "-1").')

    subparsers.add_parser("current", help="Print the currently applied revision.")

    args = parser.parse_args(argv)

    if args.command == "upgrade":
        run_core_migrations(args.revision)
    elif args.command == "downgrade":
        downgrade_core_migrations(args.revision)
    elif args.command == "current":
        revision = current_core_revision()
        print(revision if revision is not None else "(no migrations applied)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
