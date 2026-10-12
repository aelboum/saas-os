"""`saas-os-edge-config` -- emit SaaS-OS's reusable local-development
single-origin edge configuration (ADR-0024).

Development tooling, never imported by application code. It exists for the
same reason `saas-os-local-identity` does: a consuming project runs it from
its installed `saas-os` dependency instead of copying this repository's
files (ADR-0015). Unlike that tool it provisions nothing and talks to
nothing -- it writes one configuration file, which the project then owns
(ADR-0015 rules 9/10).

    saas-os-edge-config                                # print to stdout
    saas-os-edge-config --output local-dev/Caddyfile   # write a file

Reads no environment variable, handles no secret, and makes no network
call. The emitted file is parameterized by Caddy's own `{$VAR:default}`
substitution (`SAAS_OS_BACKEND_INTERNAL_ORIGIN`,
`SAAS_OS_FRONTEND_INTERNAL_ORIGIN`), so a project whose services are not
named `backend`/`frontend` sets those in its Compose file rather than
editing the file at all.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from saas_os.infra.edge.routing import read_local_edge_caddyfile


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="saas-os-edge-config",
        description="Emit SaaS-OS's reusable local-development single-origin edge "
        "(Caddy) configuration. Development tooling only -- see "
        "docs/ADR/0024-single-origin-application-runtime.md.",
    )
    parser.add_argument(
        "--output",
        help="Write to this path instead of stdout. Refuses to overwrite an existing "
        "file unless --force is given -- the emitted file becomes the project's own.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the --output path if it already exists.",
    )
    args = parser.parse_args(argv)

    content = read_local_edge_caddyfile()
    if args.output is None:
        sys.stdout.write(content)
        return 0

    destination = Path(args.output)
    if destination.exists() and not args.force:
        parser.error(f"{destination} already exists (pass --force to overwrite).")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    print(f"Wrote {destination}. This file is now yours to own and edit.")
    return 0


if __name__ == "__main__":  # pragma: no cover -- console-script entrypoint
    raise SystemExit(main())
