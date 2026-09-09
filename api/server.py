"""Production ASGI entrypoint (P1.8: docs/DEPLOYMENT-ARCHITECTURE.md
section 7 -- a genuine, long-running HTTP server process, replacing the
prior import-smoke-only `Dockerfile` `CMD`).

Runs the one real FastAPI application this repository has
(`api.main.app`, built by `api.main.create_app()`) -- never a second
application or a parallel server implementation. Host/port/log-level
come from `core.config.get_settings()` -- the settings dataclass already
established in Phase 2.1 for exactly this purpose (`host`/`port`/
`log_level` fields, `HOST`/`PORT`/`LOG_LEVEL` environment variables,
already validated: port range, known log levels) -- no second
configuration mechanism is introduced.

`uvicorn.run()` is called with the `app` object directly, not an import
string: this process is a single application instance (docs/ADR/0010:
Docker Compose + VPS, one instance) with no `workers=`/`reload=`
argument -- both would require an import-string target to re-import the
module in each worker subprocess, neither of which this deployment model
needs. `uvicorn.run()` blocks in the foreground until the process
receives `SIGINT`/`SIGTERM` (Uvicorn's own default signal handling),
running the same `lifespan` `api.main` already defines (P1.2's startup
role guard, P1.4's observability init) exactly as
`tests/api/test_main_lifespan_unit.py`'s `TestClient`-based tests already
exercise it -- a startup-phase exception (e.g. `UnsafeDatabaseRoleError`)
propagates out of `uvicorn.run()` and this process exits non-zero, so an
unsafe role (or any other startup failure) can never result in a
successfully-started, merely-unready process.
"""

from __future__ import annotations

import uvicorn
from core.config import get_settings

from api.main import app


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
