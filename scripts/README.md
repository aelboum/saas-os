# scripts/

Canonical developer validation commands, established in Phase 1.2 and
extended in Phase 1.4 (`docs/IMPLEMENTATION-ROADMAP.md`).
`.github/workflows/ci.yml` runs these same scripts, so there is one
semantic validation process, not a local one and a separate CI one.

- `check-backend.sh` -- ruff check, ruff format --check, pyright, pytest, import-linter
- `check-frontend.sh` -- TypeScript typecheck, ESLint, Next.js build
- `check-security.sh` -- pip-audit, npm audit, detect-secrets
- `check-docker.sh` -- backend + frontend image builds; real backend ASGI-server runtime validation against disposable db/redis (liveness, readiness, a representative route, dependency-failure 503, clean shutdown -- P1.8); `docker compose config`
- `check-migrations.sh` -- migration graph validation + a real clean-PostgreSQL-to-`alembic head` gate (P1.7)
- `check-packaging.sh` -- builds a real, non-editable `saas-os` wheel and proves it ships every nested subpackage and the migration environment, then installs it into an isolated venv (SaaS OS packaging implementation phase)
- `check-all.sh` -- backend + frontend + security, in sequence

`check-all.sh` deliberately excludes `check-docker.sh`,
`check-migrations.sh`, and `check-packaging.sh`: each needs real external
state or a slow subprocess (a running Docker daemon; a reachable,
disposable PostgreSQL instance; a real wheel build + venv, respectively)
and is slower than everything else here, which is fast, deterministic,
and needs no external service. Run any of them explicitly (or via CI's
`docker`/`migrations`/`packaging` jobs) when you need it.

Run with `bash scripts/<name>.sh` from anywhere in the repo (paths are
resolved relative to the script's own location). Backend/security scripts
assume the Python venv from `README.md` is active (or its `bin`/`Scripts`
directory is on `PATH`) with `pip install -e ".[dev,security]"` run;
frontend scripts assume `npm install`/`npm ci` has been run in `frontend/`;
`check-docker.sh` assumes a running Docker daemon and copies
`.env.example` to `.env` if no `.env` exists yet (never overwrites a real
one) so `docker compose config` has something to read; `check-migrations.sh`
assumes `MIGRATIONS_DATABASE_URL`/`DATABASE_URL` already point at a
disposable PostgreSQL instance (its own docstring shows how to start one)
-- it never touches a developer's persistent database.

No bootstrap/deploy scripts exist yet -- those are later phases.
