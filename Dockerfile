# Backend (core/infra/control-plane/products) development image.
# Minimal, development-oriented foundation per docs/DEPLOYMENT-ARCHITECTURE.md
# and docs/ADR/0010-deployment-target.md (Docker + Docker Compose + VPS).
# NOT a production-hardened image (no multi-stage slimming) -- that is later
# deployment work, not Phase 1.4.
#
# No secret is ever baked into this image (docs/ADR/0012-secrets-management.md):
# all secrets are injected at container runtime via environment variables
# supplied by docker-compose.yml's `env_file: .env` (never committed) or the
# host at deploy time. The build context itself excludes .env/.venv/.git/etc
# via .dockerignore -- verified empirically, docs/IMPLEMENTATION-ROADMAP.md
# Phase 1.4.

FROM python:3.13-slim

WORKDIR /app

# Install build dependencies needed by psycopg[binary]/other wheels only if
# a wheel isn't available for the target platform; kept minimal otherwise.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY core ./core
COPY infra ./infra
COPY control-plane ./control-plane
COPY products ./products
COPY contracts ./contracts
COPY api ./api

# Only the declared runtime dependencies (pyproject.toml [project]
# dependencies) are installed -- the [dev] extra (ruff/pyright/pytest/
# import-linter) is intentionally not installed into this image.
RUN pip install --no-cache-dir -e .

# Run as a non-root user (docs/SECURITY.md section 6 principle of least
# privilege, applied here to the container itself). Ownership is granted
# after all root-only build steps (apt-get, pip install) are done.
RUN groupadd --system app && useradd --system --gid app --home /app app \
    && chown -R app:app /app
USER app

# P1.8: the real, long-running ASGI production entrypoint (api/server.py --
# uvicorn.run(api.main.app, ...), host/port read from core.config.Settings'
# existing HOST/PORT env-var convention, default 0.0.0.0:8000). Replaces
# the prior import-smoke-only placeholder CMD. EXPOSE is documentation of
# the container's own listening port -- it does not by itself publish a
# host port (docker-compose.yml's own `backend` service publishes none).
EXPOSE 8000

# In-container healthcheck. python:3.13-slim has neither curl nor wget
# (verified: `docker run --rm <image> sh -c 'which curl wget'` finds
# neither) -- python itself is already present in every layer this image
# needs regardless, so the stdlib's own `urllib.request` is used instead
# of installing a package solely for this check. Probes `/readyz`
# (readiness, not `/healthz`): a container whose process is alive but
# whose required dependencies (PostgreSQL/Redis) are unreachable should be
# reported unhealthy/taken out of rotation, which only the readiness
# contract (not liveness, P1.8's own liveness/readiness split) expresses.
# A non-2xx response or connection failure raises inside the one-line
# script, which is itself the "fail appropriately" signal HEALTHCHECK
# needs -- no `|| exit 1` required.
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD ["python", "-c", "import os,urllib.request as u; u.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8000') + '/readyz', timeout=3)"]

CMD ["python", "-m", "api.server"]
