# Frontend (Next.js) image. Minimal foundation only -- see
# docs/ADR/0011-backend-language-and-toolchain.md ("Frontend: TypeScript +
# Next.js") and docs/DEPLOYMENT-ARCHITECTURE.md. No secret is ever baked
# into this image (docs/ADR/0012-secrets-management.md). frontend/.dockerignore
# keeps a host-local node_modules/.next out of the build context -- without
# it, `COPY . .` below would copy host-built (possibly wrong-platform)
# native modules into the image; verified empirically, Phase 1.4.

# Two stages. `build` installs everything, development dependencies
# included (TypeScript, ESLint, the test runner), and runs `next build`.
# The final stage installs production dependencies only and takes the
# built `.next/` from `build`, so no development dependency -- and no
# advisory that exists only in one -- is present in the image that runs.

# Base image pinned by digest (multi-architecture index) as well as tag: a
# moved tag cannot change what is built. Update procedure:
# docs/SECURITY.md, "Base image digests".
FROM node:22-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da AS build

WORKDIR /app

# Give the pre-existing non-root `node` user (docs/SECURITY.md section 6,
# principle of least privilege) ownership of the (still-empty) app
# directory *before* installing/building, so npm's own output
# (node_modules/, .next/) is node-owned from the start -- avoids a slow
# recursive `chown -R` over the full node_modules tree after the fact
# (measured at 70s+ during Phase 1.4 validation).
RUN chown node:node /app
USER node

# package-lock.json copied alongside package.json so `npm ci` installs
# deterministically from the committed lockfile, not a resolved-on-the-fly
# tree (docs/IMPLEMENTATION-ROADMAP.md Phase 1.4).
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci

COPY --chown=node:node . .

RUN npm run build


FROM node:22-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da

WORKDIR /app
RUN chown node:node /app
USER node

ENV NODE_ENV=production

COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --chown=node:node next.config.mjs ./
COPY --from=build --chown=node:node /app/.next ./.next

CMD ["npm", "start"]
