# Frontend (Next.js) development image. Minimal foundation only -- see
# docs/ADR/0011-backend-language-and-toolchain.md ("Frontend: TypeScript +
# Next.js") and docs/DEPLOYMENT-ARCHITECTURE.md. No secret is ever baked
# into this image (docs/ADR/0012-secrets-management.md). frontend/.dockerignore
# keeps a host-local node_modules/.next out of the build context -- without
# it, `COPY . .` below would copy host-built (possibly wrong-platform)
# native modules into the image; verified empirically, Phase 1.4.

FROM node:22-slim

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

CMD ["npm", "start"]
