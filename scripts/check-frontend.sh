#!/usr/bin/env bash
# Canonical frontend validation commands. Run locally after `npm install`
# in frontend/ (see README.md), and invoked verbatim by
# .github/workflows/ci.yml so local and CI checks never drift apart.
#
# Covers: docs/IMPLEMENTATION-ROADMAP.md Phase 1.2 frontend CI requirements
# (TypeScript type checking, ESLint, Next.js build), extended in Phase 10.1
# with `npm run test` (Vitest) for the frontend i18n foundation.
set -euo pipefail
cd "$(dirname "$0")/../frontend"

echo "== npm run typecheck =="
npm run typecheck

echo "== npm run lint =="
npm run lint

echo "== npm run test =="
npm run test

echo "== npm run build =="
npm run build
