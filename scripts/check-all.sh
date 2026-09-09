#!/usr/bin/env bash
# Runs every fast, deterministic canonical check: backend + frontend +
# security (dependency vulnerability scan + secret scan). See
# check-backend.sh, check-frontend.sh, check-security.sh -- this script adds
# no checks of its own.
#
# Deliberately does NOT run check-docker.sh: Docker image builds take tens
# of seconds and require a running Docker daemon, unlike everything else
# here. Run `bash scripts/check-docker.sh` separately (also run by CI's
# `docker` job). docs/IMPLEMENTATION-ROADMAP.md Phase 1.4.
set -euo pipefail
DIR="$(dirname "$0")"

"$DIR/check-backend.sh"
"$DIR/check-frontend.sh"
"$DIR/check-security.sh"
