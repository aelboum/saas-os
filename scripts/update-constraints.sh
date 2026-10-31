#!/usr/bin/env bash
# Regenerates constraints.txt (ADR-0041 amendment of 2026-10-31): the exact
# versions CI and the Dockerfile image install.
#
# Resolves `pip install ".[all,dev,security]"` from a copy of the committed
# pyproject.toml, README.md and saas_os/ inside the Dockerfile's own Python
# image (same digest), so the result is the Linux resolution CI and the
# image use, not the developer's platform. Needs Docker and access to PyPI.
# Writes constraints.txt only; review the diff, run the gates, commit it in
# its own pull request.
set -euo pipefail
cd "$(dirname "$0")/.."

image="$(sed -n 's/^FROM \(python:[^ ]*\).*/\1/p' Dockerfile | head -n 1)"
if [ -z "$image" ]; then
    echo "update-constraints: no python base image found in Dockerfile" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git archive HEAD pyproject.toml README.md saas_os | tar -x -C "$work"
# Git Bash on Windows: Docker needs the Windows form of the temporary path.
mount="$work"
if command -v cygpath >/dev/null 2>&1; then
    mount="$(cygpath -w "$work")"
fi

MSYS_NO_PATHCONV=1 docker run --rm -v "$mount:/src" -w /src "$image" sh -c \
    'python -m venv /v && /v/bin/pip install -q --upgrade pip \
     && /v/bin/pip install -q ".[all,dev,security]" \
     && /v/bin/pip freeze --exclude saas-os --exclude pip > /src/freeze.txt'

{
    sed -n '/^# Exact versions/,/^# satisfies pyproject.toml\.$/p' constraints.txt
    LC_ALL=C sort -f "$work/freeze.txt"
} > "$work/constraints.txt"
mv "$work/constraints.txt" constraints.txt
echo "update-constraints: wrote constraints.txt ($(grep -vc '^#' constraints.txt) packages) from $image"
