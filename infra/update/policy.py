"""The auto-update safety policy -- the single auditable location that
decides which SaaS-OS changes a consumer may take automatically
(docs/AUTO-UPDATE-CLI.md; ADR-0015 "Amendment: consumer update tooling").

Classification is by changed path only, never by commit message: each path
of the diff between the consumer's pinned SHA and the candidate SHA gets the
category of the FIRST rule below whose pattern matches it (`fnmatch`,
case-sensitive, `*` also matches `/`). A path no rule matches is `unknown`.
Only `AUTOMATIC_CATEGORIES` may be applied without human review; every
other category -- including `unknown` -- requires review.

The policy is code in the *installed* SaaS-OS that runs the updater. The
updater never reads a policy from the candidate revision, and a candidate
that changes the updater itself (`infra/update/`) is classified
`updater_policy` and requires review: a newer revision can never approve
its own, possibly weaker, policy.

Changing anything here is a change to the automatic-approval rules: bump
`POLICY_VERSION` and take it through normal human review.
"""

from __future__ import annotations

import enum
import hashlib
import json
from fnmatch import fnmatchcase

POLICY_VERSION = "1"


class Category(enum.StrEnum):
    UPDATER_POLICY = "updater_policy"
    MIGRATION = "migration"
    TENANT_RLS = "tenant_rls"
    PROVIDER_BOUNDARY = "provider_boundary"
    BILLING = "billing"
    AUTHORIZATION = "authorization"
    ARCHITECTURE = "architecture"
    DEPENDENCY_TOOLCHAIN = "dependency_toolchain"
    PUBLIC_API = "public_api"
    TESTS = "tests"
    DOCUMENTATION = "documentation"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


# Ordered: the first matching rule wins, so the most security-sensitive
# rules come first and a broad rule (`core/*` -> internal) never shadows a
# narrow one.
RULES: tuple[tuple[Category, tuple[str, ...]], ...] = (
    (Category.UPDATER_POLICY, ("infra/update/*",)),
    (
        Category.MIGRATION,
        ("infra/db/migrations/*", "infra/db/migration_*.py", "alembic.ini"),
    ),
    (
        Category.TENANT_RLS,
        (
            "infra/db/rls.py",
            "infra/db/session.py",
            "infra/db/role_guard.py",
            "infra/db/engine.py",
            "core/tenancy/*",
        ),
    ),
    (
        Category.PROVIDER_BOUNDARY,
        (
            "core/billing/provider.py",
            "core/billing/provider_refs.py",
            "core/billing/stripe_provider.py",
            "infra/secrets/*",
            "infra/local_identity/*",
        ),
    ),
    (Category.BILLING, ("core/billing/*", "core/usage/*")),
    (
        Category.AUTHORIZATION,
        (
            "core/authority/*",
            "core/rbac/*",
            "core/identity/*",
            "core/api_keys/*",
            "core/audit_log/*",
            "core/crypto/*",
            "api/auth/*",
            "api/dependencies.py",
            "control-plane/control_plane/data_authorization/*",
            "control-plane/control_plane/approvals/*",
            "control-plane/control_plane/tools/*",
        ),
    ),
    (
        Category.ARCHITECTURE,
        ("docs/ADR/*", "docs/ARCHITECTURE*.md", "docs/architecture/*", "CLAUDE.md"),
    ),
    (
        Category.DEPENDENCY_TOOLCHAIN,
        (
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements*.txt",
            "requirements/*",
            "*.lock",
            ".github/*",
            "scripts/*",
            "Dockerfile*",
            "docker-compose*.yml",
            ".pre-commit-config.yaml",
            ".secrets.baseline",
        ),
    ),
    (
        Category.PUBLIC_API,
        (
            "contracts/*",
            "api/*",
            "core/__init__.py",
            "core/*/__init__.py",
            "infra/__init__.py",
            "infra/*/__init__.py",
            "control-plane/control_plane/__init__.py",
            "control-plane/control_plane/*/__init__.py",
        ),
    ),
    (Category.TESTS, ("tests/*", "conftest.py", "examples/*")),
    (Category.DOCUMENTATION, ("docs/*", "*.md", "LICENSE*")),
    (Category.INTERNAL, ("core/*", "infra/*", "control-plane/*")),
)

# The only categories an update may apply without human review. Everything
# else -- migrations, RLS/tenancy, authorization, billing, provider
# boundaries, architecture/ADRs, dependencies/toolchain, public API surface,
# the updater's own policy, and anything unknown -- requires review.
AUTOMATIC_CATEGORIES: frozenset[Category] = frozenset(
    {Category.DOCUMENTATION, Category.TESTS, Category.INTERNAL}
)


def classify(path: str) -> Category:
    """The category of one repository-relative POSIX path."""
    for category, patterns in RULES:
        if any(fnmatchcase(path, pattern) for pattern in patterns):
            return category
    return Category.UNKNOWN


def requires_review(category: Category) -> bool:
    return category not in AUTOMATIC_CATEGORIES


def policy_digest() -> str:
    """A stable digest of the whole policy (version, ordered rules and
    automatic categories), recorded in every report so a decision can be
    reproduced against exactly the policy that made it."""
    canonical = json.dumps(
        {
            "version": POLICY_VERSION,
            "rules": [[category.value, list(patterns)] for category, patterns in RULES],
            "automatic": sorted(category.value for category in AUTOMATIC_CATEGORIES),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
