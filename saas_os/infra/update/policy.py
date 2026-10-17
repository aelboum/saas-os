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
that changes the updater itself (`saas_os/infra/update/`) is classified
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

# Policy v3 (docs/ADR/0038-...): every rule moved under the single `saas_os/`
# root. A path in the pre-ADR-0038 layout (`core/...`, `infra/...`, `api/...`)
# matches no rule any more and is therefore `unknown` -- review required.
# Policy v4 (AI-B to AI-H, ADR-0054): the shared egress module is a security
# control, the AI inference package a provider boundary, the platform authority
# package authorization, and the public inference interface public API; all
# require review.
POLICY_VERSION = "4"


class Category(enum.StrEnum):
    UPDATER_POLICY = "updater_policy"
    MIGRATION = "migration"
    TENANT_RLS = "tenant_rls"
    PROVIDER_BOUNDARY = "provider_boundary"
    BILLING = "billing"
    AUTHORIZATION = "authorization"
    SECURITY_CONTROL = "security_control"
    AUTONOMOUS_ORCHESTRATION = "autonomous_orchestration"
    ARCHITECTURE = "architecture"
    DEPENDENCY_TOOLCHAIN = "dependency_toolchain"
    PUBLIC_API = "public_api"
    TESTS = "tests"
    DOCUMENTATION = "documentation"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


# Ordered: the first matching rule wins, so the most security-sensitive
# rules come first and a broad rule (`saas_os/core/*` -> internal) never shadows a
# narrow one.
RULES: tuple[tuple[Category, tuple[str, ...]], ...] = (
    (Category.UPDATER_POLICY, ("saas_os/infra/update/*",)),
    (
        Category.MIGRATION,
        ("saas_os/infra/db/migrations/*", "saas_os/infra/db/migration_*.py", "alembic.ini"),
    ),
    (
        Category.TENANT_RLS,
        (
            "saas_os/infra/db/rls.py",
            "saas_os/infra/db/session.py",
            "saas_os/infra/db/role_guard.py",
            "saas_os/infra/db/engine.py",
            "saas_os/core/tenancy/*",
        ),
    ),
    (
        Category.PROVIDER_BOUNDARY,
        (
            "saas_os/core/billing/provider.py",
            "saas_os/core/billing/provider_refs.py",
            "saas_os/core/billing/stripe_provider.py",
            "saas_os/infra/secrets/*",
            "saas_os/infra/local_identity/*",
            "saas_os/control_plane/inference/*",
        ),
    ),
    (Category.BILLING, ("saas_os/core/billing/*", "saas_os/core/usage/*")),
    (
        Category.AUTHORIZATION,
        (
            "saas_os/core/authority/*",
            "saas_os/core/rbac/*",
            "saas_os/core/platform_authority/*",
            "saas_os/core/identity/*",
            "saas_os/core/api_keys/*",
            "saas_os/core/audit_log/*",
            "saas_os/core/crypto/*",
            "saas_os/api/auth/*",
            "saas_os/api/dependencies.py",
            "saas_os/control_plane/data_authorization/*",
            "saas_os/control_plane/approvals/*",
            "saas_os/control_plane/tools/*",
        ),
    ),
    # Policy v2 (final closure audit, M1): security controls and integrity
    # mechanisms that are not authorization code but whose change can weaken
    # isolation, signing, encryption, replay safety, event durability or
    # abuse limits -- never automatic, however small.
    (
        Category.SECURITY_CONTROL,
        (
            "saas_os/infra/db/init/*",
            "saas_os/infra/db/backup/encryption.py",
            "saas_os/core/webhooks/*",
            "saas_os/core/idempotency/*",
            "saas_os/core/outbox/*",
            "saas_os/infra/ratelimit/*",
            "saas_os/infra/egress/*",
        ),
    ),
    # The control plane's autonomous-execution machinery: tool registry and
    # invocation, the autonomous-development agent, and self-learning /
    # autonomous improvement. (Tools, approvals and data authorization are
    # already `authorization`.)
    (
        Category.AUTONOMOUS_ORCHESTRATION,
        (
            "saas_os/control_plane/orchestration/*",
            "saas_os/control_plane/development/*",
            "saas_os/control_plane/self_learning/*",
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
            "saas_os/contracts/*",
            "saas_os/api/*",
            "saas_os/inference/*",
            "saas_os/core/__init__.py",
            "saas_os/core/*/__init__.py",
            "saas_os/infra/__init__.py",
            "saas_os/infra/*/__init__.py",
            "saas_os/control_plane/__init__.py",
            "saas_os/control_plane/*/__init__.py",
        ),
    ),
    (Category.TESTS, ("tests/*", "conftest.py", "examples/*")),
    (Category.DOCUMENTATION, ("docs/*", "*.md", "LICENSE*")),
    (Category.INTERNAL, ("saas_os/core/*", "saas_os/infra/*", "saas_os/control_plane/*")),
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
