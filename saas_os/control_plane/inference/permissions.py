"""Tenant RBAC permissions of the AI inference subsystem (ADR-0054, ADR-0055).

| Resource        | Action   | Allows                                                      |
|-----------------|----------|-------------------------------------------------------------|
| `ai.inference`  | `run`    | Run governed inference in the tenant (AI-D)                 |
| `ai.policy`     | `read`   | Read the tenant's AI policy (AI-C)                          |
| `ai.policy`     | `manage` | Change the tenant's AI policy and preferences (AI-C, AI-E)  |
| `ai.credential` | `manage` | Store or revoke the tenant's own provider credentials (AI-E)|

`ai.inference:run`, `ai.policy:manage` and `ai.credential:manage` are never
satisfied by support access
(`saas_os.core.rbac.authorization.AI_SUPPORT_ACCESS_EXCLUDED_ACTIONS`).
Permissions are registered lazily by `authorize_caller`; a product registers
them up front with `register_ai_permissions()` so roles can be granted them.
"""

from __future__ import annotations

from saas_os.core.rbac import register_permission

AI_INFERENCE = "ai.inference"
AI_POLICY = "ai.policy"
AI_CREDENTIAL = "ai.credential"

AI_PERMISSIONS: tuple[tuple[str, str], ...] = (
    (AI_INFERENCE, "run"),
    (AI_POLICY, "read"),
    (AI_POLICY, "manage"),
    (AI_CREDENTIAL, "manage"),
)


def register_ai_permissions() -> None:
    for resource, action in AI_PERMISSIONS:
        register_permission(resource, action)
