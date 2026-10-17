"""INTERNAL: AI inference configuration (ADR-0054 Phase AI-C).

- `service`: platform operations on the global provider, model, alias,
  endpoint-trust and destination-policy catalog (ADR-0045 platform permissions
  `platform.ai_*`), plus the oversight read.
- `tenant_policy`: the minimum tenant AI policy, written through the tenant
  permission `ai.policy:manage`.

Not a supported consumer API; operators use `saas-os-operator ai-*`.
"""
