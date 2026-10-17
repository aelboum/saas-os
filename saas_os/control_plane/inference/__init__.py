"""INTERNAL: the governed AI inference subsystem (ADR-0054, ADR-0055; both
Proposed).

**This package is not a supported API and offers no stability promise.**
Products use the public interface `saas_os.inference` (ADR-0054 Q11, settled
in AI-D), which re-exports the consumer types and the governed entry points
of `service`. Importing this package directly is forbidden to products
(import-linter contract "Products do not import the AI inference internals").

- `adapters`: provider protocol adapters (AI-B, AI-G). Calling one directly
  bypasses every governance step and is **not** a safe way to send data to a
  model provider; only `service` and the conformance tests use them, and the
  operator commands may not (import-linter).
- `config`: provider, model, alias, endpoint-trust and destination-policy
  configuration (platform operations), and the minimum tenant AI policy
  (AI-C).
- `service`, `resolution`, `admission`, `attempts`, `use_cases`, `types`,
  `errors`: governed inference (AI-D) -- caller authority, classification,
  eligibility, entitlement and concurrency admission, pre-send attempt
  evidence, settlement and usage.
- `usage`: the platform read of a tenant's AI usage totals (AI-D).
"""
