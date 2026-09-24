"""Local-development identity tooling (docs/ADR/0023-..., docs/LOCAL-IDENTITY.md).

Developer tooling only -- never imported by application code, never on any
request path. It ships inside the `saas-os` distribution so a consuming
project can run it from its own installed SaaS-OS dependency (the
`saas-os-local-identity` console script) instead of copying SaaS-OS
repository files (ADR-0015: SaaS-OS is a dependency, not a template).

Adds no dependency of its own: it uses only the standard library and
`httpx`, which is already a runtime dependency (`pyproject.toml`).
"""
