"""SaaS-OS consumer auto-update tooling (`saas-os-update`; docs/AUTO-UPDATE-CLI.md).

Development and CI tooling, never imported by application code. It moves a
consuming project's exact-SHA SaaS-OS pin (ADR-0015 rules 7-8) to a newer
commit only when the change is classified SAFE by `saas_os.infra.update.policy`,
validates the result, and rolls back on failure. Standard library only; no
network access, no secrets, no hosting-provider API.
"""
