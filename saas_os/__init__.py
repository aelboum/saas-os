"""SaaS OS -- the single import root of the `saas-os` distribution (docs/ADR/0038-...).

Everything the distribution ships lives under this package: `saas_os.core`,
`saas_os.infra`, `saas_os.api`, `saas_os.contracts` and `saas_os.control_plane`.
The distribution installs no other top-level import name.
"""
