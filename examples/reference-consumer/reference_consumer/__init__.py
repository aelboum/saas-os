"""`reference_consumer` -- the ADR-0018 architecture-validation fixture.

Not part of the `saas-os` package (excluded from `pyproject.toml`'s
`[tool.setuptools] packages` and `[tool.importlinter] root_packages` --
it lives under `examples/`, outside every path either config scans), not
a real product, and never distributed. It consumes `saas-os` the same way
a real independent SaaS project would: ordinary package imports
(`core.*`, `infra.*`, `api.platform`, `control_plane.*`) against an
installed `saas-os`, never a source-tree/`sys.path` shortcut into this
repository's own `core/`, `infra/`, etc.

See this directory's own `README.md` and
`docs/ADR/0018-reference-consumer-validation-fixture.md`.
"""
