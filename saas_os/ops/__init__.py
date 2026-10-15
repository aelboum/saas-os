"""Operator commands that are not an HTTP capability (ADR-0050).

Nothing here is imported by `saas_os.api`, Core, a product or the AI
Control Plane (import-linter: "Operator commands are imported by nothing").
The commands run with the deployment's own credentials, as the restricted
application role.
"""
