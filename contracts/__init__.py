"""`contracts` -- the SaaS Product Contract schema and validator
(docs/IMPLEMENTATION-ROADMAP.md Phase 6.1; docs/ARCHITECTURE.md section 9:
"The SaaS Product Contract").

This is the first point at which the Product Contract -- previously only
documented as a specification (`docs/ARCHITECTURE.md` section 9: "No
parser, validator, or runtime for this contract exists yet") -- becomes
real: a schema a product's manifest is validated against.

Layer placement (`docs/ARCHITECTURE.md` section 4's own Module Ownership
table): `contracts/*` is listed as "Cross-cutting (owned by Core
governance)" -- a standalone top-level package, not nested under
`core/`, `infra/`, `control_plane/`, or `products/`. This module is
deliberately a dependency-free leaf: it imports nothing from those four
layers (stdlib only -- `dataclasses`, `json`), so it introduces no new
import-linter edge and needs no change to the existing seven contracts
in `pyproject.toml`'s `[tool.importlinter]`.

Owns: the `ProductContract` schema (`contracts/schema.py`) and
`validate_contract()`, the validator every future product manifest is
checked against. Field catalogs (`contracts/catalog.py`) enumerate the
Core modules, Infrastructure services, and AI Control Plane tools a
contract may legitimately reference, given what actually exists in this
repository as of this phase.

Does NOT own (explicit Non-Goals, deferred to a future phase): contract
*persistence* -- `docs/DATA-ARCHITECTURE.md`'s own `contracts.*` schema
note is written "once implemented," i.e. a future registry, not this
phase's `Files/Modules Affected: contracts/*"` scope; no product exists
yet to author a real contract; no runtime enforcement or consumption of
a contract by Core, the AI Control Plane, or an API gateway (`docs/
AI-CONTROL-PLANE.md` section 10, `docs/API-ARCHITECTURE.md`'s own
`apiRoutes` note -- both describe *future* consumers of this schema).
"""

from contracts.errors import ContractValidationError
from contracts.schema import ProductContract, validate_contract

__all__ = [
    "ProductContract",
    "validate_contract",
    "ContractValidationError",
]
