"""The Product Contract schema and validator
(docs/IMPLEMENTATION-ROADMAP.md Phase 6.1; docs/ARCHITECTURE.md section
9's own 14-field table).

`validate_contract()` takes a raw `dict` (already `json.loads()`-parsed
by the caller -- this module never touches a filesystem or a specific
serialization format itself, since `docs/ARCHITECTURE.md` section 9
explicitly defers "contract file format" to this phase without fixing
it) and returns a `ProductContract`, or raises `ContractValidationError`
carrying every field-level failure found, not just the first.

Only `productName`/`productVersion` are strictly mandatory keys -- every
other field defaults to an empty collection (`[]`) or `None` when
absent, since a minimal product may legitimately use none of a given
capability (e.g. a product with no background workers simply omits
`backgroundWorkers`). `requiredCoreModules`, `requiredInfrastructureServices`,
and `aiTools` are still validated whenever present/non-empty -- an
absent list is not the same as a list containing an invalid entry.

Uses stdlib `dataclasses` only -- no new third-party dependency
(pydantic is only ever a *transitive* dependency of this repository via
`fastapi`/`stripe`, never a direct one; this module does not change
that). Mirrors the validation *style* already established elsewhere in
this codebase (e.g. `core/billing/service.py::_validate_key`,
`core/usage/service.py::_validate_metric`): plain functions, explicit
non-empty/length/pattern checks, no schema-definition framework.

**Security Requirement** (this phase's own roadmap text): `aiTools` and
`environmentVariables` are validated against `contracts/catalog.py`'s
reference catalogs -- `aiTools` against `KNOWN_AI_TOOLS` (currently
empty; Phase 7's tool registry does not exist yet, so any declared tool
is unauthorized by construction, a safe default). `environmentVariables`
is validated *structurally* (name/type/required shape) only -- this
module never calls `infra.secrets` and never resolves an actual secret
value; no platform-wide "authorized secret name" registry exists
anywhere in this codebase yet (that is deployment-tooling's future
concern, not this schema validator's), and introducing one here would
be exactly the kind of new `infra.secrets`-adjacent call site Phase
6.1's own constraints (never a new secret-consuming call site outside
`infra/secrets`) counsel against. This is a deliberate, documented scope
boundary, not an oversight.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from contracts.catalog import (
    KNOWN_AI_TOOLS,
    KNOWN_CORE_MODULES,
    KNOWN_INFRASTRUCTURE_SERVICES,
)
from contracts.errors import ContractValidationError

_MAX_NAME_LENGTH = 100
_VALID_ENV_VAR_TYPES = frozenset({"string", "number", "boolean", "secret"})
_VALID_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class EnvironmentVariableDeclaration:
    name: str
    type: str
    required: bool
    description: str | None = None


@dataclass(frozen=True)
class BackgroundWorkerDeclaration:
    name: str
    trigger: str
    owningModule: str  # noqa: N815 -- mirrors ARCHITECTURE.md section 9's own camelCase field names


@dataclass(frozen=True)
class ApiRouteDeclaration:
    path: str
    method: str


@dataclass(frozen=True)
class FeatureFlagDeclaration:
    key: str
    defaultState: bool  # noqa: N815 -- mirrors ARCHITECTURE.md section 9's own camelCase field names


@dataclass(frozen=True)
class DatabaseMigrationsDeclaration:
    schemaNamespace: str  # noqa: N815
    migrationsPath: str  # noqa: N815


@dataclass(frozen=True)
class DeploymentRequirements:
    compute: str | None = None
    region: str | None = None
    scaling: str | None = None


@dataclass(frozen=True)
class ProductContract:
    """The validated, in-memory representation of one product's
    declared contract (docs/ARCHITECTURE.md section 9's 14-field table).
    Only ever constructed by `validate_contract()` -- never directly --
    so an instance existing at all is itself proof it passed validation.
    """

    productName: str  # noqa: N815
    productVersion: str  # noqa: N815
    requiredCoreModules: list[str] = field(default_factory=list)  # noqa: N815
    requiredInfrastructureServices: list[str] = field(default_factory=list)  # noqa: N815
    databaseMigrations: DatabaseMigrationsDeclaration | None = None  # noqa: N815
    environmentVariables: list[EnvironmentVariableDeclaration] = field(  # noqa: N815
        default_factory=list
    )
    healthChecks: list[str] = field(default_factory=list)  # noqa: N815
    backgroundWorkers: list[BackgroundWorkerDeclaration] = field(default_factory=list)  # noqa: N815
    apiRoutes: list[ApiRouteDeclaration] = field(default_factory=list)  # noqa: N815
    frontendModules: list[str] = field(default_factory=list)  # noqa: N815
    billingMetrics: list[str] = field(default_factory=list)  # noqa: N815
    featureFlags: list[FeatureFlagDeclaration] = field(default_factory=list)  # noqa: N815
    deploymentRequirements: DeploymentRequirements | None = None  # noqa: N815
    aiTools: list[str] = field(default_factory=list)  # noqa: N815
    supportKnowledge: str | None = None  # noqa: N815


def _require_string(
    value: Any, field_name: str, errors: list[str], *, max_length: int = _MAX_NAME_LENGTH
) -> str | None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{field_name} must be a non-empty string.")
        return None
    if len(value) > max_length:
        errors.append(f"{field_name} exceeds {max_length} characters.")
        return None
    return value


def _require_string_list(value: Any, field_name: str, errors: list[str]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{field_name} must be a list of strings.")
        return []
    return value


def _validate_known_members(
    values: list[str], field_name: str, known: frozenset[str], errors: list[str]
) -> None:
    for value in values:
        if value not in known:
            errors.append(f"{field_name} references unknown entry {value!r}.")


def _validate_environment_variables(
    raw: Any, errors: list[str]
) -> list[EnvironmentVariableDeclaration]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        errors.append("environmentVariables must be a list.")
        return []
    result: list[EnvironmentVariableDeclaration] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            errors.append(f"environmentVariables[{i}] must be an object.")
            continue
        name = _require_string(entry.get("name"), f"environmentVariables[{i}].name", errors)
        var_type = entry.get("type")
        if var_type not in _VALID_ENV_VAR_TYPES:
            errors.append(
                f"environmentVariables[{i}].type must be one of {sorted(_VALID_ENV_VAR_TYPES)}, "
                f"got {var_type!r}."
            )
            var_type = None
        required = entry.get("required")
        if not isinstance(required, bool):
            errors.append(f"environmentVariables[{i}].required must be a boolean.")
            required = None
        description = entry.get("description")
        if description is not None and not isinstance(description, str):
            errors.append(f"environmentVariables[{i}].description must be a string.")
            description = None
        if name is not None and var_type is not None and required is not None:
            result.append(
                EnvironmentVariableDeclaration(
                    name=name, type=var_type, required=required, description=description
                )
            )
    return result


def _validate_background_workers(raw: Any, errors: list[str]) -> list[BackgroundWorkerDeclaration]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        errors.append("backgroundWorkers must be a list.")
        return []
    result: list[BackgroundWorkerDeclaration] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            errors.append(f"backgroundWorkers[{i}] must be an object.")
            continue
        name = _require_string(entry.get("name"), f"backgroundWorkers[{i}].name", errors)
        trigger = _require_string(entry.get("trigger"), f"backgroundWorkers[{i}].trigger", errors)
        owning_module = _require_string(
            entry.get("owningModule"), f"backgroundWorkers[{i}].owningModule", errors
        )
        if name is not None and trigger is not None and owning_module is not None:
            result.append(
                BackgroundWorkerDeclaration(name=name, trigger=trigger, owningModule=owning_module)
            )
    return result


def _validate_api_routes(raw: Any, errors: list[str]) -> list[ApiRouteDeclaration]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        errors.append("apiRoutes must be a list.")
        return []
    result: list[ApiRouteDeclaration] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            errors.append(f"apiRoutes[{i}] must be an object.")
            continue
        path = entry.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            errors.append(f"apiRoutes[{i}].path must be a string starting with '/'.")
            path = None
        method = entry.get("method")
        if method not in _VALID_HTTP_METHODS:
            errors.append(
                f"apiRoutes[{i}].method must be one of {sorted(_VALID_HTTP_METHODS)}, "
                f"got {method!r}."
            )
            method = None
        if path is not None and method is not None:
            result.append(ApiRouteDeclaration(path=path, method=method))
    return result


def _validate_feature_flags(raw: Any, errors: list[str]) -> list[FeatureFlagDeclaration]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        errors.append("featureFlags must be a list.")
        return []
    result: list[FeatureFlagDeclaration] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            errors.append(f"featureFlags[{i}] must be an object.")
            continue
        key = _require_string(entry.get("key"), f"featureFlags[{i}].key", errors)
        default_state = entry.get("defaultState")
        if not isinstance(default_state, bool):
            errors.append(f"featureFlags[{i}].defaultState must be a boolean.")
            default_state = None
        if key is not None and default_state is not None:
            result.append(FeatureFlagDeclaration(key=key, defaultState=default_state))
    return result


def _validate_database_migrations(
    raw: Any, errors: list[str]
) -> DatabaseMigrationsDeclaration | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        errors.append("databaseMigrations must be an object.")
        return None
    schema_namespace = _require_string(
        raw.get("schemaNamespace"), "databaseMigrations.schemaNamespace", errors
    )
    migrations_path = _require_string(
        raw.get("migrationsPath"), "databaseMigrations.migrationsPath", errors
    )
    if schema_namespace is None or migrations_path is None:
        return None
    return DatabaseMigrationsDeclaration(
        schemaNamespace=schema_namespace, migrationsPath=migrations_path
    )


def _validate_deployment_requirements(raw: Any, errors: list[str]) -> DeploymentRequirements | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        errors.append("deploymentRequirements must be an object.")
        return None
    for key in ("compute", "region", "scaling"):
        if key in raw and raw[key] is not None and not isinstance(raw[key], str):
            errors.append(f"deploymentRequirements.{key} must be a string.")
    return DeploymentRequirements(
        compute=raw.get("compute"), region=raw.get("region"), scaling=raw.get("scaling")
    )


def validate_contract(data: dict[str, Any]) -> ProductContract:
    """Validate a raw, already-parsed contract `dict` against the Product
    Contract schema (docs/ARCHITECTURE.md section 9). Raises
    `ContractValidationError` (carrying every failure found, not just the
    first) on any violation; returns a `ProductContract` otherwise.
    """
    if not isinstance(data, dict):
        raise ContractValidationError(["contract must be a JSON object."])

    errors: list[str] = []

    product_name = _require_string(data.get("productName"), "productName", errors)
    product_version = _require_string(data.get("productVersion"), "productVersion", errors)
    if product_version is not None:
        parts = product_version.split(".")
        if len(parts) != 3 or not all(part.isdigit() for part in parts):
            errors.append(
                f"productVersion must be a semantic version (e.g. '1.0.0'), "
                f"got {product_version!r}."
            )
            product_version = None

    required_core_modules = _require_string_list(
        data.get("requiredCoreModules"), "requiredCoreModules", errors
    )
    _validate_known_members(
        required_core_modules, "requiredCoreModules", KNOWN_CORE_MODULES, errors
    )

    required_infra_services = _require_string_list(
        data.get("requiredInfrastructureServices"), "requiredInfrastructureServices", errors
    )
    _validate_known_members(
        required_infra_services,
        "requiredInfrastructureServices",
        KNOWN_INFRASTRUCTURE_SERVICES,
        errors,
    )

    ai_tools = _require_string_list(data.get("aiTools"), "aiTools", errors)
    _validate_known_members(ai_tools, "aiTools", KNOWN_AI_TOOLS, errors)

    database_migrations = _validate_database_migrations(data.get("databaseMigrations"), errors)
    environment_variables = _validate_environment_variables(
        data.get("environmentVariables"), errors
    )
    health_checks = _require_string_list(data.get("healthChecks"), "healthChecks", errors)
    background_workers = _validate_background_workers(data.get("backgroundWorkers"), errors)
    api_routes = _validate_api_routes(data.get("apiRoutes"), errors)
    frontend_modules = _require_string_list(data.get("frontendModules"), "frontendModules", errors)
    billing_metrics = _require_string_list(data.get("billingMetrics"), "billingMetrics", errors)
    feature_flags = _validate_feature_flags(data.get("featureFlags"), errors)
    deployment_requirements = _validate_deployment_requirements(
        data.get("deploymentRequirements"), errors
    )
    support_knowledge = data.get("supportKnowledge")
    if support_knowledge is not None and not isinstance(support_knowledge, str):
        errors.append("supportKnowledge must be a string.")
        support_knowledge = None

    if errors:
        raise ContractValidationError(errors)

    assert product_name is not None
    assert product_version is not None

    return ProductContract(
        productName=product_name,
        productVersion=product_version,
        requiredCoreModules=required_core_modules,
        requiredInfrastructureServices=required_infra_services,
        databaseMigrations=database_migrations,
        environmentVariables=environment_variables,
        healthChecks=health_checks,
        backgroundWorkers=background_workers,
        apiRoutes=api_routes,
        frontendModules=frontend_modules,
        billingMetrics=billing_metrics,
        featureFlags=feature_flags,
        deploymentRequirements=deployment_requirements,
        aiTools=ai_tools,
        supportKnowledge=support_knowledge,
    )
