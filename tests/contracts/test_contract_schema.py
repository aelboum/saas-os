"""Product Contract schema/validator tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 6.1's own Tests requirement: "schema validation unit tests (valid
contract accepted, contract missing a required field rejected, contract
referencing a nonexistent Core module rejected)"). Pure unit tests --
no database, no Redis, no network -- `contracts` has no such
dependencies (contracts/__init__.py's own docstring).
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from contracts.schema import ProductContract

from contracts import ContractValidationError, validate_contract

_SAMPLES_DIR = Path(__file__).resolve().parents[2] / "contracts" / "samples"


def _load_sample(name: str) -> dict:
    return json.loads((_SAMPLES_DIR / name).read_text())


# --- Acceptance Criteria: hand-written minimal sample validates ------------


def test_minimal_sample_contract_validates_successfully() -> None:
    data = _load_sample("minimal_product.json")
    contract = validate_contract(data)
    assert isinstance(contract, ProductContract)
    assert contract.productName == "minimal-hypothetical-product"
    assert contract.productVersion == "0.1.0"
    assert contract.requiredCoreModules == [
        "tenancy",
        "identity",
        "rbac",
        "billing",
        "usage",
    ]


# --- Acceptance Criteria: deliberately malformed sample is rejected --------


def test_malformed_sample_contract_is_rejected_with_a_clear_error() -> None:
    data = _load_sample("malformed_product.json")
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(data)
    errors = excinfo.value.errors
    assert any("productVersion" in e for e in errors)
    assert any("nonexistent_core_module" in e for e in errors)
    assert any("not_a_real_type" in e for e in errors)
    assert any("nonexistent_tool" in e for e in errors)


# --- Tests bullet 1: valid contract accepted --------------------------------


def test_minimal_valid_contract_dict_is_accepted() -> None:
    contract = validate_contract({"productName": "tiny-product", "productVersion": "1.0.0"})
    assert contract.productName == "tiny-product"
    assert contract.requiredCoreModules == []
    assert contract.aiTools == []
    assert contract.databaseMigrations is None
    assert contract.deploymentRequirements is None


# --- Tests bullet 2: contract missing a required field rejected ------------


def test_missing_product_name_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract({"productVersion": "1.0.0"})
    assert any("productName" in e for e in excinfo.value.errors)


def test_missing_product_version_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract({"productName": "tiny-product"})
    assert any("productVersion" in e for e in excinfo.value.errors)


def test_empty_product_name_is_rejected() -> None:
    with pytest.raises(ContractValidationError):
        validate_contract({"productName": "  ", "productVersion": "1.0.0"})


def test_malformed_product_version_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract({"productName": "tiny-product", "productVersion": "not-semver"})
    assert any("productVersion" in e for e in excinfo.value.errors)


# --- Tests bullet 3: contract referencing a nonexistent Core module rejected -


def test_contract_referencing_nonexistent_core_module_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {
                "productName": "tiny-product",
                "productVersion": "1.0.0",
                "requiredCoreModules": ["tenancy", "not_a_real_core_module"],
            }
        )
    assert any("not_a_real_core_module" in e for e in excinfo.value.errors)


def test_contract_referencing_real_core_modules_is_accepted() -> None:
    contract = validate_contract(
        {
            "productName": "tiny-product",
            "productVersion": "1.0.0",
            "requiredCoreModules": ["tenancy", "identity", "billing", "usage"],
        }
    )
    assert contract.requiredCoreModules == ["tenancy", "identity", "billing", "usage"]


# --- Security Requirement: aiTools validated against the authorized set ----


def test_contract_declaring_any_ai_tool_is_rejected() -> None:
    """No AI Control Plane tool registry exists yet
    (docs/IMPLEMENTATION-ROADMAP.md Phase 7.1 not built) -- the known-tool
    catalog is empty by construction, so ANY declared aiTools entry today
    references a tool that doesn't exist and must be rejected -- a
    default-deny safe default, not a bug."""
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {
                "productName": "tiny-product",
                "productVersion": "1.0.0",
                "aiTools": ["some_future_tool"],
            }
        )
    assert any("some_future_tool" in e for e in excinfo.value.errors)


def test_contract_declaring_no_ai_tools_is_accepted() -> None:
    contract = validate_contract(
        {"productName": "tiny-product", "productVersion": "1.0.0", "aiTools": []}
    )
    assert contract.aiTools == []


# --- Security Requirement: environmentVariables structural validation ------


def test_environment_variable_with_unknown_type_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {
                "productName": "tiny-product",
                "productVersion": "1.0.0",
                "environmentVariables": [
                    {"name": "SOME_VAR", "type": "bogus_type", "required": True}
                ],
            }
        )
    assert any("environmentVariables[0].type" in e for e in excinfo.value.errors)


def test_environment_variable_with_missing_required_flag_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {
                "productName": "tiny-product",
                "productVersion": "1.0.0",
                "environmentVariables": [{"name": "SOME_VAR", "type": "secret"}],
            }
        )
    assert any("environmentVariables[0].required" in e for e in excinfo.value.errors)


def test_valid_environment_variable_declaration_is_accepted() -> None:
    contract = validate_contract(
        {
            "productName": "tiny-product",
            "productVersion": "1.0.0",
            "environmentVariables": [
                {
                    "name": "SOME_SECRET",
                    "type": "secret",
                    "required": True,
                    "description": "an upstream credential",
                }
            ],
        }
    )
    assert len(contract.environmentVariables) == 1
    assert contract.environmentVariables[0].name == "SOME_SECRET"
    assert contract.environmentVariables[0].type == "secret"


# --- requiredInfrastructureServices -----------------------------------------


def test_contract_referencing_nonexistent_infrastructure_service_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {
                "productName": "tiny-product",
                "productVersion": "1.0.0",
                "requiredInfrastructureServices": ["db", "not_a_real_service"],
            }
        )
    assert any("not_a_real_service" in e for e in excinfo.value.errors)


# --- apiRoutes / backgroundWorkers / featureFlags structural validation ----


def test_api_route_with_invalid_method_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {
                "productName": "tiny-product",
                "productVersion": "1.0.0",
                "apiRoutes": [{"path": "/v1/status", "method": "TRACE"}],
            }
        )
    assert any("apiRoutes[0].method" in e for e in excinfo.value.errors)


def test_api_route_with_path_not_starting_with_slash_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {
                "productName": "tiny-product",
                "productVersion": "1.0.0",
                "apiRoutes": [{"path": "v1/status", "method": "GET"}],
            }
        )
    assert any("apiRoutes[0].path" in e for e in excinfo.value.errors)


def test_background_worker_missing_owning_module_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {
                "productName": "tiny-product",
                "productVersion": "1.0.0",
                "backgroundWorkers": [{"name": "worker", "trigger": "event.x"}],
            }
        )
    assert any("backgroundWorkers[0].owningModule" in e for e in excinfo.value.errors)


def test_feature_flag_with_non_boolean_default_state_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {
                "productName": "tiny-product",
                "productVersion": "1.0.0",
                "featureFlags": [{"key": "beta", "defaultState": "yes"}],
            }
        )
    assert any("featureFlags[0].defaultState" in e for e in excinfo.value.errors)


# --- databaseMigrations / deploymentRequirements ----------------------------


def test_database_migrations_missing_schema_namespace_is_rejected() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {
                "productName": "tiny-product",
                "productVersion": "1.0.0",
                "databaseMigrations": {"migrationsPath": "products/x/migrations"},
            }
        )
    assert any("databaseMigrations.schemaNamespace" in e for e in excinfo.value.errors)


def test_deployment_requirements_all_optional_fields_accepted() -> None:
    contract = validate_contract(
        {
            "productName": "tiny-product",
            "productVersion": "1.0.0",
            "deploymentRequirements": {"compute": "shared"},
        }
    )
    assert contract.deploymentRequirements is not None
    assert contract.deploymentRequirements.compute == "shared"
    assert contract.deploymentRequirements.region is None


# --- Non-object input --------------------------------------------------------


def test_non_dict_input_is_rejected() -> None:
    with pytest.raises(ContractValidationError):
        validate_contract([])  # type: ignore[arg-type]


# --- Error reporting: every failure is reported, not just the first --------


def test_multiple_failures_are_all_reported_together() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {
                "requiredCoreModules": ["bogus_a", "bogus_b"],
                "requiredInfrastructureServices": ["bogus_service"],
            }
        )
    errors = excinfo.value.errors
    assert any("productName" in e for e in errors)
    assert any("productVersion" in e for e in errors)
    assert any("bogus_a" in e for e in errors)
    assert any("bogus_b" in e for e in errors)
    assert any("bogus_service" in e for e in errors)


# --- Architecture boundary: contracts is a dependency-free leaf ------------


def test_contracts_module_does_not_import_core_infra_control_plane_or_products() -> None:
    """Non-vacuous documentation of the boundary this module relies on
    (docs/ARCHITECTURE.md section 4's own Module Ownership table:
    `contracts/*` is a standalone, cross-cutting package) -- the real
    enforcement is that no import-linter contract needed to change for
    this phase, because contracts/ has zero edges into any of the four
    layers; this just confirms the module's own source doesn't contain
    such an import.
    """
    import contracts.catalog as catalog_module
    import contracts.errors as errors_module
    import contracts.schema as schema_module

    for module in (catalog_module, errors_module, schema_module):
        source = inspect.getsource(module)
        for forbidden in ("import core", "import infra", "import control_plane", "import products"):
            assert forbidden not in source, f"{module.__name__} unexpectedly contains {forbidden!r}"
