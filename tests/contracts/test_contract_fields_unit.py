"""Field-level branches of the Product Contract validator
(`saas_os/contracts/schema.py`) that `test_contract_schema.py` does not
reach: wrong container types, non-object entries, length and version
bounds, the optional string fields, and a contract that declares every
field. Ledger row "Product Contract (Phase 6.1) has one test file".
Pure unit tests: no database, no Redis, no network.
"""

from __future__ import annotations

from typing import Any

import pytest

from saas_os.contracts import ContractValidationError, validate_contract
from saas_os.contracts.schema import (
    ApiRouteDeclaration,
    BackgroundWorkerDeclaration,
    DatabaseMigrationsDeclaration,
    DeploymentRequirements,
    EnvironmentVariableDeclaration,
    FeatureFlagDeclaration,
)

_BASE: dict[str, Any] = {"productName": "tiny-product", "productVersion": "1.0.0"}

_STRING_LIST_FIELDS = (
    "requiredCoreModules",
    "requiredInfrastructureServices",
    "aiTools",
    "healthChecks",
    "frontendModules",
    "billingMetrics",
)
_OBJECT_LIST_FIELDS = ("environmentVariables", "backgroundWorkers", "apiRoutes", "featureFlags")


def _errors(**fields: Any) -> list[str]:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract({**_BASE, **fields})
    return excinfo.value.errors


# --- Container types ---------------------------------------------------------


@pytest.mark.parametrize("field_name", _STRING_LIST_FIELDS)
@pytest.mark.parametrize("value", ["tenancy", {"a": "b"}, 3])
def test_a_string_list_field_that_is_not_a_list_is_rejected(field_name: str, value: Any) -> None:
    assert _errors(**{field_name: value}) == [f"{field_name} must be a list of strings."]


@pytest.mark.parametrize("field_name", _STRING_LIST_FIELDS)
def test_a_string_list_field_with_a_non_string_item_is_rejected(field_name: str) -> None:
    assert _errors(**{field_name: ["ok", 7]}) == [f"{field_name} must be a list of strings."]


@pytest.mark.parametrize("field_name", ("healthChecks", "frontendModules", "billingMetrics"))
def test_a_free_string_list_field_is_kept_as_declared(field_name: str) -> None:
    contract = validate_contract({**_BASE, field_name: ["a", "b"]})
    assert getattr(contract, field_name) == ["a", "b"]


@pytest.mark.parametrize("field_name", _OBJECT_LIST_FIELDS)
def test_an_object_list_field_that_is_not_a_list_is_rejected(field_name: str) -> None:
    assert _errors(**{field_name: {"name": "x"}}) == [f"{field_name} must be a list."]


@pytest.mark.parametrize("field_name", _OBJECT_LIST_FIELDS)
def test_a_non_object_entry_is_rejected_with_its_index(field_name: str) -> None:
    assert _errors(**{field_name: ["not-an-object"]}) == [f"{field_name}[0] must be an object."]


@pytest.mark.parametrize("field_name", ("databaseMigrations", "deploymentRequirements"))
def test_an_object_field_that_is_not_an_object_is_rejected(field_name: str) -> None:
    assert _errors(**{field_name: ["x"]}) == [f"{field_name} must be an object."]


@pytest.mark.parametrize("field_name", _STRING_LIST_FIELDS + _OBJECT_LIST_FIELDS)
def test_an_explicit_null_list_field_is_the_same_as_an_absent_one(field_name: str) -> None:
    assert getattr(validate_contract({**_BASE, field_name: None}), field_name) == []


# --- Strings: type, blank and length -----------------------------------------


@pytest.mark.parametrize("value", [123, True, None, "", "   "])
def test_a_product_name_that_is_not_a_non_empty_string_is_rejected(value: Any) -> None:
    assert _errors(productName=value) == ["productName must be a non-empty string."]


def test_a_name_of_exactly_one_hundred_characters_is_accepted() -> None:
    assert validate_contract({**_BASE, "productName": "p" * 100}).productName == "p" * 100


def test_a_name_longer_than_one_hundred_characters_is_rejected() -> None:
    assert _errors(productName="p" * 101) == ["productName exceeds 100 characters."]


def test_a_nested_name_longer_than_one_hundred_characters_is_rejected() -> None:
    errors = _errors(featureFlags=[{"key": "k" * 101, "defaultState": False}])
    assert errors == ["featureFlags[0].key exceeds 100 characters."]


def test_a_blank_nested_name_is_rejected() -> None:
    errors = _errors(backgroundWorkers=[{"name": "  ", "trigger": "t", "owningModule": "m"}])
    assert errors == ["backgroundWorkers[0].name must be a non-empty string."]


# --- productVersion -----------------------------------------------------------


@pytest.mark.parametrize("version", ["1.0", "1.0.0.0", "1.0.0-beta", "v1.0.0", "1..0", "a.b.c"])
def test_a_version_that_is_not_three_numeric_parts_is_rejected(version: str) -> None:
    errors = _errors(productVersion=version)
    assert errors == [f"productVersion must be a semantic version (e.g. '1.0.0'), got {version!r}."]


def test_a_multi_digit_version_is_accepted() -> None:
    assert validate_contract({**_BASE, "productVersion": "10.20.30"}).productVersion == "10.20.30"


# --- Entry fields ---------------------------------------------------------------


def test_an_environment_variable_description_that_is_not_a_string_is_rejected() -> None:
    errors = _errors(
        environmentVariables=[{"name": "V", "type": "string", "required": False, "description": 5}]
    )
    assert errors == ["environmentVariables[0].description must be a string."]


@pytest.mark.parametrize("required", ["true", 1, None])
def test_an_environment_variable_required_flag_must_be_a_real_boolean(required: Any) -> None:
    errors = _errors(environmentVariables=[{"name": "V", "type": "string", "required": required}])
    assert errors == ["environmentVariables[0].required must be a boolean."]


@pytest.mark.parametrize("default_state", [1, 0, "false", None])
def test_a_feature_flag_default_state_must_be_a_real_boolean(default_state: Any) -> None:
    errors = _errors(featureFlags=[{"key": "beta", "defaultState": default_state}])
    assert errors == ["featureFlags[0].defaultState must be a boolean."]


@pytest.mark.parametrize("method", ["get", "HEAD", "OPTIONS", None])
def test_an_api_route_method_outside_the_five_upper_case_verbs_is_rejected(method: Any) -> None:
    errors = _errors(apiRoutes=[{"path": "/v1/x", "method": method}])
    assert len(errors) == 1
    assert errors[0].startswith("apiRoutes[0].method must be one of")


def test_an_api_route_path_that_is_not_a_string_is_rejected() -> None:
    errors = _errors(apiRoutes=[{"path": None, "method": "GET"}])
    assert errors == ["apiRoutes[0].path must be a string starting with '/'."]


def test_an_error_names_the_index_of_the_failing_entry() -> None:
    errors = _errors(
        apiRoutes=[{"path": "/ok", "method": "GET"}, {"path": "/bad", "method": "TRACE"}]
    )
    assert len(errors) == 1
    assert errors[0].startswith("apiRoutes[1].method")


def test_database_migrations_missing_its_path_is_rejected() -> None:
    errors = _errors(databaseMigrations={"schemaNamespace": "product_x"})
    assert errors == ["databaseMigrations.migrationsPath must be a non-empty string."]


@pytest.mark.parametrize("key", ["compute", "region", "scaling"])
def test_a_deployment_requirement_that_is_not_a_string_is_rejected(key: str) -> None:
    assert _errors(deploymentRequirements={key: 2}) == [
        f"deploymentRequirements.{key} must be a string."
    ]


def test_support_knowledge_that_is_not_a_string_is_rejected() -> None:
    assert _errors(supportKnowledge=["faq"]) == ["supportKnowledge must be a string."]


# --- Whole contract -------------------------------------------------------------


def test_a_contract_declaring_every_field_is_returned_as_declared() -> None:
    contract = validate_contract(
        {
            "productName": "full-product",
            "productVersion": "2.3.4",
            "requiredCoreModules": ["tenancy", "billing"],
            "requiredInfrastructureServices": ["db", "jobs"],
            "databaseMigrations": {
                "schemaNamespace": "full_product",
                "migrationsPath": "full_product/migrations",
            },
            "environmentVariables": [
                {"name": "FULL_URL", "type": "string", "required": True},
                {"name": "FULL_KEY", "type": "secret", "required": False, "description": "d"},
            ],
            "healthChecks": ["/health"],
            "backgroundWorkers": [{"name": "sync", "trigger": "cron", "owningModule": "full.sync"}],
            "apiRoutes": [{"path": "/v1/full", "method": "POST"}],
            "frontendModules": ["full-ui"],
            "billingMetrics": ["full.requests"],
            "featureFlags": [{"key": "full.beta", "defaultState": True}],
            "deploymentRequirements": {"compute": "shared", "region": "eu", "scaling": "auto"},
            "aiTools": [],
            "supportKnowledge": "docs/full.md",
        }
    )
    assert contract.productName == "full-product"
    assert contract.productVersion == "2.3.4"
    assert contract.requiredCoreModules == ["tenancy", "billing"]
    assert contract.requiredInfrastructureServices == ["db", "jobs"]
    assert contract.databaseMigrations == DatabaseMigrationsDeclaration(
        schemaNamespace="full_product", migrationsPath="full_product/migrations"
    )
    assert contract.environmentVariables == [
        EnvironmentVariableDeclaration(name="FULL_URL", type="string", required=True),
        EnvironmentVariableDeclaration(
            name="FULL_KEY", type="secret", required=False, description="d"
        ),
    ]
    assert contract.healthChecks == ["/health"]
    assert contract.backgroundWorkers == [
        BackgroundWorkerDeclaration(name="sync", trigger="cron", owningModule="full.sync")
    ]
    assert contract.apiRoutes == [ApiRouteDeclaration(path="/v1/full", method="POST")]
    assert contract.frontendModules == ["full-ui"]
    assert contract.billingMetrics == ["full.requests"]
    assert contract.featureFlags == [FeatureFlagDeclaration(key="full.beta", defaultState=True)]
    assert contract.deploymentRequirements == DeploymentRequirements(
        compute="shared", region="eu", scaling="auto"
    )
    assert contract.aiTools == []
    assert contract.supportKnowledge == "docs/full.md"


def test_one_bad_entry_fails_the_whole_contract_rather_than_being_dropped() -> None:
    errors = _errors(
        featureFlags=[{"key": "good", "defaultState": True}, {"key": "bad", "defaultState": "x"}]
    )
    assert errors == ["featureFlags[1].defaultState must be a boolean."]


def test_the_error_is_a_value_error_whose_message_lists_every_failure() -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract({"productVersion": "1.0", "supportKnowledge": 1})
    error = excinfo.value
    assert isinstance(error, ValueError)
    assert error.errors == [
        "productName must be a non-empty string.",
        "productVersion must be a semantic version (e.g. '1.0.0'), got '1.0'.",
        "supportKnowledge must be a string.",
    ]
    assert str(error) == "Product contract validation failed: " + "; ".join(error.errors)
