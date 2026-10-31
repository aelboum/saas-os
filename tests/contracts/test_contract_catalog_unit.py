"""The reference catalogs the Product Contract validator checks against
(`saas_os/contracts/catalog.py`). The catalog says it lists only what
exists and is never pre-populated; these tests hold it to that, and pin
its current members so a change to what a contract may reference is a
reviewed change.

The catalogs do not list every package that exists: since the owner
decision of 2026-10-31 they add `outbox`, `email` and `egress`, which a
product uses directly, and leave out internals (`crypto`, `config`,
`authority`, `platform_authority`, ...). This file therefore asserts
"listed implies exists", not the converse.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from saas_os.contracts import ContractValidationError, validate_contract
from saas_os.contracts.catalog import (
    KNOWN_AI_TOOLS,
    KNOWN_CORE_MODULES,
    KNOWN_INFRASTRUCTURE_SERVICES,
)

_PACKAGE = Path(__file__).resolve().parents[2] / "saas_os"


def test_the_core_module_catalog_is_the_reviewed_set() -> None:
    assert KNOWN_CORE_MODULES == {
        "tenancy",
        "identity",
        "rbac",
        "audit_log",
        "api_keys",
        "feature_flags",
        "webhooks",
        "notifications",
        "billing",
        "usage",
        "outbox",
        "email",
    }


def test_the_infrastructure_service_catalog_is_the_reviewed_set() -> None:
    assert KNOWN_INFRASTRUCTURE_SERVICES == {
        "db",
        "jobs",
        "observability",
        "health",
        "secrets",
        "deploy",
        "egress",
    }


def test_the_ai_tool_catalog_is_empty() -> None:
    assert KNOWN_AI_TOOLS == frozenset()


@pytest.mark.parametrize("name", sorted(KNOWN_CORE_MODULES))
def test_every_listed_core_module_is_a_core_package(name: str) -> None:
    assert (_PACKAGE / "core" / name / "__init__.py").is_file()


@pytest.mark.parametrize("name", sorted(KNOWN_INFRASTRUCTURE_SERVICES - {"deploy"}))
def test_every_listed_infrastructure_service_is_an_infra_package(name: str) -> None:
    assert (_PACKAGE / "infra" / name / "__init__.py").is_file()


def test_the_deploy_service_names_the_deployment_tooling() -> None:
    """`deploy` is the one entry that is not a `saas_os/infra` package: the
    deployment tooling lives in `deploy/` at the repository root."""
    assert not (_PACKAGE / "infra" / "deploy").exists()
    assert (_PACKAGE.parent / "deploy").is_dir()


def test_every_catalog_entry_is_accepted_by_the_validator() -> None:
    contract = validate_contract(
        {
            "productName": "catalog-product",
            "productVersion": "1.0.0",
            "requiredCoreModules": sorted(KNOWN_CORE_MODULES),
            "requiredInfrastructureServices": sorted(KNOWN_INFRASTRUCTURE_SERVICES),
        }
    )
    assert contract.requiredCoreModules == sorted(KNOWN_CORE_MODULES)
    assert contract.requiredInfrastructureServices == sorted(KNOWN_INFRASTRUCTURE_SERVICES)


@pytest.mark.parametrize(
    "name", ["platform_authority", "crypto", "config", "authority", "Tenancy", "core.tenancy"]
)
def test_an_internal_or_misspelled_core_name_is_rejected(name: str) -> None:
    with pytest.raises(ContractValidationError) as excinfo:
        validate_contract(
            {"productName": "p", "productVersion": "1.0.0", "requiredCoreModules": [name]}
        )
    assert excinfo.value.errors == [f"requiredCoreModules references unknown entry {name!r}."]
