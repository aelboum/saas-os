"""Pure unit tests for `control_plane.orchestration.tools` -- no
database needed. Proves `ToolRegistry.register()`'s structural
guarantees (docs/IMPLEMENTATION-ROADMAP.md Phase 7.1;
docs/AI-CONTROL-PLANE.md section 5: "No tool is ever created at tier 3
...").
"""

from __future__ import annotations

import pytest

from control_plane.orchestration.errors import (
    InvalidToolDefinitionError,
    ToolNotFoundError,
)
from control_plane.orchestration.tools import ToolDefinition, ToolRegistry


async def _stub_handler(context, payload) -> dict[str, object]:
    return {"ok": True}


def _definition(**overrides: object) -> ToolDefinition:
    defaults: dict[str, object] = dict(
        key="stub_tool",
        description="A stub tool.",
        handler=_stub_handler,
        required_scope_type="tenant",
        required_resource="control_plane.stub_tool",
        required_action="invoke",
        autonomy_tier=0,
    )
    defaults.update(overrides)
    return ToolDefinition(**defaults)  # type: ignore[arg-type]


def test_register_and_get_tool() -> None:
    registry = ToolRegistry()
    registry.register(_definition())
    tool = registry.get("stub_tool")
    assert tool.key == "stub_tool"


def test_get_unknown_tool_raises() -> None:
    registry = ToolRegistry()
    with pytest.raises(ToolNotFoundError):
        registry.get("nonexistent")


def test_list_tools_includes_registered_tool() -> None:
    registry = ToolRegistry()
    registry.register(_definition())
    assert {t.key for t in registry.list()} == {"stub_tool"}


def test_duplicate_tool_key_rejected() -> None:
    registry = ToolRegistry()
    registry.register(_definition())
    with pytest.raises(InvalidToolDefinitionError):
        registry.register(_definition())


def test_empty_tool_key_rejected() -> None:
    registry = ToolRegistry()
    with pytest.raises(InvalidToolDefinitionError):
        registry.register(_definition(key=""))


def test_tier_3_tool_is_rejected() -> None:
    """docs/AI-CONTROL-PLANE.md section 5: "No tool is ever created at
    tier 3 without a separate, explicit, documented human decision --
    this document does not pre-authorize it for anything." No such
    decision exists in this repository, so registration itself refuses
    tier 3 -- default deny at the registration boundary."""
    registry = ToolRegistry()
    with pytest.raises(InvalidToolDefinitionError, match="tier"):
        registry.register(_definition(key="tier3_tool", autonomy_tier=3))


def test_negative_tier_is_rejected() -> None:
    registry = ToolRegistry()
    with pytest.raises(InvalidToolDefinitionError):
        registry.register(_definition(key="bad_tier_tool", autonomy_tier=-1))


def test_tenant_scoped_tool_without_resource_action_is_rejected() -> None:
    registry = ToolRegistry()
    with pytest.raises(InvalidToolDefinitionError):
        registry.register(
            _definition(key="incomplete_tool", required_resource=None, required_action=None)
        )


def test_repository_scoped_tool_without_scope_value_is_rejected() -> None:
    registry = ToolRegistry()
    with pytest.raises(InvalidToolDefinitionError):
        registry.register(
            _definition(
                key="repo_tool",
                required_scope_type="repository",
                required_resource=None,
                required_action=None,
                required_scope_value=None,
            )
        )


def test_repository_scoped_tool_with_scope_value_is_accepted() -> None:
    registry = ToolRegistry()
    registry.register(
        _definition(
            key="repo_tool",
            required_scope_type="repository",
            required_resource=None,
            required_action=None,
            required_scope_value="example/example-repo",
        )
    )
    tool = registry.get("repo_tool")
    assert tool.required_scope_value == "example/example-repo"


def test_unknown_scope_type_is_rejected() -> None:
    registry = ToolRegistry()
    with pytest.raises(InvalidToolDefinitionError):
        registry.register(_definition(key="bad_scope_tool", required_scope_type="planet"))  # type: ignore[arg-type]


def test_unknown_data_classification_is_rejected() -> None:
    registry = ToolRegistry()
    with pytest.raises(InvalidToolDefinitionError):
        registry.register(_definition(key="bad_dc_tool", data_classification="unknown"))


def test_unknown_side_effect_is_rejected() -> None:
    registry = ToolRegistry()
    with pytest.raises(InvalidToolDefinitionError):
        registry.register(_definition(key="bad_se_tool", side_effect="unknown"))


def test_requires_data_authorization_defaults_to_false() -> None:
    """Deny-by-default (docs/AI-CONTROL-PLANE.md section 2.1): a tool that
    never explicitly opts in is never treated as an external-provider
    tool."""
    registry = ToolRegistry()
    registry.register(_definition())
    assert registry.get("stub_tool").requires_data_authorization is False


def test_requires_data_authorization_can_be_declared_true() -> None:
    registry = ToolRegistry()
    registry.register(_definition(key="external_tool", requires_data_authorization=True))
    assert registry.get("external_tool").requires_data_authorization is True


def test_two_registries_are_fully_isolated() -> None:
    """Tests must never leak a registered stub tool into another test's
    registry -- proves `ToolRegistry` is a genuine, isolated instance,
    not backed by shared module state."""
    registry_a = ToolRegistry()
    registry_b = ToolRegistry()
    registry_a.register(_definition())
    assert registry_a.list() != registry_b.list()
    with pytest.raises(ToolNotFoundError):
        registry_b.get("stub_tool")
