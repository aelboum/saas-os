"""The first real AI Control Plane tool: propose a code change against
one repository via a pull request (docs/IMPLEMENTATION-ROADMAP.md Phase
7.3).

`build_open_pull_request_tool(repository, provider)` is a **factory**,
not a module-level singleton -- which repository a development-agent
tool is allowed to target, and which `PullRequestProvider` it calls
through, are deployment decisions (docs/AI-CONTROL-PLANE.md section 7:
"agent identity for this tool is scoped to 'this repository' only"), not
something this source file should hardcode. A deployer registers one
instance of this tool per repository a development agent is authorized
to act on.

`autonomy_tier=1` (propose + human approval via normal PR review, this
phase's own Objective) -- this tool can never be invoked directly through
`control_plane.orchestration.invoke_tool()`; it must be proposed through
`control_plane.approvals` and executed only once approved.

`required_scope_type="repository"` -- no `core.rbac` permission check
applies (there is no tenant involved in "propose a change to this
platform's own codebase"); authorization is purely the agent's declared
repository scope matching this tool's own `required_scope_value`
(`control_plane.orchestration.service._is_authorized`), reinforced a
second time inside the handler itself (`RepositoryScopeMismatchError`)
as defense in depth against a payload naming a different repository than
the tool's own declared scope.
"""

from __future__ import annotations

from collections.abc import Mapping

from control_plane.development.errors import RepositoryScopeMismatchError
from control_plane.development.provider import FileChange, PullRequestProvider
from control_plane.orchestration.tools import ToolDefinition, ToolExecutionContext

TOOL_KEY = "development.open_pull_request"


def _build_handler(provider: PullRequestProvider):
    async def handler(
        context: ToolExecutionContext, payload: Mapping[str, object]
    ) -> dict[str, object]:
        repository = str(payload["repository"])
        if context.agent_scope_value != repository:
            raise RepositoryScopeMismatchError(context.agent_scope_value, repository)

        file_changes = [
            FileChange(path=str(item["path"]), content=str(item["content"]))
            for item in payload.get("file_changes", [])  # type: ignore[union-attr]
        ]
        pr_id = provider.open_pull_request(
            repository=repository,
            base_branch=str(payload["base_branch"]),
            branch_name=str(payload["branch_name"]),
            title=str(payload["title"]),
            body=str(payload.get("body", "")),
            file_changes=file_changes,
        )
        return {"pull_request_id": pr_id}

    return handler


def build_open_pull_request_tool(
    repository: str, *, provider: PullRequestProvider
) -> ToolDefinition:
    handler = _build_handler(provider)
    return ToolDefinition(
        key=TOOL_KEY,
        description="Propose a code change against one repository via a pull request.",
        handler=handler,
        required_scope_type="repository",
        required_scope_value=repository,
        autonomy_tier=1,
        data_classification="none",
        side_effect="mutating",
    )
