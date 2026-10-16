"""Deterministic authorization and execution boundary for sandboxed tools."""

from collections.abc import Mapping

from injection_sandbox.agent.schemas import ToolRequest, ToolResult
from injection_sandbox.security.policy import authorize_tool
from injection_sandbox.tools.registry import ToolRegistry


class ToolGateway:
    """Authorize requests and dispatch only to trusted registered handlers."""

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    def execute(self, request: ToolRequest) -> ToolResult:
        """Authorize, dispatch, and safely return a structured tool result."""

        decision = authorize_tool(request)

        if not decision.allowed:
            return ToolResult(
                tool_name=request.name,
                success=False,
                error=decision.reason,
            )

        handler = self._registry.get(request.name)

        if handler is None:
            return ToolResult(
                tool_name=request.name,
                success=False,
                error="Tool is approved but no handler is registered.",
            )

        # Copy the arguments so the handler receives a separate mapping.
        arguments: Mapping[str, object] = dict(request.arguments)

        try:
            result = handler(arguments)
        except Exception:  # noqa: BLE001
            # Do not expose exception messages, paths, or implementation details.
            return ToolResult(
                tool_name=request.name,
                success=False,
                error="Tool execution failed.",
            )

        if not isinstance(result, ToolResult):
            return ToolResult(
                tool_name=request.name,
                success=False,
                error="Tool returned an invalid result.",
            )

        if result.tool_name != request.name:
            return ToolResult(
                tool_name=request.name,
                success=False,
                error="Tool returned a mismatched result.",
            )

        return result
