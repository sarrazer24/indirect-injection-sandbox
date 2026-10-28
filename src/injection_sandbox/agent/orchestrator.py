"""Minimal C0 agent loop that proposes a single tool call and executes it through the gateway."""

from __future__ import annotations

from injection_sandbox.agent.qwen_adapter import Qwen2_5_3BAdapter
from injection_sandbox.agent.schemas import ToolRequest, ToolResult
from injection_sandbox.security.gateway import ToolGateway
from injection_sandbox.security.policy import ALLOWED_TOOLS
from injection_sandbox.tools.registry import ToolRegistry


class C0AgentLoop:
    """Request one model-approved action and execute it only through the sandbox gateway."""

    def __init__(
        self,
        adapter: Qwen2_5_3BAdapter,
        gateway: ToolGateway | None = None,
    ) -> None:
        self.adapter = adapter
        self.gateway = gateway or ToolGateway(ToolRegistry())

    def run(
        self,
        task: str,
        *,
        system_prompt: str | None = None,
        history: list[dict[str, str]] | None = None,
    ) -> ToolResult:
        """Ask the model for a single JSON tool proposal and execute it safely."""
        prompt = (
            "Return only a JSON object with exactly these keys: 'name' and 'arguments'. "
            "Allowed tool names are: read_document, read_web_fixture, draft_email. "
            "Use only the schema fields required by the selected tool and no extra keys. "
            "Do not emit prose or markdown."
        )

        try:
            proposal = self.adapter.generate_json(
                f"{task}\n\n{prompt}",
                system_prompt=system_prompt,
                history=history,
            )
        except ValueError as exc:
            return ToolResult(
                tool_name="agent",
                success=False,
                error=str(exc),
            )
        except (AttributeError, TypeError, RuntimeError) as exc:
            return ToolResult(
                tool_name="agent",
                success=False,
                error=f"Model proposal failed: {exc}",
            )

        if not isinstance(proposal, dict):
            return ToolResult(
                tool_name="agent",
                success=False,
                error="Model proposal must be a JSON object.",
            )

        if set(proposal) != {"name", "arguments"}:
            return ToolResult(
                tool_name="agent",
                success=False,
                error="Model proposal must include exactly 'name' and 'arguments'.",
            )

        tool_name = proposal.get("name")
        arguments = proposal.get("arguments")

        if not isinstance(tool_name, str) or not isinstance(arguments, dict):
            return ToolResult(
                tool_name="agent",
                success=False,
                error="Model proposal must include a tool name and arguments object.",
            )

        if tool_name not in ALLOWED_TOOLS:
            return ToolResult(
                tool_name="agent",
                success=False,
                error="Tool is not allowlisted.",
            )

        try:
            request = ToolRequest(name=tool_name, arguments=arguments)
        except ValueError:
            return ToolResult(
                tool_name="agent",
                success=False,
                error="Tool proposal failed validation.",
            )

        return self.gateway.execute(request)
