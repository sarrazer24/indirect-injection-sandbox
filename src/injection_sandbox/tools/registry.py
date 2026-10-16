"""Registry of trusted handlers for sandboxed tools."""

from collections.abc import Callable, Mapping

from injection_sandbox.agent.schemas import ToolResult
from injection_sandbox.security.policy import ALLOWED_TOOLS

ToolHandler = Callable[[Mapping[str, object]], ToolResult]


class ToolRegistry:
    """Store trusted handlers for explicitly allowlisted tools."""

    def __init__(self) -> None:
        self._handlers: dict[str, ToolHandler] = {}

    def register(self, name: str, handler: ToolHandler) -> None:
        """Register one trusted handler for an allowlisted tool."""

        if name not in ALLOWED_TOOLS:
            raise ValueError("Cannot register a tool that is not allowlisted.")

        if not callable(handler):
            raise TypeError("Tool handler must be callable.")

        if name in self._handlers:
            raise ValueError("A handler is already registered for this tool.")

        self._handlers[name] = handler

    def get(self, name: str) -> ToolHandler | None:
        """Return a registered handler, or None if none exists."""

        return self._handlers.get(name)

    @property
    def registered_names(self) -> frozenset[str]:
        """Return the names of registered tools without exposing the registry."""

        return frozenset(self._handlers)
