import pytest

from injection_sandbox.agent.schemas import ToolResult
from injection_sandbox.tools.registry import ToolRegistry


def sample_handler(arguments: object) -> ToolResult:
    return ToolResult(
        tool_name="read_document",
        success=True,
        content="Synthetic document",
    )


def test_register_and_retrieve_approved_handler():
    registry = ToolRegistry()

    registry.register("read_document", sample_handler)

    assert registry.get("read_document") is sample_handler
    assert "read_document" in registry.registered_names


def test_unregistered_tool_returns_none():
    registry = ToolRegistry()

    assert registry.get("read_document") is None


def test_unknown_tool_cannot_be_registered():
    registry = ToolRegistry()

    with pytest.raises(ValueError, match="not allowlisted"):
        registry.register("delete_file", sample_handler)


def test_duplicate_registration_is_rejected():
    registry = ToolRegistry()
    registry.register("read_document", sample_handler)

    with pytest.raises(ValueError, match="already registered"):
        registry.register("read_document", sample_handler)


def test_registered_names_cannot_mutate_registry():
    registry = ToolRegistry()
    registry.register("read_document", sample_handler)

    names = registry.registered_names

    assert isinstance(names, frozenset)
    assert names == frozenset({"read_document"})
