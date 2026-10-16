import pytest
from pydantic import ValidationError

from injection_sandbox.agent.schemas import ToolRequest, ToolResult


def test_valid_request_is_accepted():
    request = ToolRequest(
        name="read_document",
        arguments={"document_id": "doc-001"},
    )

    assert request.name == "read_document"
    assert request.arguments["document_id"] == "doc-001"


def test_unknown_tool_can_be_represented_for_gateway_denial():
    request = ToolRequest(
        name="delete_file",
        arguments={"path": "report.txt"},
    )

    assert request.name == "delete_file"


def test_extra_top_level_fields_are_rejected():
    with pytest.raises(ValidationError):
        ToolRequest(
            name="read_document",
            arguments={},
            authorized=True,
        )


def test_too_many_arguments_are_rejected():
    with pytest.raises(ValidationError):
        ToolRequest(
            name="read_document",
            arguments={f"arg{i}": i for i in range(11)},
        )


def test_nested_argument_objects_are_rejected():
    with pytest.raises(ValidationError):
        ToolRequest(
            name="read_document",
            arguments={"document_id": {"path": "secret.txt"}},
        )


def test_oversized_argument_string_is_rejected():
    with pytest.raises(ValidationError):
        ToolRequest(
            name="draft_email",
            arguments={"body": "x" * 10_001},
        )


def test_successful_result_requires_content():
    with pytest.raises(ValidationError):
        ToolResult(
            tool_name="read_document",
            success=True,
        )


def test_failed_result_requires_error():
    with pytest.raises(ValidationError):
        ToolResult(
            tool_name="read_document",
            success=False,
        )


def test_failed_result_with_error_is_valid():
    result = ToolResult(
        tool_name="read_document",
        success=False,
        error="Document not found.",
    )

    assert result.success is False
    assert result.error == "Document not found."
