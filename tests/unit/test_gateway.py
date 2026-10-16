from injection_sandbox.agent.schemas import ToolRequest, ToolResult
from injection_sandbox.security.gateway import ToolGateway
from injection_sandbox.tools.registry import ToolRegistry


def successful_handler(arguments: object) -> ToolResult:
    return ToolResult(
        tool_name="read_document",
        success=True,
        content="Synthetic document",
    )


def test_gateway_executes_registered_authorized_tool():
    registry = ToolRegistry()
    registry.register("read_document", successful_handler)
    gateway = ToolGateway(registry)

    result = gateway.execute(
        ToolRequest(
            name="read_document",
            arguments={"document_id": "public_report"},
        )
    )

    assert result.success is True
    assert result.content == "Synthetic document"


def test_denied_request_never_invokes_handler():
    calls = []

    def tracking_handler(arguments: object) -> ToolResult:
        calls.append(arguments)
        return successful_handler(arguments)

    registry = ToolRegistry()
    registry.register("read_document", tracking_handler)
    gateway = ToolGateway(registry)

    result = gateway.execute(
        ToolRequest(
            name="read_document",
            arguments={
                "document_id": "public_report",
                "path": "../../secret.txt",
            },
        )
    )

    assert result.success is False
    assert calls == []


def test_missing_handler_fails_safely():
    gateway = ToolGateway(ToolRegistry())

    result = gateway.execute(
        ToolRequest(
            name="read_document",
            arguments={"document_id": "public_report"},
        )
    )

    assert result.success is False
    assert result.error == "Tool is approved but no handler is registered."


def test_handler_exception_does_not_leak_details():
    def failing_handler(arguments: object) -> ToolResult:
        raise RuntimeError("secret internal path: C:\\private\\data.txt")

    registry = ToolRegistry()
    registry.register("read_document", failing_handler)
    gateway = ToolGateway(registry)

    result = gateway.execute(
        ToolRequest(
            name="read_document",
            arguments={"document_id": "public_report"},
        )
    )

    assert result.success is False
    assert result.error == "Tool execution failed."
    assert "private" not in result.error


def test_mismatched_result_tool_name_is_rejected():
    def mismatched_handler(arguments: object) -> ToolResult:
        return ToolResult(
            tool_name="draft_email",
            success=True,
            content="Unexpected result",
        )

    registry = ToolRegistry()
    registry.register("read_document", mismatched_handler)
    gateway = ToolGateway(registry)

    result = gateway.execute(
        ToolRequest(
            name="read_document",
            arguments={"document_id": "public_report"},
        )
    )

    assert result.success is False
    assert result.error == "Tool returned a mismatched result."


def test_non_tool_result_is_rejected():
    def invalid_handler(arguments: object) -> ToolResult:
        return "not a ToolResult"

    registry = ToolRegistry()
    registry.register("read_document", invalid_handler)
    gateway = ToolGateway(registry)

    result = gateway.execute(
        ToolRequest(
            name="read_document",
            arguments={"document_id": "public_report"},
        )
    )

    assert result.success is False
    assert result.error == "Tool returned an invalid result."
