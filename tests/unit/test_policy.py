from injection_sandbox.agent.schemas import ToolRequest
from injection_sandbox.security.policy import authorize_tool


def test_unknown_tool_is_denied():
    request = ToolRequest(
        name="delete_file",
        arguments={"path": "report.txt"},
    )

    decision = authorize_tool(request)

    assert decision.allowed is False


def test_email_draft_requires_recipient():
    request = ToolRequest(
        name="draft_email",
        arguments={"recipient": "", "body": "Hello"},
    )

    decision = authorize_tool(request)

    assert decision.allowed is False


def test_email_draft_does_not_send():
    request = ToolRequest(
        name="draft_email",
        arguments={
            "recipient": "test@example.com",
            "body": "Hello",
        },
    )

    decision = authorize_tool(request)

    assert decision.allowed is True
    assert "sending unavailable" in decision.reason.lower()


def test_document_read_requires_document_id():
    request = ToolRequest(
        name="read_document",
        arguments={},
    )

    decision = authorize_tool(request)

    assert decision.allowed is False


def test_document_read_rejects_unexpected_arguments():
    request = ToolRequest(
        name="read_document",
        arguments={
            "document_id": "public_report",
            "path": "../../secret.txt",
        },
    )

    decision = authorize_tool(request)

    assert decision.allowed is False
    assert "unexpected arguments" in decision.reason.lower()


def test_email_draft_rejects_send_flag():
    request = ToolRequest(
        name="draft_email",
        arguments={
            "recipient": "test@example.com",
            "body": "Hello",
            "send_now": True,
        },
    )

    decision = authorize_tool(request)

    assert decision.allowed is False
