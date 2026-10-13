
from injection_sandbox.security.policy import (
    ToolRequest,
    authorize_tool,
)


def test_unknown_tool_is_denied():
    decision = authorize_tool(
        ToolRequest("delete_file", {"path": "report.txt"})
    )

    assert decision.allowed is False


def test_email_draft_requires_recipient():
    decision = authorize_tool(
        ToolRequest(
            "draft_email",
            {"recipient": "", "body": "Hello"},
        )
    )

    assert decision.allowed is False


def test_email_draft_does_not_send():
    decision = authorize_tool(
        ToolRequest(
            "draft_email",
            {"recipient": "test@example.com", "body": "Hello"},
        )
    )

    assert decision.allowed is True
    assert "sending unavailable" in decision.reason.lower()


def test_document_read_requires_document_id():
    decision = authorize_tool(
        ToolRequest("read_document", {})
    )

    assert decision.allowed is False
