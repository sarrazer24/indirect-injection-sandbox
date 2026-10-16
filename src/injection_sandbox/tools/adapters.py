"""Trusted adapters that connect handlers to sandbox components."""

from collections.abc import Mapping

from injection_sandbox.agent.schemas import ToolResult
from injection_sandbox.tools.email_draft import EmailDrafter
from injection_sandbox.tools.file_reader import DocumentReader
from injection_sandbox.tools.registry import ToolHandler
from injection_sandbox.tools.web_reader import WebFixtureReader


def make_document_reader_handler(reader: DocumentReader) -> ToolHandler:
    """Create a handler that reads documents only through DocumentReader."""

    def handle(arguments: Mapping[str, object]) -> ToolResult:
        document_id = arguments.get("document_id")

        if not isinstance(document_id, str):
            return ToolResult(
                tool_name="read_document",
                success=False,
                error="A valid document ID is required.",
            )

        return reader.read(document_id)

    return handle


def make_web_fixture_reader_handler(reader: WebFixtureReader) -> ToolHandler:
    """Create a handler that reads fixtures only through WebFixtureReader."""

    def handle(arguments: Mapping[str, object]) -> ToolResult:
        fixture_id = arguments.get("fixture_id")

        if not isinstance(fixture_id, str):
            return ToolResult(
                tool_name="read_web_fixture",
                success=False,
                error="A valid fixture ID is required.",
            )

        return reader.read(fixture_id)

    return handle


def make_email_draft_handler(drafter: EmailDrafter) -> ToolHandler:
    """Create a handler that drafts messages without sending them."""

    def handle(arguments: Mapping[str, object]) -> ToolResult:
        recipient = arguments.get("recipient")
        body = arguments.get("body")

        if not isinstance(recipient, str) or not isinstance(body, str):
            return ToolResult(
                tool_name="draft_email",
                success=False,
                error="A valid recipient and email body are required.",
            )

        return drafter.draft(recipient, body)

    return handle
