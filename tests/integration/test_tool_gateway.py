from injection_sandbox.agent.schemas import ToolRequest
from injection_sandbox.security.gateway import ToolGateway
from injection_sandbox.tools.adapters import (
    make_document_reader_handler,
    make_email_draft_handler,
    make_web_fixture_reader_handler,
)
from injection_sandbox.tools.email_draft import EmailDrafter
from injection_sandbox.tools.file_reader import DocumentReader
from injection_sandbox.tools.registry import ToolRegistry
from injection_sandbox.tools.web_reader import WebFixtureReader


def make_gateway(tmp_path):
    (tmp_path / "public_report.txt").write_text(
        "Synthetic public report",
        encoding="utf-8",
    )

    reader = DocumentReader(
        documents_root=tmp_path,
        approved_documents={"public_report": "public_report.txt"},
    )

    registry = ToolRegistry()
    registry.register(
        "read_document",
        make_document_reader_handler(reader),
    )

    return ToolGateway(registry)


def test_gateway_reads_approved_document_end_to_end(tmp_path):
    gateway = make_gateway(tmp_path)

    result = gateway.execute(
        ToolRequest(
            name="read_document",
            arguments={"document_id": "public_report"},
        )
    )

    assert result.success is True
    assert result.content == "Synthetic public report"


def test_gateway_rejects_unapproved_document_id(tmp_path):
    gateway = make_gateway(tmp_path)

    result = gateway.execute(
        ToolRequest(
            name="read_document",
            arguments={"document_id": "private_report"},
        )
    )

    assert result.success is False
    assert result.error == "Document ID is not approved."


def test_gateway_rejects_model_supplied_path(tmp_path):
    gateway = make_gateway(tmp_path)

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
    assert result.error == "Unexpected arguments are not permitted."


def test_gateway_does_not_read_outside_document_root(tmp_path):
    gateway = make_gateway(tmp_path)
    outside_file = tmp_path.parent / "secret.txt"
    outside_file.write_text("Synthetic secret", encoding="utf-8")

    try:
        # This ID is approved in the reader configuration, but its configured
        # path attempts to escape the document root.
        reader = DocumentReader(
            documents_root=tmp_path,
            approved_documents={"outside": "../secret.txt"},
        )
        registry = ToolRegistry()
        registry.register(
            "read_document",
            make_document_reader_handler(reader),
        )
        gateway = ToolGateway(registry)

        result = gateway.execute(
            ToolRequest(
                name="read_document",
                arguments={"document_id": "outside"},
            )
        )

        assert result.success is False
        assert result.error == "Document path escapes the approved directory."
    finally:
        outside_file.unlink(missing_ok=True)


def make_full_gateway(tmp_path):
    """Register all three restricted tools for integration testing."""

    (tmp_path / "public_report.txt").write_text(
        "Synthetic public report",
        encoding="utf-8",
    )
    (tmp_path / "research.html").write_text(
        "<html><body>Synthetic research page</body></html>",
        encoding="utf-8",
    )

    document_reader = DocumentReader(
        documents_root=tmp_path,
        approved_documents={"public_report": "public_report.txt"},
    )
    web_reader = WebFixtureReader(
        fixtures_root=tmp_path,
        approved_fixtures={"research_page": "research.html"},
    )

    registry = ToolRegistry()
    registry.register(
        "read_document",
        make_document_reader_handler(document_reader),
    )
    registry.register(
        "read_web_fixture",
        make_web_fixture_reader_handler(web_reader),
    )
    registry.register(
        "draft_email",
        make_email_draft_handler(EmailDrafter()),
    )

    return ToolGateway(registry)


def test_gateway_reads_approved_web_fixture(tmp_path):
    gateway = make_full_gateway(tmp_path)

    result = gateway.execute(
        ToolRequest(
            name="read_web_fixture",
            arguments={"fixture_id": "research_page"},
        )
    )

    assert result.success is True
    assert "Synthetic research page" in result.content


def test_gateway_rejects_unapproved_web_fixture(tmp_path):
    gateway = make_full_gateway(tmp_path)

    result = gateway.execute(
        ToolRequest(
            name="read_web_fixture",
            arguments={"fixture_id": "unapproved_page"},
        )
    )

    assert result.success is False
    assert result.error == "Fixture ID is not approved."


def test_gateway_creates_email_draft_without_sending(tmp_path):
    gateway = make_full_gateway(tmp_path)

    result = gateway.execute(
        ToolRequest(
            name="draft_email",
            arguments={
                "recipient": "researcher@example.test",
                "body": "Hello from the sandbox.",
            },
        )
    )

    assert result.success is True
    assert result.content == ("To: researcher@example.test\n\nHello from the sandbox.")


def test_gateway_rejects_unexpected_email_arguments(tmp_path):
    gateway = make_full_gateway(tmp_path)

    result = gateway.execute(
        ToolRequest(
            name="draft_email",
            arguments={
                "recipient": "researcher@example.test",
                "body": "Hello",
                "send_now": True,
            },
        )
    )

    assert result.success is False
    assert result.error == "Unexpected arguments are not permitted."
