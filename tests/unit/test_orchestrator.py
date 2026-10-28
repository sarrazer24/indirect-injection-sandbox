from pathlib import Path

from injection_sandbox.agent.orchestrator import C0AgentLoop
from injection_sandbox.security.gateway import ToolGateway
from injection_sandbox.tools.adapters import make_document_reader_handler
from injection_sandbox.tools.file_reader import DocumentReader
from injection_sandbox.tools.registry import ToolRegistry


class FakeAdapter:
    def __init__(self, *, proposal=None, error=None):
        self.proposal = proposal
        self.error = error

    def generate_json(self, user_message: str, *, system_prompt: str | None = None, history=None):
        del user_message, system_prompt, history
        if self.error is not None:
            raise self.error
        return self.proposal


def _make_gateway(tmp_path: Path) -> tuple[ToolGateway, list[tuple[str, dict[str, object]]]]:
    documents_root = tmp_path / "docs"
    documents_root.mkdir()
    (documents_root / "public.txt").write_text("approved content", encoding="utf-8")

    calls: list[tuple[str, dict[str, object]]] = []

    def tracking_handler(arguments: dict[str, object]):
        calls.append(("read_document", dict(arguments)))
        return make_document_reader_handler(
            DocumentReader(
                documents_root,
                {"public_report": "public.txt"},
            )
        )(arguments)

    registry = ToolRegistry()
    registry.register("read_document", tracking_handler)
    return ToolGateway(registry), calls


def test_agent_loop_executes_valid_tool_request(tmp_path):
    gateway, calls = _make_gateway(tmp_path)
    adapter = FakeAdapter(
        proposal={
            "name": "read_document",
            "arguments": {"document_id": "public_report"},
        }
    )

    result = C0AgentLoop(adapter, gateway).run("Read the public report")

    assert result.success is True
    assert result.content == "approved content"
    assert result.tool_name == "read_document"
    assert calls == [("read_document", {"document_id": "public_report"})]


def test_agent_loop_handles_invalid_json(tmp_path):
    del tmp_path
    adapter = FakeAdapter(error=ValueError("Model output is not valid JSON."))

    result = C0AgentLoop(adapter).run("Read the public report")

    assert result.success is False
    assert result.error == "Model output is not valid JSON."


def test_agent_loop_denies_unauthorized_proposals(tmp_path):
    gateway, calls = _make_gateway(tmp_path)
    adapter = FakeAdapter(
        proposal={
            "name": "read_document",
            "arguments": {"document_id": "public_report", "path": "../../secret.txt"},
        }
    )

    result = C0AgentLoop(adapter, gateway).run("Read the public report")

    assert result.success is False
    assert result.error == "Unexpected arguments are not permitted."
    assert calls == []


def test_agent_loop_rejects_extra_proposal_fields(tmp_path):
    gateway, calls = _make_gateway(tmp_path)
    adapter = FakeAdapter(
        proposal={
            "name": "read_document",
            "arguments": {"document_id": "public_report"},
            "debug": "should-not-pass",
        }
    )

    result = C0AgentLoop(adapter, gateway).run("Read the public report")

    assert result.success is False
    assert result.error == "Model proposal must include exactly 'name' and 'arguments'."
    assert calls == []


def test_agent_loop_rejects_unknown_tool(tmp_path):
    gateway, calls = _make_gateway(tmp_path)
    adapter = FakeAdapter(
        proposal={
            "name": "delete_document",
            "arguments": {"document_id": "public_report"},
        }
    )

    result = C0AgentLoop(adapter, gateway).run("Read the public report")

    assert result.success is False
    assert result.error == "Tool is not allowlisted."
    assert calls == []


def test_agent_loop_rejects_malformed_arguments(tmp_path):
    gateway, calls = _make_gateway(tmp_path)
    adapter = FakeAdapter(
        proposal={
            "name": "read_document",
            "arguments": {"document_id": ["not", "a", "string"]},
        }
    )

    result = C0AgentLoop(adapter, gateway).run("Read the public report")

    assert result.success is False
    assert result.error == "Tool proposal failed validation."
    assert calls == []
