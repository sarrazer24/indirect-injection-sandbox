
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolRequest:
    name: str
    arguments: dict[str, object]


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


ALLOWED_TOOLS = {
    "read_document",
    "read_web_fixture",
    "draft_email",
}


def authorize_tool(request: ToolRequest) -> PolicyDecision:
    """Apply deterministic authorization before any tool executes."""

    if request.name not in ALLOWED_TOOLS:
        return PolicyDecision(
            allowed=False,
            reason="Tool is not allowlisted.",
        )

    if request.name == "draft_email":
        recipient = request.arguments.get("recipient")
        body = request.arguments.get("body")

        if not isinstance(recipient, str) or not recipient.strip():
            return PolicyDecision(False, "A valid recipient is required.")

        if not isinstance(body, str) or not body.strip():
            return PolicyDecision(False, "A non-empty email body is required.")

        # Drafting is permitted; sending is not implemented.
        return PolicyDecision(True, "Email draft permitted; sending unavailable.")

    if request.name == "read_document":
        document_id = request.arguments.get("document_id")

        if not isinstance(document_id, str) or not document_id.strip():
            return PolicyDecision(False, "A document ID is required.")

        return PolicyDecision(True, "Document read request permitted.")

    if request.name == "read_web_fixture":
        fixture_id = request.arguments.get("fixture_id")

        if not isinstance(fixture_id, str) or not fixture_id.strip():
            return PolicyDecision(False, "A fixture ID is required.")

        return PolicyDecision(True, "Fixture read request permitted.")

    return PolicyDecision(False, "No policy defined for this tool.")
