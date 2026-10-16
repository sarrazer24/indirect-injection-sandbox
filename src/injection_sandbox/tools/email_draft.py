"""Create email drafts without sending messages."""

from injection_sandbox.agent.schemas import ToolResult

MAX_RECIPIENT_LENGTH = 320
MAX_BODY_LENGTH = 10_000


class EmailDrafter:
    """Create bounded drafts in memory; never send email."""

    def draft(self, recipient: str, body: str) -> ToolResult:
        """Validate and format an email draft."""

        if not isinstance(recipient, str) or not recipient.strip():
            return self._failure("A valid recipient is required.")

        if len(recipient) > MAX_RECIPIENT_LENGTH:
            return self._failure("Recipient exceeds the maximum allowed length.")

        if not isinstance(body, str) or not body.strip():
            return self._failure("A non-empty email body is required.")

        if len(body) > MAX_BODY_LENGTH:
            return self._failure("Email body exceeds the maximum allowed length.")

        return ToolResult(
            tool_name="draft_email",
            success=True,
            content=f"To: {recipient.strip()}\n\n{body.strip()}",
        )

    @staticmethod
    def _failure(message: str) -> ToolResult:
        return ToolResult(
            tool_name="draft_email",
            success=False,
            error=message,
        )
