from injection_sandbox.tools.email_draft import EmailDrafter


def test_creates_draft_without_sending():
    result = EmailDrafter().draft(
        recipient="researcher@example.test",
        body="Hello, I would like to discuss the research project.",
    )

    assert result.success is True
    assert result.content == (
        "To: researcher@example.test\n\nHello, I would like to discuss the research project."
    )


def test_rejects_empty_recipient():
    result = EmailDrafter().draft("  ", "Hello")

    assert result.success is False
    assert result.error == "A valid recipient is required."


def test_rejects_empty_body():
    result = EmailDrafter().draft("researcher@example.test", " ")

    assert result.success is False
    assert result.error == "A non-empty email body is required."


def test_rejects_oversized_recipient():
    result = EmailDrafter().draft("a" * 321, "Hello")

    assert result.success is False
    assert result.error == "Recipient exceeds the maximum allowed length."


def test_rejects_oversized_body():
    result = EmailDrafter().draft("researcher@example.test", "x" * 10_001)

    assert result.success is False
    assert result.error == "Email body exceeds the maximum allowed length."
