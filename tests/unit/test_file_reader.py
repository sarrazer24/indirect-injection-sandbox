from pathlib import Path

from injection_sandbox.tools.file_reader import DocumentReader


def make_reader(
    tmp_path: Path,
    documents: dict[str, str],
    max_bytes: int = 20_000,
) -> DocumentReader:
    root = tmp_path / "documents"
    root.mkdir(exist_ok=True)

    return DocumentReader(
        documents_root=root,
        approved_documents=documents,
        max_bytes=max_bytes,
    )


def test_reads_approved_document(tmp_path):
    root = tmp_path / "documents"
    root.mkdir()
    (root / "welcome.txt").write_text("Synthetic test document.", encoding="utf-8")

    reader = DocumentReader(root, {"doc-001": "welcome.txt"})
    result = reader.read("doc-001")

    assert result.success is True
    assert result.content == "Synthetic test document."
    assert result.error is None


def test_rejects_unknown_document_id(tmp_path):
    reader = make_reader(tmp_path, {"doc-001": "welcome.txt"})

    result = reader.read("doc-999")

    assert result.success is False
    assert result.error == "Document ID is not approved."


def test_rejects_empty_document_id(tmp_path):
    reader = make_reader(tmp_path, {})

    result = reader.read("")

    assert result.success is False


def test_rejects_path_traversal(tmp_path):
    root = tmp_path / "documents"
    root.mkdir()
    (tmp_path / "secret.txt").write_text("Synthetic secret.", encoding="utf-8")

    reader = DocumentReader(root, {"doc-evil": "../secret.txt"})
    result = reader.read("doc-evil")

    assert result.success is False
    assert result.error == "Document path escapes the approved directory."


def test_rejects_absolute_path_in_configuration(tmp_path):
    root = tmp_path / "documents"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("Synthetic secret.", encoding="utf-8")

    reader = DocumentReader(root, {"doc-evil": str(outside)})
    result = reader.read("doc-evil")

    assert result.success is False
    assert result.error == "Approved document configuration is invalid."


def test_rejects_oversized_document(tmp_path):
    root = tmp_path / "documents"
    root.mkdir()
    (root / "large.txt").write_text("x" * 11, encoding="utf-8")

    reader = DocumentReader(root, {"doc-large": "large.txt"}, max_bytes=10)
    result = reader.read("doc-large")

    assert result.success is False
    assert result.error == "Document exceeds the maximum allowed size."


def test_missing_approved_file_fails_safely(tmp_path):
    reader = make_reader(tmp_path, {"doc-missing": "missing.txt"})

    result = reader.read("doc-missing")

    assert result.success is False
    assert result.error == "Document could not be read safely."


def test_invalid_utf8_fails_safely(tmp_path):
    root = tmp_path / "documents"
    root.mkdir()
    (root / "invalid.txt").write_bytes(b"\xff\xfe")

    reader = DocumentReader(root, {"doc-invalid": "invalid.txt"})
    result = reader.read("doc-invalid")

    assert result.success is False
    assert result.error == "Document is not valid UTF-8 text."


def test_rejects_non_positive_size_limit(tmp_path):
    root = tmp_path / "documents"
    root.mkdir()

    try:
        DocumentReader(root, {}, max_bytes=0)
    except ValueError as exc:
        assert "positive" in str(exc)
    else:
        raise AssertionError("Expected invalid size limit to be rejected.")
