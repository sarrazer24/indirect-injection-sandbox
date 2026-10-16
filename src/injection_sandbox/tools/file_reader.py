"""Read approved synthetic documents without accepting model-supplied paths."""

from collections.abc import Mapping
from pathlib import Path

from injection_sandbox.agent.schemas import ToolResult

DEFAULT_MAX_DOCUMENT_BYTES = 20_000


class DocumentReader:
    """Read documents addressed by trusted IDs under one configured root."""

    def __init__(
        self,
        documents_root: Path,
        approved_documents: Mapping[str, str],
        max_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES,
    ) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive.")

        self._root = Path(documents_root).resolve()
        if not self._root.is_dir():
            raise ValueError("The documents root must be an existing directory.")

        self._approved_documents = dict(approved_documents)
        self._max_bytes = max_bytes

    def read(self, document_id: str) -> ToolResult:
        """Read an approved document and return a bounded structured result."""

        if not isinstance(document_id, str) or not document_id.strip():
            return self._failure("A valid document ID is required.")

        relative_path = self._approved_documents.get(document_id)
        if relative_path is None:
            return self._failure("Document ID is not approved.")

        try:
            requested_path = Path(relative_path)

            if requested_path.is_absolute():
                return self._failure("Approved document configuration is invalid.")

            resolved_path = (self._root / requested_path).resolve(strict=True)

            if not resolved_path.is_relative_to(self._root):
                return self._failure("Document path escapes the approved directory.")

            if not resolved_path.is_file():
                return self._failure("Approved document is not a regular file.")

            # Read at most one byte beyond the limit to detect oversized files.
            with resolved_path.open("rb") as document_file:
                raw_content = document_file.read(self._max_bytes + 1)

            if len(raw_content) > self._max_bytes:
                return self._failure("Document exceeds the maximum allowed size.")

            content = raw_content.decode("utf-8", errors="strict")

        except UnicodeDecodeError:
            return self._failure("Document is not valid UTF-8 text.")
        except (OSError, RuntimeError, ValueError):
            return self._failure("Document could not be read safely.")

        return ToolResult(
            tool_name="read_document",
            success=True,
            content=content,
        )

    @staticmethod
    def _failure(message: str) -> ToolResult:
        return ToolResult(
            tool_name="read_document",
            success=False,
            error=message,
        )
