"""Read approved local HTML fixtures without making network requests."""

from collections.abc import Mapping
from pathlib import Path

from injection_sandbox.agent.schemas import ToolResult

DEFAULT_MAX_FIXTURE_BYTES = 20_000


class WebFixtureReader:
    """Read HTML fixtures addressed by trusted IDs under one configured root."""

    def __init__(
        self,
        fixtures_root: Path,
        approved_fixtures: Mapping[str, str],
        max_bytes: int = DEFAULT_MAX_FIXTURE_BYTES,
    ) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive.")

        self._root = Path(fixtures_root).resolve()
        if not self._root.is_dir():
            raise ValueError("The fixtures root must be an existing directory.")

        self._approved_fixtures = dict(approved_fixtures)
        self._max_bytes = max_bytes

    def read(self, fixture_id: str) -> ToolResult:
        """Read one approved fixture and return bounded HTML text."""

        if not isinstance(fixture_id, str) or not fixture_id.strip():
            return self._failure("A valid fixture ID is required.")

        relative_path = self._approved_fixtures.get(fixture_id)
        if relative_path is None:
            return self._failure("Fixture ID is not approved.")

        try:
            requested_path = Path(relative_path)

            if requested_path.is_absolute():
                return self._failure("Approved fixture configuration is invalid.")

            resolved_path = (self._root / requested_path).resolve(strict=True)

            if not resolved_path.is_relative_to(self._root):
                return self._failure("Fixture path escapes the approved directory.")

            if not resolved_path.is_file():
                return self._failure("Approved fixture is not a regular file.")

            with resolved_path.open("rb") as fixture_file:
                raw_content = fixture_file.read(self._max_bytes + 1)

            if len(raw_content) > self._max_bytes:
                return self._failure("Fixture exceeds the maximum allowed size.")

            content = raw_content.decode("utf-8", errors="strict")

        except UnicodeDecodeError:
            return self._failure("Fixture is not valid UTF-8 text.")
        except (OSError, RuntimeError, ValueError):
            return self._failure("Fixture could not be read safely.")

        return ToolResult(
            tool_name="read_web_fixture",
            success=True,
            content=content,
        )

    @staticmethod
    def _failure(message: str) -> ToolResult:
        return ToolResult(
            tool_name="read_web_fixture",
            success=False,
            error=message,
        )
