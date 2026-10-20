"""Load and validate benchmark cases stored as JSON Lines."""

import json
from collections import defaultdict
from pathlib import Path

from pydantic import ValidationError

from injection_sandbox.evaluation.benchmark_schema import BenchmarkCase


class DatasetError(ValueError):
    """Raised when a benchmark dataset is invalid."""


def load_jsonl(path: Path) -> list[BenchmarkCase]:
    """Load benchmark cases from a JSONL file.

    Each non-empty line must contain one valid BenchmarkCase JSON object.
    Errors identify the file and line number without exposing file contents.
    """
    cases: list[BenchmarkCase] = []
    source = Path(path)

    try:
        with source.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    raw_case = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise DatasetError(
                        f"{source}:{line_number}: invalid JSON "
                        f"(line {exc.lineno}, column {exc.colno})"
                    ) from exc

                if not isinstance(raw_case, dict):
                    raise DatasetError(
                        f"{source}:{line_number}: each JSONL record must be an object"
                    )

                try:
                    case = BenchmarkCase.model_validate(raw_case)
                except ValidationError as exc:
                    error_summary = "; ".join(
                        f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                        for error in exc.errors(include_input=False)
                    )
                    raise DatasetError(
                        f"{source}:{line_number}: invalid benchmark case: {error_summary}"
                    ) from exc

                cases.append(case)

    except UnicodeDecodeError as exc:
        raise DatasetError(f"{source}: file is not valid UTF-8") from exc
    except OSError as exc:
        raise DatasetError(f"{source}: unable to read dataset file") from exc

    if not cases:
        raise DatasetError(f"{source}: dataset contains no benchmark cases")

    validate_dataset(cases)
    return cases


def validate_dataset(
    cases: list[BenchmarkCase],
    *,
    approved_document_ids: set[str] | None = None,
    approved_web_fixture_ids: set[str] | None = None,
) -> None:
    """Validate cross-case integrity and optional trusted fixture mappings.

    The fixture-ID sets should come from trusted application configuration,
    not from values supplied by benchmark records themselves.
    """
    if not cases:
        raise DatasetError("Dataset contains no benchmark cases")

    seen_ids: set[str] = set()
    family_splits: dict[str, set[str]] = defaultdict(set)

    for case in cases:
        if case.case_id in seen_ids:
            raise DatasetError(f"Duplicate case_id: {case.case_id}")
        seen_ids.add(case.case_id)

        family_splits[case.family_id].add(case.split)

        if (
            case.source_type == "document"
            and approved_document_ids is not None
            and case.fixture_id not in approved_document_ids
        ):
            raise DatasetError(f"Case {case.case_id} references an unapproved document ID")

        if (
            case.source_type == "web_fixture"
            and approved_web_fixture_ids is not None
            and case.fixture_id not in approved_web_fixture_ids
        ):
            raise DatasetError(f"Case {case.case_id} references an unapproved web fixture ID")

    for family_id, splits in family_splits.items():
        if len(splits) > 1:
            split_names = ", ".join(sorted(splits))
            raise DatasetError(
                f"Attack family {family_id!r} appears in multiple splits: {split_names}"
            )
