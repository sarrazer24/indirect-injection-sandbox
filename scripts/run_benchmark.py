"""Run the deterministic Phase 5 baseline benchmark."""

from __future__ import annotations

import argparse
from pathlib import Path

from injection_sandbox.evaluation.dataset import load_jsonl, validate_dataset
from injection_sandbox.evaluation.reporting import render_report, write_jsonl
from injection_sandbox.evaluation.runner import run_mock_baseline


def _load_fixture_map(directory: Path) -> dict[str, str]:
    """Load approved document fixtures keyed by fixture ID."""
    return {
        path.stem: path.read_text(encoding="utf-8-sig") for path in sorted(directory.glob("*.txt"))
    }


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Run the deterministic C0 benchmark baseline.")
    parser.add_argument(
        "--attack-dataset",
        type=Path,
        default=repo_root / "datasets" / "attacks" / "indirect_injection.jsonl",
        help="Benchmark JSONL file to execute.",
    )
    parser.add_argument(
        "--fixture-dir",
        type=Path,
        default=repo_root / "datasets" / "fixtures" / "documents",
        help="Directory of approved fixture text files keyed by fixture ID.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=repo_root / "results",
        help="Directory for machine-readable logs and markdown summary.",
    )
    args = parser.parse_args()

    cases = load_jsonl(args.attack_dataset)
    fixtures = _load_fixture_map(args.fixture_dir)
    validate_dataset(
        cases,
        approved_document_ids=set(fixtures),
        approved_web_fixture_ids=set(),
    )
    records = run_mock_baseline(cases, fixtures)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    trial_path = args.output_dir / "phase5_baseline_trials.jsonl"
    report_path = args.output_dir / "phase5_baseline_report.md"

    write_jsonl(trial_path, records)
    report_path.write_text(render_report(records), encoding="utf-8")

    print(f"Wrote trial log: {trial_path}")
    print(f"Wrote baseline report: {report_path}")
    print(render_report(records))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
