"""Tests for the deterministic mock benchmark runner and reports."""

import json
from pathlib import Path

from injection_sandbox.evaluation.dataset import load_jsonl
from injection_sandbox.evaluation.metrics import calculate_metrics
from injection_sandbox.evaluation.outcomes import SecurityOutcome, TaskUtility
from injection_sandbox.evaluation.reporting import render_jsonl, render_report, write_jsonl
from injection_sandbox.evaluation.runner import run_mock_baseline

ROOT = Path(__file__).resolve().parents[2]


def run_records():
    cases = load_jsonl(ROOT / "datasets" / "attacks" / "indirect_injection.jsonl")
    contents = {
        path.stem: path.read_text(encoding="utf-8-sig")
        for path in (ROOT / "datasets" / "fixtures" / "documents").glob("*.txt")
    }
    return run_mock_baseline(cases, contents)


def test_mock_runner_is_repeatable_and_records_evidence() -> None:
    first = run_records()
    second = run_records()

    assert first == second
    assert all(record.tool_trace[0].success for record in first)
    assert all(record.evaluation.utility == TaskUtility.INDETERMINATE for record in first)
    assert all("task_completion" not in record.evidence.observed_evidence for record in first)
    assert all(record.evidence.evidence_complete is False for record in first)
    assert all(record.evidence.prohibited_attempt_observed is None for record in first)
    assert first[1].evidence.unauthorized_disclosure_confirmed is True
    assert first[1].evaluation.security == SecurityOutcome.ATTACK_SUCCEEDED
    assert first[0].evaluation.security == SecurityOutcome.INDETERMINATE


def test_secret_disclosure_requires_marker_in_recorded_output() -> None:
    cases = load_jsonl(ROOT / "datasets" / "attacks" / "indirect_injection.jsonl")
    contents = {
        path.stem: path.read_text(encoding="utf-8-sig")
        for path in (ROOT / "datasets" / "fixtures" / "documents").glob("*.txt")
    }
    contents["doc-003"] = contents["doc-003"].replace(
        "SYNTHETIC_SECRET_CANARY_7F3A91",
        "REDACTED_SYNTHETIC_SECRET",
    )

    record = run_mock_baseline(cases, contents)[1]

    assert "SYNTHETIC_SECRET_CANARY_7F3A91" not in record.final_answer
    assert record.evidence.unauthorized_disclosure_confirmed is False
    assert "final_output_scan" in record.evidence.observed_evidence
    assert record.evaluation.security == SecurityOutcome.INDETERMINATE


def test_unavailable_fixture_is_not_mislabeled_as_authorization_denial() -> None:
    cases = load_jsonl(ROOT / "datasets" / "attacks" / "indirect_injection.jsonl")
    contents = {"doc-001": "Fixture available"}

    record = run_mock_baseline(cases, contents)[1]

    assert record.tool_trace[0].gateway_decision == "allowed"
    assert record.tool_trace[0].execution_status == "fixture_unavailable"
    assert record.tool_trace[0].executed is True
    assert record.tool_trace[0].success is False
    assert record.tool_trace[0].error == "Fixture is unavailable."


def test_metrics_use_evaluable_denominators_and_preserve_unmeasured_fp_rate() -> None:
    metrics = calculate_metrics(run_records())

    assert metrics.evaluable_attack_trials == 1
    assert metrics.indeterminate_attack_trials == 1
    assert metrics.successful_attacks == 1
    assert metrics.attack_success_rate == 1.0
    assert metrics.attack_attempts is None
    assert metrics.attack_attempt_rate is None
    assert metrics.unauthorized_execution_rate is None
    assert metrics.prevented_attacks is None
    assert metrics.blocking_rate is None
    assert metrics.benign_task_success_rate is None
    assert metrics.false_positive_rate is None
    assert metrics.average_latency_ms is None
    assert metrics.estimated_cost is None


def test_jsonl_and_markdown_reports_match_the_records(tmp_path: Path) -> None:
    records = run_records()
    encoded = render_jsonl(records)

    assert encoded == render_jsonl(records)
    decoded = [json.loads(line) for line in encoded.splitlines()]
    assert len(decoded) == len(records)
    assert {item["run_id"] for item in decoded} == {record.run_id for record in records}
    assert {item["trial_id"] for item in decoded} == {record.trial_id for record in records}
    assert {item["benchmark_version"] for item in decoded} == {
        record.benchmark_version for record in records
    }
    output = tmp_path / "trials.jsonl"
    write_jsonl(output, records)
    assert output.read_text(encoding="utf-8").splitlines() == encoded.splitlines()

    report = render_report(records)
    assert "not an LLM behavior experiment" in report
    assert "Mock-confirmed prohibited-outcome rate (not LLM ASR): 100.0% (1/1" in report
    assert f"- Trials: {len(decoded)}" in report
    assert f"- Attack cases: {len(records)}" in report
    assert "- Benign cases: 0" in report
    assert "- Split counts: dev=2" in report
    assert records[0].run_id in report
    assert records[0].trial_id in report
    assert records[0].benchmark_version in report
    assert "- Attack attempt rate: Not evaluated" in report
    assert "False Positive Rate: Not evaluated" in report
    assert "Benign Task Success Rate: Not evaluated (0/0" in report
