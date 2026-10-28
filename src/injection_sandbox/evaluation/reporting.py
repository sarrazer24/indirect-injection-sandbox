"""Deterministic serialization and concise benchmark reporting."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from injection_sandbox.evaluation.metrics import BenchmarkMetrics, calculate_metrics
from injection_sandbox.evaluation.runner import CaseRunRecord


def render_markdown(metrics: BenchmarkMetrics) -> str:
    """Render aggregate results without implying real-model evaluation."""

    def display(value: float | None) -> str:
        return "Not evaluated" if value is None else f"{value:.1%}"

    latency = (
        "Not measured"
        if metrics.average_latency_ms is None
        else f"{metrics.average_latency_ms:.2f} ms"
    )
    cost = "Not measured" if metrics.estimated_cost is None else f"{metrics.estimated_cost:.6f}"
    return "\n".join(
        (
            "# Deterministic Echo Pipeline Smoke Test",
            "",
            (
                "This is a deterministic pipeline check, not an LLM behavior experiment. "
                "Its observed-outcome rate is not a real-model attack success rate or evidence "
                "of defense effectiveness."
            ),
            "",
            f"- Trials: {metrics.total_trials}",
            (
                f"- Mock-confirmed prohibited-outcome rate (not LLM ASR): "
                f"{display(metrics.attack_success_rate)} "
                f"({metrics.successful_attacks}/{metrics.evaluable_attack_trials} evaluable attack cases)"
            ),
            f"- Attack attempt rate: {display(metrics.attack_attempt_rate)}",
            f"- Unauthorized execution rate: {display(metrics.unauthorized_execution_rate)}",
            f"- Blocking rate: {display(metrics.blocking_rate)}",
            (
                f"- Benign Task Success Rate: {display(metrics.benign_task_success_rate)} "
                f"({metrics.successful_benign_tasks}/{metrics.evaluable_benign_trials} evaluable benign trials)"
            ),
            f"- False Positive Rate: {display(metrics.false_positive_rate)}",
            (
                f"- Execution-error rate: {display(metrics.execution_error_rate)} "
                f"({metrics.execution_error_trials}/{metrics.total_trials} trials)"
            ),
            f"- Average latency: {latency}",
            f"- Estimated cost: {cost}",
            "",
            (
                "Attack-attempt and unauthorized-execution metrics are unavailable because "
                "the echo mock does not produce agent-proposed prohibited actions. "
                "Indeterminate cases are excluded from evaluable denominators. False-positive "
                "performance is unavailable because this run has no blocking detector."
            ),
        )
    )


def render_jsonl(records: Iterable[CaseRunRecord]) -> str:
    """Serialize per-case records to stable UTF-8 JSON Lines text."""
    return "".join(
        json.dumps(record.model_dump(mode="json"), sort_keys=True, ensure_ascii=False) + "\n"
        for record in records
    )


def write_jsonl(path: Path, records: Iterable[CaseRunRecord]) -> None:
    """Persist structured per-case logs; does not create missing parent directories."""
    Path(path).write_text(render_jsonl(records), encoding="utf-8", newline="\n")


def render_report(records: Iterable[CaseRunRecord]) -> str:
    """Render run metadata and Markdown metrics from the same trial records."""
    materialized = list(records)
    if not materialized:
        raise ValueError("At least one trial record is required to render a report.")

    metrics = calculate_metrics(materialized)
    split_counts = Counter(record.split for record in materialized)
    case_type_counts = Counter(record.case_type for record in materialized)
    run_ids = sorted({record.run_id for record in materialized})
    trial_ids = sorted({record.trial_id for record in materialized})
    benchmark_versions = sorted({record.benchmark_version for record in materialized})
    configurations = sorted({record.configuration for record in materialized})
    model_ids = sorted({record.model_id for record in materialized})

    metadata = [
        f"- Configuration: {', '.join(configurations)}",
        f"- Model: {', '.join(model_ids)}",
        f"- Benchmark version: {', '.join(benchmark_versions)}",
        f"- Run IDs: {', '.join(run_ids)}",
        f"- Trial IDs: {', '.join(trial_ids)}",
        f"- Attack cases: {case_type_counts['attack']}",
        f"- Benign cases: {case_type_counts['benign']}",
        "- Split counts: "
        + ", ".join(f"{split}={split_counts[split]}" for split in sorted(split_counts)),
    ]
    return render_markdown(metrics).replace(
        "\n- Trials:",
        "\n" + "\n".join(metadata) + "\n- Trials:",
        1,
    )
