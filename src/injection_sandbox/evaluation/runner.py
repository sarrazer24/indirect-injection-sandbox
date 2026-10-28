"""Deterministic mock-model baseline for benchmark execution.

This harness deliberately uses an echo model: it requests only the case's approved
source fixture and echoes its contents. It is a pipeline smoke-test baseline, not a
claim about real model behavior or semantic task quality.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict

from injection_sandbox.agent.schemas import ToolRequest, ToolResult
from injection_sandbox.evaluation.benchmark_schema import BenchmarkCase
from injection_sandbox.evaluation.outcomes import (
    EvaluationResult,
    OutcomeEvidence,
    classify_evaluation,
)
from injection_sandbox.security.gateway import ToolGateway
from injection_sandbox.security.policy import authorize_tool
from injection_sandbox.tools.registry import ToolRegistry

MODEL_ID = "deterministic-echo-mock-v1"
BENCHMARK_VERSION_PREFIX = "sha256:"


class ToolTrace(BaseModel):
    """Observable mock tool request, authorization, and execution record."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    tool: str
    resource_id: str
    gateway_decision: Literal["allowed", "denied"]
    execution_status: Literal["not_executed", "succeeded", "failed", "fixture_unavailable"]
    executed: bool
    success: bool
    error: str | None = None


class CaseRunRecord(BaseModel):
    """Stable per-case benchmark result; no wall-clock fields are included."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    run_id: str
    trial_id: str
    configuration: Literal["C0"]
    model_id: str
    benchmark_version: str
    case_id: str
    case_type: Literal["attack", "benign"]
    split: Literal["dev", "validation", "held_out"]
    trial: int
    final_answer: str
    tool_trace: list[ToolTrace]
    evidence: OutcomeEvidence
    evaluation: EvaluationResult
    latency_ms: float | None = None


class DeterministicEchoModel:
    """A deterministic mock that returns retrieved fixture text verbatim."""

    model_id = MODEL_ID

    def generate(self, *, task: str, retrieved_content: str) -> str:
        """Return fixture contents verbatim; ``task`` is intentionally not interpreted."""
        del task
        return retrieved_content


def _read_fixture(
    case: BenchmarkCase,
    fixture_contents: Mapping[str, str],
) -> tuple[ToolResult, bool]:
    """Read the case fixture through the same registry/gateway boundary as tools."""
    tool = "read_document" if case.source_type == "document" else "read_web_fixture"
    operation = next(
        (
            item
            for item in case.allowed_operations
            if item.tool == tool and case.fixture_id in item.resource_ids
        ),
        None,
    )
    if operation is None:
        return (
            ToolResult(
                tool_name=tool,
                success=False,
                error="The case does not authorize its source fixture.",
            ),
            False,
        )

    def handle(arguments: Mapping[str, object]) -> ToolResult:
        id_argument = "document_id" if tool == "read_document" else "fixture_id"
        resource_id = arguments.get(id_argument)
        if resource_id != case.fixture_id:
            return ToolResult(tool_name=tool, success=False, error="Fixture is not approved.")
        content = fixture_contents.get(case.fixture_id)
        if content is None:
            return ToolResult(tool_name=tool, success=False, error="Fixture is unavailable.")
        return ToolResult(tool_name=tool, success=True, content=content)

    registry = ToolRegistry()
    registry.register(tool, handle)
    request = ToolRequest(
        name=tool,
        arguments={
            "document_id" if tool == "read_document" else "fixture_id": case.fixture_id,
        },
    )
    decision = authorize_tool(request)
    result = ToolGateway(registry).execute(request)
    return result, decision.allowed


def _benchmark_version(cases: Sequence[BenchmarkCase]) -> str:
    """Hash the exact case definitions used by this run."""
    serialized = json.dumps(
        [case.model_dump(mode="json") for case in sorted(cases, key=lambda item: item.case_id)],
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    return BENCHMARK_VERSION_PREFIX + hashlib.sha256(serialized).hexdigest()


def run_mock_baseline(
    cases: Sequence[BenchmarkCase],
    fixture_contents: Mapping[str, str],
    *,
    run_id: str | None = None,
    trial: int = 1,
) -> list[CaseRunRecord]:
    """Run the deterministic C0 echo baseline against supplied trusted fixtures.

    ``fixture_contents`` is supplied by the harness and keyed by approved fixture ID;
    cases never provide paths. The returned run ID is content-addressed unless one is
    explicitly supplied, so identical inputs produce identical records.
    """
    if not cases:
        raise ValueError("At least one benchmark case is required.")
    if trial < 1:
        raise ValueError("trial must be a positive integer.")
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("Benchmark case IDs must be unique within a run.")

    model = DeterministicEchoModel()
    benchmark_version = _benchmark_version(cases)
    if run_id is None:
        identity = {
            "configuration": "C0",
            "model_id": model.model_id,
            "benchmark_version": benchmark_version,
            "trial": trial,
            "cases": [
                {
                    "case_id": case.case_id,
                    "fixture_id": case.fixture_id,
                    "content": fixture_contents.get(case.fixture_id),
                }
                for case in sorted(cases, key=lambda item: item.case_id)
            ],
        }
        digest = hashlib.sha256(
            json.dumps(identity, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()[:16]
        run_id = f"mock-{digest}"

    records: list[CaseRunRecord] = []
    for case in cases:
        tool = "read_document" if case.source_type == "document" else "read_web_fixture"
        result, authorized = _read_fixture(case, fixture_contents)
        if not authorized:
            execution_status = "not_executed"
        elif result.success:
            execution_status = "succeeded"
        elif result.error == "Fixture is unavailable.":
            execution_status = "fixture_unavailable"
        else:
            execution_status = "failed"
        trace = ToolTrace(
            tool=tool,
            resource_id=case.fixture_id,
            gateway_decision="allowed" if authorized else "denied",
            execution_status=execution_status,
            executed=authorized,
            success=result.success,
            error=result.error,
        )
        answer = model.generate(
            task=case.user_task,
            retrieved_content=result.content or "",
        )
        output_scan_completed = True
        disclosure = any(marker in answer for marker in case.synthetic_secret_markers)
        observed = [
            "tool_request_trace",
            "gateway_decision",
            "tool_execution_result",
        ]
        if output_scan_completed:
            observed.append("final_output_scan")
        observed_evidence = observed
        # The echo mock does not produce model-proposed actions or assess task
        # completion, hijacking, draft manipulation, or policy changes.
        evidence_complete = set(case.required_evidence).issubset(observed_evidence)
        security_checks_completed = (
            evidence_complete
            and output_scan_completed
            and set(case.prohibited_outcomes) <= {"synthetic_secret_disclosure"}
        )
        evidence = OutcomeEvidence(
            prohibited_attempt_observed=None,
            gateway_decision="not_applicable",
            control_block_confirmed=False,
            blocking_control="not_applicable",
            unauthorized_execution_confirmed=False,
            unauthorized_disclosure_confirmed=disclosure,
            other_prohibited_outcome_confirmed=False,
            security_checks_completed=security_checks_completed,
            task_completion_confirmed=None,
            evidence_complete=evidence_complete,
            observed_evidence=observed_evidence,
            evidence_notes=(
                "Deterministic echo smoke test only. The harness records one source-tool "
                "request, its gateway result, and a final-output marker scan. It does not "
                "generate adversarial tool proposals or evaluate semantic task completion."
            ),
        )
        evaluation = classify_evaluation(case, evidence)
        records.append(
            CaseRunRecord(
                run_id=run_id,
                trial_id=f"{run_id}:{case.case_id}:trial-{trial}",
                configuration="C0",
                model_id=model.model_id,
                benchmark_version=benchmark_version,
                case_id=case.case_id,
                case_type=case.case_type,
                split=case.split,
                trial=trial,
                final_answer=answer,
                tool_trace=[trace],
                evidence=evidence,
                evaluation=evaluation,
            )
        )
    return records
