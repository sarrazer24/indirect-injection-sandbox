"""Strict schemas for Phase 4 benchmark cases."""

from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

CaseId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9_-]*$",
    ),
]

ShortText = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=2000),
]

SecretMarker = Annotated[
    str,
    StringConstraints(strict=True, min_length=4, max_length=128),
]

AttackCategory = Literal[
    "instruction_override",
    "unauthorized_tool_use",
    "unauthorized_resource_access",
    "synthetic_secret_disclosure",
    "draft_manipulation",
    "argument_manipulation",
    "policy_configuration_manipulation",
]

DeliveryTechnique = Literal[
    "plain_text",
    "obfuscation",
    "formatting",
    "encoding",
]

ProhibitedOutcome = Literal[
    "task_hijacking",
    "unauthorized_tool_execution",
    "unauthorized_resource_access",
    "synthetic_secret_disclosure",
    "unauthorized_draft_creation",
    "unauthorized_draft_content",
    "policy_modification",
]

ToolName = Literal[
    "read_document",
    "read_web_fixture",
    "draft_email",
]

EvidenceRequirement = Literal[
    "tool_request_trace",
    "gateway_decision",
    "tool_execution_result",
    "final_output_scan",
    "task_completion",
]


class AllowedOperation(BaseModel):
    """An operation the agent is permitted to perform for a benchmark case."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    tool: ToolName
    resource_ids: list[CaseId] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_operation(self) -> "AllowedOperation":
        """Require resource scoping for resource-reading tools."""
        if self.tool in {"read_document", "read_web_fixture"}:
            if not self.resource_ids:
                raise ValueError("Resource-reading operations require approved resource IDs")
        elif self.resource_ids:
            raise ValueError("Only resource-reading operations may declare resource IDs")

        if len(self.resource_ids) != len(set(self.resource_ids)):
            raise ValueError("resource_ids must not contain duplicates")

        return self


class BenchmarkCase(BaseModel):
    """One attack or benign-control case in the benchmark."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
    )

    case_id: CaseId
    case_type: Literal["attack", "benign"]
    split: Literal["dev", "validation", "held_out"]
    family_id: CaseId

    source_type: Literal["document", "web_fixture"]
    fixture_id: CaseId

    user_task: ShortText
    expected_behavior: Literal[
        "complete_task",
        "ignore_injection_and_complete_task",
    ]

    allowed_operations: list[AllowedOperation]
    required_evidence: list[EvidenceRequirement]

    attack_categories: list[AttackCategory] = Field(default_factory=list)
    delivery_techniques: list[DeliveryTechnique] = Field(default_factory=list)
    prohibited_outcomes: list[ProhibitedOutcome] = Field(default_factory=list)
    synthetic_secret_markers: list[SecretMarker] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_case_consistency(self) -> "BenchmarkCase":
        """Ensure fields agree with the declared case type."""

        list_fields = (
            ("attack_categories", self.attack_categories),
            ("delivery_techniques", self.delivery_techniques),
            ("prohibited_outcomes", self.prohibited_outcomes),
            ("synthetic_secret_markers", self.synthetic_secret_markers),
            ("required_evidence", self.required_evidence),
        )

        for field_name, values in list_fields:
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must not contain duplicates")

        if not self.allowed_operations:
            raise ValueError("Cases require at least one allowed operation")

        if not self.required_evidence:
            raise ValueError("Cases require at least one evidence requirement")

        operation_keys = [
            (operation.tool, tuple(operation.resource_ids)) for operation in self.allowed_operations
        ]
        if len(operation_keys) != len(set(operation_keys)):
            raise ValueError("allowed_operations must not contain duplicates")

        source_tool = "read_document" if self.source_type == "document" else "read_web_fixture"

        if not any(
            operation.tool == source_tool and self.fixture_id in operation.resource_ids
            for operation in self.allowed_operations
        ):
            raise ValueError("Allowed operations must include the case's source fixture")

        if self.case_type == "attack":
            if not self.attack_categories:
                raise ValueError("Attack cases require at least one attack category")

            if not self.delivery_techniques:
                raise ValueError("Attack cases require at least one delivery technique")

            if not self.prohibited_outcomes:
                raise ValueError("Attack cases require at least one prohibited outcome")

            if self.expected_behavior != "ignore_injection_and_complete_task":
                raise ValueError(
                    "Attack cases must ignore the injection and complete the legitimate task"
                )

        if self.case_type == "benign":
            if self.attack_categories:
                raise ValueError("Benign cases must not declare attack categories")

            if self.delivery_techniques:
                raise ValueError("Benign cases must not declare attack delivery techniques")

            if self.prohibited_outcomes:
                raise ValueError("Benign cases must not declare attack outcomes")

            if self.synthetic_secret_markers:
                raise ValueError("Benign cases must not declare synthetic secret markers")

            if self.expected_behavior != "complete_task":
                raise ValueError("Benign cases must expect normal task completion")

        if (
            "synthetic_secret_disclosure" in self.attack_categories
            and not self.synthetic_secret_markers
        ):
            raise ValueError("Secret-disclosure cases require at least one synthetic secret marker")

        return self
