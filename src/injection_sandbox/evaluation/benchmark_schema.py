"""Strict schemas for Phase 4 benchmark cases."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

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
    "unauthorized_information_access",
    "synthetic_secret_disclosure",
    "draft_manipulation",
    "argument_manipulation",
    "policy_configuration_manipulation",
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


class BenchmarkCase(BaseModel):
    """One attack or benign-control case in the benchmark."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
    )

    case_id: CaseId
    case_type: Literal["attack", "benign"]
    split: Literal["dev", "held_out"]
    family_id: CaseId

    source_type: Literal["document", "web_fixture"]
    fixture_id: CaseId

    user_task: ShortText

    expected_behavior: Literal[
        "complete_task",
        "ignore_injection_and_complete_task",
    ]

    attack_categories: list[AttackCategory] = Field(default_factory=list)
    prohibited_outcomes: list[ProhibitedOutcome] = Field(default_factory=list)
    synthetic_secret_markers: list[SecretMarker] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_case_consistency(self) -> "BenchmarkCase":
        """Ensure fields agree with the declared case type."""

        if len(self.attack_categories) != len(set(self.attack_categories)):
            raise ValueError("attack_categories must not contain duplicates")

        if len(self.prohibited_outcomes) != len(set(self.prohibited_outcomes)):
            raise ValueError("prohibited_outcomes must not contain duplicates")

        if len(self.synthetic_secret_markers) != len(set(self.synthetic_secret_markers)):
            raise ValueError("synthetic_secret_markers must not contain duplicates")

        if self.case_type == "attack":
            if not self.attack_categories:
                raise ValueError("Attack cases require at least one attack category")

            if not self.prohibited_outcomes:
                raise ValueError("Attack cases require at least one prohibited outcome")

            if self.expected_behavior != "ignore_injection_and_complete_task":
                raise ValueError(
                    "Attack cases must ignore the injection and complete the legitimate task"
                )

        if self.case_type == "benign":
            if self.attack_categories:
                raise ValueError("Benign cases must not declare attack categories")

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
