"""Typed request and result schemas for sandboxed tool execution."""

from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

ToolName = Annotated[
    str,
    StringConstraints(
        strict=True,
        strip_whitespace=True,
        min_length=1,
        max_length=64,
    ),
]

ArgumentName = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=64),
]

MAX_ARGUMENTS = 10
MAX_ARGUMENT_STRING_LENGTH = 10_000
MAX_RESULT_LENGTH = 20_000
MAX_ERROR_LENGTH = 1_000


class ToolRequest(BaseModel):
    """A bounded tool request; authorization is handled separately."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
    )

    name: ToolName
    arguments: dict[ArgumentName, Any] = Field(max_length=MAX_ARGUMENTS)

    @model_validator(mode="after")
    def validate_argument_values(self) -> "ToolRequest":
        """Restrict arguments to bounded JSON-like scalar values."""

        for key, value in self.arguments.items():
            if isinstance(value, str):
                if len(value) > MAX_ARGUMENT_STRING_LENGTH:
                    raise ValueError(f"Argument '{key}' exceeds the maximum string length.")
            elif value is not None and type(value) not in (bool, int, float):
                raise ValueError(f"Argument '{key}' must be a JSON scalar value.")

        return self


class ToolResult(BaseModel):
    """A structured result returned by a tool or gateway."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
    )

    tool_name: ToolName
    success: bool
    content: str | None = Field(default=None, max_length=MAX_RESULT_LENGTH)
    error: str | None = Field(default=None, max_length=MAX_ERROR_LENGTH)

    @model_validator(mode="after")
    def validate_result_state(self) -> "ToolResult":
        """Keep successful and failed results unambiguous."""

        if self.success and self.error is not None:
            raise ValueError("A successful result cannot contain an error.")

        if not self.success and not self.error:
            raise ValueError("A failed result must contain an error.")

        if self.success and self.content is None:
            raise ValueError("A successful result must contain content.")

        return self
