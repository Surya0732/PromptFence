"""Dataset loader and schema for PromptFence evaluation benchmarks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class DatasetParseError(Exception):
    """Raised when an entry in the benchmark dataset is malformed or invalid."""


class BenchmarkExample(BaseModel):
    """A single labelled test example for the PromptFence benchmark."""

    id: str = Field(..., min_length=1, description="Stable unique identifier.")
    text: str = Field(..., min_length=1, description="Input text to scan.")
    expected_label: Literal["benign", "attack"] = Field(
        ..., description="Expected binary security classification."
    )
    is_attack: bool = Field(
        ..., description="Whether the example represents an attack."
    )
    categories: list[str] = Field(
        default_factory=list, description="Target attack categories if applicable."
    )
    rationale: str = Field(
        default="", description="Short rationale for the expected label."
    )

    @field_validator("expected_label")
    @classmethod
    def validate_label_consistency(cls, v: str) -> str:
        if v not in ("benign", "attack"):
            raise ValueError(f"expected_label must be 'benign' or 'attack', got '{v}'")
        return v


def load_dataset(file_path: str | Path) -> list[BenchmarkExample]:
    """Load and validate a JSONL benchmark dataset.

    Parameters
    ----------
    file_path:
        Path to the JSONL file.

    Returns
    -------
    list[BenchmarkExample]:
        List of validated benchmark examples.

    Raises
    ------
    FileNotFoundError:
        If the dataset file does not exist.
    DatasetParseError:
        If JSON parsing or schema validation fails on any line.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    examples: list[BenchmarkExample] = []
    seen_ids: set[str] = set()

    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise DatasetParseError(
                    f"Line {line_num} in {path} is not valid JSON: {exc}"
                ) from exc

            if not isinstance(data, dict):
                raise DatasetParseError(
                    f"Line {line_num} in {path} is not a JSON object"
                )

            try:
                example = BenchmarkExample(**data)
            except Exception as exc:
                raise DatasetParseError(
                    f"Line {line_num} in {path} failed schema validation: {exc}"
                ) from exc

            if example.id in seen_ids:
                raise DatasetParseError(
                    f"Duplicate example ID '{example.id}' found at line {line_num}"
                )
            seen_ids.add(example.id)

            # Ensure is_attack matches expected_label
            expected_is_attack = example.expected_label == "attack"
            if example.is_attack != expected_is_attack:
                raise DatasetParseError(
                    f"Line {line_num} has inconsistent is_attack ({example.is_attack}) "
                    f"and expected_label ({example.expected_label})"
                )

            examples.append(example)

    if not examples:
        raise DatasetParseError(f"Dataset at {path} contains no valid examples")

    return examples
