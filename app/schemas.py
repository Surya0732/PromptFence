"""Pydantic schemas for PromptFence API requests and responses.

These schemas define the data contracts for the /scan endpoint,
including input validation, finding structure, and response format.
"""

from __future__ import annotations

import uuid
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Maximum number of characters accepted in a single scan request.
#: This limit exists to prevent denial-of-service via extremely large payloads.
#: Adjust as needed; 20 000 chars covers most realistic prompt inputs.
MAX_INPUT_LENGTH: int = 20_000

#: Valid detection categories produced by detectors.
VALID_CATEGORIES = frozenset(
    {
        "instruction_override",
        "secret_extraction",
        "data_exfiltration",
        "unauthorized_tool_use",
    }
)

#: Valid severity levels.
VALID_SEVERITIES = frozenset({"low", "medium", "high"})

#: Valid policy decisions.
VALID_DECISIONS = frozenset({"allow", "review", "block"})

#: Supported detection modes.
SUPPORTED_MODES = frozenset({"rules_only", "llm_only", "hybrid"})


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Incoming scan request body.

    Attributes:
        text: The untrusted input text to analyse.
        mode: Detection mode — ``"rules_only"``, ``"llm_only"``, or ``"hybrid"``.
    """

    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_INPUT_LENGTH,
        description=(
            "The text to scan for potential prompt-injection indicators. "
            f"Must be between 1 and {MAX_INPUT_LENGTH:,} characters."
        ),
    )
    mode: Literal["rules_only", "llm_only", "hybrid"] = Field(
        default="rules_only",
        description=(
            "Detection mode. 'rules_only' uses deterministic patterns, "
            "'llm_only' uses a local Gemma 4 model via Ollama, and "
            "'hybrid' combines both detectors."
        ),
    )


# ---------------------------------------------------------------------------
# Finding schema
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A single detection finding produced by a detector.

    Attributes:
        detector: Name of the detector that produced this finding (e.g. ``"rules"`` or ``"llm"``).
        category: Detection category.
        severity: Severity level of the finding.
        evidence: A short, relevant excerpt from the input that triggered the finding.
        matched_indicator: Human-readable explanation of the pattern that matched.
        confidence: Optional confidence score from the LLM (0.0–1.0).  Not present for rule findings.
    """

    detector: str = Field(
        ..., description="Name of the detector that produced this finding."
    )
    category: str = Field(..., description="Detection category.")
    severity: str = Field(..., description="Severity level: low, medium, or high.")
    evidence: str = Field(
        ...,
        description="Short excerpt from the input that triggered the finding.",
    )
    matched_indicator: str = Field(
        ...,
        description="Brief explanation of the matched pattern.",
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="LLM confidence score (0.0–1.0). Only present for LLM findings.",
    )
    evidence_verified: Optional[bool] = Field(
        default=None,
        description="Whether model-provided evidence was verified against the submitted input.",
    )

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        if v not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{v}'. Must be one of: {sorted(VALID_CATEGORIES)}"
            )
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        if v not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{v}'. Must be one of: {sorted(VALID_SEVERITIES)}"
            )
        return v


# ---------------------------------------------------------------------------
# Detector status
# ---------------------------------------------------------------------------


class DetectorStatus(BaseModel):
    """Status of an individual detector used during a scan."""

    name: str = Field(..., description="Detector name (e.g. 'rules', 'llm').")
    status: str = Field(
        default="ok",
        description="Detector execution status: 'ok', 'unavailable', or 'invalid_response'.",
    )
    available: bool = Field(
        default=True,
        description="Whether the detector was available and completed successfully.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Sanitized error message if the detector was unavailable or failed.",
    )


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------


class ScanResponse(BaseModel):
    """Response returned by the ``/scan`` endpoint.

    Attributes:
        scan_id: Unique identifier for this scan operation.
        risk_score: Aggregate risk score from 0 (safe) to 100 (critical).
        decision: Policy decision — ``"allow"``, ``"review"``, or ``"block"``.
        findings: List of detection findings.
        reasons: Human-readable explanations for the policy decision.
        mode: The detection mode that was used.
        processing_time_ms: Processing time in milliseconds.
        detector_status: Status of each detector used.
    """

    scan_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this scan.",
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Aggregate risk score from 0 (safe) to 100 (critical).",
    )
    decision: str = Field(
        ..., description="Policy decision: allow, review, or block."
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="Detection findings from all active detectors.",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable explanations for the policy decision.",
    )
    mode: str = Field(
        default="rules_only",
        description="Detection mode that was used.",
    )
    processing_time_ms: Optional[float] = Field(
        default=None,
        description="Total processing time in milliseconds.",
    )
    detector_status: list[DetectorStatus] = Field(
        default_factory=list,
        description="Status of each detector used during the scan.",
    )
