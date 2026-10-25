"""Structured schemas and models for PromptFence."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class Decision(str, Enum):
    """Permitted policy engine and scan decisions."""

    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class PolicyMode(str, Enum):
    """Supported policy evaluation sensitivity tiers."""

    PERMISSIVE = "permissive"
    BALANCED = "balanced"
    STRICT = "strict"


class DetectorMode(str, Enum):
    """Supported detector pipeline modes."""

    RULES = "rules"
    LLM = "llm"
    HYBRID = "hybrid"


class FindingCategory(str, Enum):
    """Predefined categories of prompt injection / security findings."""

    INSTRUCTION_OVERRIDE = "instruction_override"
    SECRET_EXTRACTION = "secret_extraction"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"


class FindingSeverity(str, Enum):
    """Predefined finding severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ToolStatus(str, Enum):
    """Execution status for agent mock-tool actions."""

    EXECUTED = "executed"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    BLOCKED_PENDING_REVIEW = "blocked_pending_review"
    REJECTED_UNKNOWN_TOOL = "rejected_unknown_tool"
    REJECTED_INVALID_ARGUMENTS = "rejected_invalid_arguments"


class ScanRequest(BaseModel):
    """Incoming scan request payload."""

    text: str = Field(
        ...,
        min_length=1,
        max_length=50000,
        description="The prompt or text to inspect for injection indicators.",
    )
    source_type: Optional[str] = Field(
        default="text",
        max_length=100,
        description="Origin context of the text (e.g. 'text', 'user_input', 'retrieved_context').",
    )
    policy_mode: PolicyMode = Field(
        default=PolicyMode.BALANCED,
        description="Policy enforcement profile: 'permissive', 'balanced', or 'strict'.",
    )
    detector_mode: DetectorMode = Field(
        default=DetectorMode.RULES,
        description="Detector execution mode: 'rules', 'llm', or 'hybrid'.",
    )

    @field_validator("text")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        """Ensure text is not empty or composed solely of whitespace."""
        if not value or not value.strip():
            raise ValueError("text must contain non-whitespace characters")
        return value


class Finding(BaseModel):
    """Structured detection finding emitted by a detector."""

    detector: str = Field(
        default="rule_engine",
        description="Identifier of the detector that discovered the indicator.",
    )
    category: FindingCategory = Field(
        ...,
        description="Predefined category of the detected indicator.",
    )
    severity: FindingSeverity = Field(
        ...,
        description="Predefined severity level of the finding.",
    )
    evidence: str = Field(
        ...,
        description="Contextual snippet from the input text containing the match.",
    )
    matched_indicator: str = Field(
        ...,
        description="The specific signature or phrase rule that triggered.",
    )


class ScanResponse(BaseModel):
    """Validated response payload for a completed scan."""

    scan_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the scan event.",
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Deterministic heuristic risk score between 0 and 100.",
    )
    decision: Decision = Field(
        ...,
        description="Action decision determined by the policy engine: allow, review, or block.",
    )
    findings: List[Finding] = Field(
        default_factory=list,
        description="List of detected indicator findings.",
    )
    explanation: str = Field(
        ...,
        description="Human-readable explanation of the decision and risk rationale.",
    )
    latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Server-side processing latency in milliseconds (pipeline execution).",
    )
    detector_mode: DetectorMode = Field(
        default=DetectorMode.RULES,
        description="Detector execution mode applied for this scan.",
    )
    detector_status: str = Field(
        default="ok",
        description="Operational status of the detector pipeline ('ok', 'degraded', 'error').",
    )


class HealthResponse(BaseModel):
    """Service health response."""

    status: str = Field(default="ok", description="Operational status.")
    service: str = Field(default="PromptFence", description="Service identifier.")
    version: str = Field(default="0.1.0", description="Application version.")


class TelemetryResponse(BaseModel):
    """Real in-process telemetry statistics recorded by the active server instance."""

    total_scans: int = Field(..., ge=0, description="Total number of scan operations executed.")
    allowed_count: int = Field(..., ge=0, description="Number of scans resulting in 'allow'.")
    reviewed_count: int = Field(..., ge=0, description="Number of scans resulting in 'review'.")
    blocked_count: int = Field(..., ge=0, description="Number of scans resulting in 'block'.")
    total_findings: int = Field(..., ge=0, description="Total security findings identified.")
    avg_latency_ms: float = Field(..., ge=0.0, description="Mean pipeline latency in milliseconds.")
    last_latency_ms: float = Field(..., ge=0.0, description="Most recent pipeline latency in milliseconds.")


class ToolAction(BaseModel):
    """Proposed tool action descriptor for agent simulation."""

    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Name of the mock tool proposed for execution (e.g. 'approve_invoice').",
    )
    arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Keyword arguments supplied for the mock tool invocation.",
    )


class SimulateRequest(BaseModel):
    """Payload for simulating agent action with untrusted content inspection."""

    text: str = Field(
        ...,
        min_length=1,
        max_length=50000,
        description="Untrusted prompt or document text to inspect before tool invocation.",
    )
    proposed_tool: ToolAction = Field(
        ...,
        description="The action the agent proposes to take based on the untrusted input.",
    )
    policy_mode: PolicyMode = Field(
        default=PolicyMode.BALANCED,
        description="Enforcement policy tier: 'permissive', 'balanced', or 'strict'.",
    )
    detector_mode: DetectorMode = Field(
        default=DetectorMode.RULES,
        description="Detector execution mode: 'rules', 'llm', or 'hybrid'.",
    )
    source_type: Optional[str] = Field(
        default="agent_input",
        max_length=100,
        description="Contextual source of the input text.",
    )

    @field_validator("text")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        """Ensure input text is non-empty."""
        if not value or not value.strip():
            raise ValueError("text must contain non-whitespace characters")
        return value


class SimulateResponse(BaseModel):
    """Result of agent simulation including policy outcome and execution record."""

    scan_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the inspection scan.",
    )
    decision: Decision = Field(
        ...,
        description="Policy enforcement decision: 'allow', 'review', or 'block'.",
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Deterministic heuristic risk score.",
    )
    findings: List[Finding] = Field(
        default_factory=list,
        description="Security findings detected in the untrusted text.",
    )
    explanation: str = Field(
        ...,
        description="Explanation of policy decision.",
    )
    tool_proposed: ToolAction = Field(
        ...,
        description="The tool action originally requested by the agent.",
    )
    tool_executed: bool = Field(
        ...,
        description="Whether the mock tool was actually executed in backend code.",
    )
    tool_status: ToolStatus = Field(
        ...,
        description="Status code describing tool outcome.",
    )
    execution_result: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Output emitted by the mock tool if execution succeeded, or error details.",
    )
    latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Total processing latency in milliseconds.",
    )
    detector_mode: DetectorMode = Field(
        default=DetectorMode.RULES,
        description="Detector execution mode applied for this simulation.",
    )
    detector_status: str = Field(
        default="ok",
        description="Operational status of the detector pipeline ('ok', 'degraded', 'error').",
    )
