"""Safe mock-agent execution sandbox and tool enforcement for PromptFence.

This module provides a deterministic, secure simulation environment to demonstrate
unprotected vs. protected AI agent behavior.

Notice:
No real financial transfers, hiring decisions, refunds, external network calls,
filesystem modifications, or shell commands are ever executed. All tools are
sandboxed mock implementations with strict parameter validation and safety ceilings.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Tuple
from uuid import uuid4

from fastapi import HTTPException, status

from app.detectors.llm import LLMDetectorError, detect_with_llm
from app.detectors.rules import detect_with_rules
from app.policy.engine import evaluate_policy
from app.schemas import (
    Decision,
    DetectorMode,
    Finding,
    SimulateRequest,
    SimulateResponse,
    ToolAction,
    ToolStatus,
)
from app.telemetry import telemetry

# -----------------------------------------------------------------------------
# Mock Tool Implementations & Validation
# -----------------------------------------------------------------------------

def _validate_and_run_approve_invoice(args: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Mock tool: Approves vendor invoice up to safety ceiling ($5,000.00)."""
    invoice_id = str(args.get("invoice_id", "")).strip()
    recipient = str(args.get("recipient", "")).strip()
    raw_amount = args.get("amount")

    if not invoice_id:
        return False, "Missing or empty 'invoice_id'", {}
    if not recipient:
        return False, "Missing or empty 'recipient'", {}
    if raw_amount is None:
        return False, "Missing required 'amount'", {}

    try:
        amount = float(raw_amount)
    except (ValueError, TypeError):
        return False, "Parameter 'amount' must be a numeric value", {}

    if amount <= 0.0:
        return False, "Parameter 'amount' must be greater than zero", {}
    if amount > 5000.0:
        return False, f"Amount ${amount:.2f} exceeds mock auto-approval ceiling ($5,000.00)", {}

    return True, "", {
        "status": "approved",
        "invoice_id": invoice_id,
        "amount": amount,
        "recipient": recipient,
        "mock_confirmation_token": f"MOCK-INV-AUTH-{invoice_id[:8]}",
    }


def _validate_and_run_hire_candidate(args: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Mock tool: Extends job offer if candidate meets minimum score (70/100)."""
    candidate_id = str(args.get("candidate_id", "")).strip()
    role = str(args.get("role", "")).strip()
    raw_score = args.get("qualification_score")

    if not candidate_id:
        return False, "Missing or empty 'candidate_id'", {}
    if not role:
        return False, "Missing or empty 'role'", {}
    if raw_score is None:
        return False, "Missing required 'qualification_score'", {}

    try:
        score = int(raw_score)
    except (ValueError, TypeError):
        return False, "Parameter 'qualification_score' must be an integer", {}

    if score < 0 or score > 100:
        return False, "Score must be an integer between 0 and 100", {}
    if score < 70:
        return False, f"Qualification score ({score}) is below hiring threshold (70)", {}

    return True, "", {
        "status": "offer_extended",
        "candidate_id": candidate_id,
        "role": role,
        "qualification_score": score,
        "mock_offer_id": f"MOCK-OFFER-{candidate_id[:8]}",
    }


def _validate_and_run_issue_refund(args: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Mock tool: Issues customer support refund up to safety ceiling ($250.00)."""
    ticket_id = str(args.get("ticket_id", "")).strip()
    reason = str(args.get("reason", "")).strip()
    raw_amount = args.get("amount")

    if not ticket_id:
        return False, "Missing or empty 'ticket_id'", {}
    if not reason:
        return False, "Missing or empty 'reason'", {}
    if raw_amount is None:
        return False, "Missing required 'amount'", {}

    try:
        amount = float(raw_amount)
    except (ValueError, TypeError):
        return False, "Parameter 'amount' must be a numeric value", {}

    if amount <= 0.0:
        return False, "Parameter 'amount' must be greater than zero", {}
    if amount > 250.0:
        return False, f"Refund amount ${amount:.2f} exceeds auto-refund ceiling ($250.00)", {}

    return True, "", {
        "status": "refund_issued",
        "ticket_id": ticket_id,
        "amount": amount,
        "reason": reason,
        "mock_refund_tx": f"MOCK-TX-{ticket_id[:8]}",
    }


# Authorized tool registry mapping tool name to validation/execution function
MOCK_TOOL_REGISTRY: Dict[str, Callable[[Dict[str, Any]], Tuple[bool, str, Dict[str, Any]]]] = {
    "approve_invoice": _validate_and_run_approve_invoice,
    "hire_candidate": _validate_and_run_hire_candidate,
    "issue_refund": _validate_and_run_issue_refund,
}


def run_simulation(request: SimulateRequest) -> SimulateResponse:
    """Execute the simulation pipeline: inspect input, enforce policy, and guard tool execution.

    Pipeline steps:
    1. Scan untrusted content using requested detector mode (rules, llm, or hybrid).
    2. Evaluate findings against policy engine profile.
    3. Verify tool against explicit authorized allowlist.
    4. Validate tool arguments and domain safety constraints.
    5. Enforce policy decision in backend code before execution.
    6. Record outcome and measured latency in telemetry.
    """
    t0 = time.perf_counter()
    scan_id = uuid4()
    detector_mode = request.detector_mode
    detector_status_str = "ok"
    degraded_note = ""

    findings: list[Finding] = []

    # 1. Detection
    if detector_mode == DetectorMode.RULES:
        raw_findings = detect_with_rules(request.text)
        findings = [Finding(**f) for f in raw_findings]
    elif detector_mode == DetectorMode.LLM:
        try:
            findings = detect_with_llm(request.text)
        except LLMDetectorError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"LLM detector unavailable: {exc}",
            ) from exc
    elif detector_mode == DetectorMode.HYBRID:
        raw_findings = detect_with_rules(request.text)
        findings = [Finding(**f) for f in raw_findings]
        try:
            llm_findings = detect_with_llm(request.text)
            findings.extend(llm_findings)
        except LLMDetectorError as exc:
            detector_status_str = "degraded"
            degraded_note = (
                f"LLM detector unavailable ({type(exc).__name__}); "
                "evaluation completed using rule engine findings only."
            )

    # 2. Policy evaluation
    policy_outcome = evaluate_policy(findings, mode=request.policy_mode)
    decision_val = policy_outcome["decision"]
    risk_score = policy_outcome["risk_score"]
    explanation = policy_outcome["explanation"]
    if detector_status_str == "degraded" and degraded_note:
        explanation = f"[DEGRADED] {degraded_note} {explanation}"

    tool_name = request.proposed_tool.tool_name

    # 3. Tool allowlist check
    if tool_name not in MOCK_TOOL_REGISTRY:
        tool_status = ToolStatus.REJECTED_UNKNOWN_TOOL
        tool_executed = False
        execution_result = {
            "error": f"Tool '{tool_name}' is not in the authorized agent tool allowlist.",
            "authorized_tools": sorted(list(MOCK_TOOL_REGISTRY.keys())),
        }
    else:
        # 4. Argument validation
        tool_func = MOCK_TOOL_REGISTRY[tool_name]
        is_valid, validation_err, mock_data = tool_func(request.proposed_tool.arguments)

        if not is_valid:
            tool_status = ToolStatus.REJECTED_INVALID_ARGUMENTS
            tool_executed = False
            execution_result = {
                "error": f"Tool argument validation rejected: {validation_err}",
            }
        else:
            # 5. Policy enforcement
            if decision_val == Decision.BLOCK.value:
                tool_status = ToolStatus.BLOCKED_BY_POLICY
                tool_executed = False
                execution_result = {
                    "error": (
                        "Execution blocked: PromptFence security policy halted action "
                        "due to detected injection indicators in input content."
                    ),
                }
            elif decision_val == Decision.REVIEW.value:
                tool_status = ToolStatus.BLOCKED_PENDING_REVIEW
                tool_executed = False
                execution_result = {
                    "error": (
                        "Execution suspended: Security policy requires manual human review "
                        "before this tool action can proceed."
                    ),
                }
            else:
                # Decision == ALLOW and arguments valid -> Safe to execute mock tool
                tool_status = ToolStatus.EXECUTED
                tool_executed = True
                execution_result = mock_data

    latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    # 6. Record real telemetry
    telemetry.record_scan(
        decision=decision_val,
        findings_count=len(findings),
        latency_ms=latency_ms,
    )

    return SimulateResponse(
        scan_id=scan_id,
        decision=Decision(decision_val),
        risk_score=risk_score,
        findings=findings,
        explanation=explanation,
        tool_proposed=request.proposed_tool,
        tool_executed=tool_executed,
        tool_status=tool_status,
        execution_result=execution_result,
        latency_ms=latency_ms,
        detector_mode=detector_mode,
        detector_status=detector_status_str,
    )
