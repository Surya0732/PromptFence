"""PromptFence — FastAPI application.

This module exposes the REST API for scanning untrusted text inputs.
Detection and policy logic live in separate modules; this file handles
HTTP routing, request validation, detector dispatch, and response formatting.

Endpoints
---------
- ``GET  /health`` — health check and version info.
- ``POST /scan``   — scan text for prompt-injection indicators.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException

from app.config import OLLAMA_BASE_URL, OLLAMA_MODEL
from app.detectors.llm_detector import detect_with_llm
from app.detectors.merger import merge_findings
from app.detectors.rules import detect_with_rules
from app.policy.engine import evaluate_policy
from app.schemas import DetectorStatus, Finding, ScanRequest, ScanResponse

# ---------------------------------------------------------------------------
# Logging — never log full user input or secrets
# ---------------------------------------------------------------------------

logger = logging.getLogger("promptfence")

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

VERSION = "0.2.0"

app = FastAPI(
    title="PromptFence",
    description=(
        "A reusable security harness for AI agents that detects possible "
        "prompt injection and applies security policies before an agent can act."
    ),
    version=VERSION,
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict:
    """Return a health check with version, status, model, and component readiness."""
    ollama_status = "unavailable"
    try:
        with httpx.Client(timeout=0.6) as client:
            resp = client.get(f"{OLLAMA_BASE_URL}/api/tags")
            if resp.status_code == 200:
                ollama_status = "available"
    except Exception:
        ollama_status = "unavailable"

    return {
        "status": "healthy",
        "version": VERSION,
        "phase": 2,
        "model": OLLAMA_MODEL,
        "components": {
            "rule_engine": "operational",
            "ollama": ollama_status,
        },
    }


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    """Scan untrusted text for prompt-injection indicators.

    Workflow:
    1. Validate request body and requested mode (rules_only, llm_only, or hybrid).
    2. Dispatch to appropriate detector(s).
    3. Merge findings and track detector health statuses.
    4. Apply independent policy engine to compute risk score and decision.
    5. Return structured ScanResponse disclosing findings and detector statuses.

    Security guarantees:
    - Never logs complete user input or potential secrets.
    - Rules-only mode never makes network calls or touches Ollama.
    - Detector failures are never treated as proof of safety.
    """
    start_time = time.perf_counter()
    scan_id = str(uuid.uuid4())

    logger.info(
        "Scan requested: scan_id=%s mode=%s text_length=%d",
        scan_id,
        request.mode,
        len(request.text),
    )

    detector_statuses: list[DetectorStatus] = []
    raw_findings: list[dict[str, Any]] = []

    # --- Mode Dispatch ---
    if request.mode == "rules_only":
        raw_findings = detect_with_rules(request.text)
        detector_statuses.append(
            DetectorStatus(name="rules", status="ok", available=True)
        )

    elif request.mode == "llm_only":
        llm_result = detect_with_llm(request.text)
        detector_statuses.append(
            DetectorStatus(
                name="llm",
                status=llm_result.status,
                available=llm_result.is_ok,
                error=llm_result.error,
            )
        )
        raw_findings = llm_result.findings

    elif request.mode == "hybrid":
        rule_findings = detect_with_rules(request.text)
        rule_status = DetectorStatus(name="rules", status="ok", available=True)

        llm_result = detect_with_llm(request.text)
        llm_status = DetectorStatus(
            name="llm",
            status=llm_result.status,
            available=llm_result.is_ok,
            error=llm_result.error,
        )

        detector_statuses.extend([rule_status, llm_status])

        if llm_result.is_ok:
            raw_findings = merge_findings(rule_findings, llm_result.findings)
        else:
            # Gemma/Ollama failed; preserve rule-based findings!
            raw_findings = rule_findings
            logger.warning(
                "Hybrid mode degraded: LLM detector status=%s, preserving rule findings count=%d",
                llm_result.status,
                len(rule_findings),
            )

    else:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported mode: '{request.mode}'. Supported modes: rules_only, llm_only, hybrid.",
        )

    # --- Policy Evaluation ---
    policy_result = evaluate_policy(
        raw_findings,
        detector_statuses=detector_statuses,
        mode=request.mode,
    )

    # Convert finding dicts to validated Pydantic models
    validated_findings = [Finding(**f) for f in raw_findings]

    elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

    response = ScanResponse(
        scan_id=scan_id,
        risk_score=policy_result["risk_score"],
        decision=policy_result["decision"],
        findings=validated_findings,
        reasons=policy_result["reasons"],
        mode=request.mode,
        processing_time_ms=elapsed_ms,
        detector_status=detector_statuses,
    )

    logger.info(
        "Scan complete: scan_id=%s risk_score=%d decision=%s findings=%d elapsed_ms=%.2f",
        scan_id,
        response.risk_score,
        response.decision,
        len(response.findings),
        elapsed_ms,
    )

    return response
