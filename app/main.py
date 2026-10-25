"""FastAPI application entry point for PromptFence."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import time
from uuid import uuid4

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.detectors.llm import LLMDetectorError, detect_with_llm
from app.detectors.rules import detect_with_rules
from app.policy.engine import evaluate_policy
from app.schemas import (
    DetectorMode,
    Finding,
    HealthResponse,
    ScanRequest,
    ScanResponse,
    SimulateRequest,
    SimulateResponse,
    TelemetryResponse,
)
from app.simulation import run_simulation
from app.telemetry import telemetry

# Configure structured logging (avoids logging sensitive user prompt payloads)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("promptfence")

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="PromptFence",
    version="0.2.0",
    description="Open-source AI security harness for indirect prompt injection and agent guardrails.",
)

# Optional CORS middleware for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files directory if present
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get(
    "/",
    summary="Web User Interface",
    tags=["Frontend"],
)
def get_index():
    """Serve PromptFence single-page web user interface."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return JSONResponse(
        {
            "service": "PromptFence",
            "status": "ok",
            "message": "Web interface static assets not found. Visit /health or /docs.",
        },
        status_code=200,
    )


@app.get(
    "/api/benchmark",
    summary="Retrieve verified benchmark evaluation metrics",
    tags=["Evaluation"],
)
def get_benchmark_metrics():
    """Retrieve verified benchmark metrics from evaluation artifacts."""
    results_dir = BASE_DIR / "evaluation" / "results"
    if results_dir.exists():
        runs = sorted(
            [d for d in results_dir.iterdir() if d.is_dir() and d.name.startswith("run_")],
            reverse=True,
        )
        if runs:
            metrics_file = runs[0] / "metrics.json"
            if metrics_file.exists():
                try:
                    with open(metrics_file, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception as exc:
                    logger.warning("Failed to read benchmark metrics.json: %s", exc)
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to read benchmark metrics file.",
                    ) from exc
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="No benchmark evaluation artifacts found.",
    )



@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    tags=["System"],
)
def get_health() -> HealthResponse:
    """Return operational status and metadata for PromptFence."""
    return HealthResponse(
        status="ok",
        service="PromptFence",
        version="0.2.0",
    )


@app.get(
    "/telemetry",
    response_model=TelemetryResponse,
    summary="In-process operational telemetry",
    tags=["Telemetry"],
)
def get_telemetry() -> TelemetryResponse:
    """Retrieve actual in-process scan telemetry and decision distributions.

    Notice: Counters are maintained in-memory per worker process.
    Counters reset upon application restart and are not synchronized across distributed workers.
    """
    return telemetry.get_metrics()


@app.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan prompt text for injection and policy violations",
    tags=["Security Engine"],
)
def scan_text(request: ScanRequest) -> ScanResponse:
    """Scan incoming text using the requested detector mode and evaluate policy.

    Detector modes:
    - rules: Deterministic phrase rules only.
    - llm: Local Ollama LLM detector only. Raises HTTP 503 if inference fails.
    - hybrid: Runs rules and LLM; combines findings; gracefully degrades to rules if LLM fails.

    Notice: Input text is NEVER executed or interpreted as code/instructions.
    For privacy and security, prompt contents are never logged.
    """
    t0 = time.perf_counter()
    scan_id = uuid4()
    text_length = len(request.text)
    detector_mode = request.detector_mode
    detector_status_str = "ok"
    degraded_note = ""

    findings: list[Finding] = []

    if detector_mode == DetectorMode.RULES:
        findings_data = detect_with_rules(request.text)
        findings = [Finding(**f) for f in findings_data]

    elif detector_mode == DetectorMode.LLM:
        try:
            findings = detect_with_llm(request.text)
        except LLMDetectorError as exc:
            logger.warning("LLM detector failure in LLM mode: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"LLM detector unavailable: {exc}",
            ) from exc

    elif detector_mode == DetectorMode.HYBRID:
        # 1. Run deterministic rules detector
        findings_data = detect_with_rules(request.text)
        findings = [Finding(**f) for f in findings_data]

        # 2. Run local LLM detector
        try:
            llm_findings = detect_with_llm(request.text)
            findings.extend(llm_findings)
        except LLMDetectorError as exc:
            logger.warning("LLM detector failed in hybrid mode; preserving rule findings: %s", exc)
            detector_status_str = "degraded"
            degraded_note = (
                f"LLM detector unavailable ({type(exc).__name__}); "
                "evaluation completed using rule engine findings only."
            )

    # Evaluate policy across collected findings
    policy_outcome = evaluate_policy(findings, mode=request.policy_mode)

    explanation = policy_outcome["explanation"]
    if detector_status_str == "degraded" and degraded_note:
        explanation = f"[DEGRADED] {degraded_note} {explanation}"

    # Measure pipeline execution latency
    latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    # Record real telemetry metrics
    telemetry.record_scan(
        decision=policy_outcome["decision"],
        findings_count=len(findings),
        latency_ms=latency_ms,
    )

    logger.info(
        "Scan completed: id=%s pol=%s det=%s status=%s len=%d findings=%d dec=%s score=%d lat=%.2fms",
        scan_id,
        request.policy_mode.value,
        detector_mode.value,
        detector_status_str,
        text_length,
        len(findings),
        policy_outcome["decision"],
        policy_outcome["risk_score"],
        latency_ms,
    )

    return ScanResponse(
        scan_id=scan_id,
        risk_score=policy_outcome["risk_score"],
        decision=policy_outcome["decision"],
        findings=findings,
        explanation=explanation,
        latency_ms=latency_ms,
        detector_mode=detector_mode,
        detector_status=detector_status_str,
    )


@app.post(
    "/simulate",
    response_model=SimulateResponse,
    status_code=status.HTTP_200_OK,
    summary="Simulate agent action with untrusted content inspection and tool policy enforcement",
    tags=["Agent Simulation"],
)
def simulate_agent_action(request: SimulateRequest) -> SimulateResponse:
    """Safely evaluate an agent's proposed action on untrusted input content.

    Enforces security policy in backend code BEFORE any mock tool executes.
    If the security policy yields 'block' or 'review', the mock tool invocation
    is intercepted and prevented.
    """
    return run_simulation(request)
