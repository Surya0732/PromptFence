"""Benchmark evaluation runner for PromptFence.

Executes test examples across rules-only, LLM-only, and hybrid modes,
reusing the production detectors and policy engine.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from app.config import OLLAMA_MODEL
from app.detectors.llm_detector import detect_with_llm
from app.detectors.merger import merge_findings
from app.detectors.rules import detect_with_rules
from app.evaluation.dataset import BenchmarkExample
from app.evaluation.metrics import BenchmarkMetrics, compute_metrics
from app.policy.engine import evaluate_policy
from app.schemas import DetectorStatus

logger = logging.getLogger("promptfence.benchmark")


@dataclass
class BenchmarkRunResult:
    """Complete summary of a benchmark evaluation run."""

    mode: str
    model_name: str
    dataset_path: str
    dataset_version: str
    timestamp: str
    evaluations: list[dict[str, Any]]
    metrics: BenchmarkMetrics
    failed_count: int
    timeout_count: int
    skipped_count: int

    def to_dict(self) -> dict[str, Any]:
        """Convert entire benchmark run to serialisable dictionary."""
        return {
            "metadata": {
                "mode": self.mode,
                "model_name": self.model_name,
                "dataset_path": self.dataset_path,
                "dataset_version": self.dataset_version,
                "timestamp": self.timestamp,
                "total_samples": self.metrics.total_samples,
                "successful_samples": self.metrics.successful_inferences,
                "failed_samples": self.failed_count,
                "timeout_samples": self.timeout_count,
                "skipped_samples": self.skipped_count,
            },
            "metrics": self.metrics.to_dict(),
            "sample_evaluations": self.evaluations,
        }


def run_evaluation(
    dataset: Sequence[BenchmarkExample],
    mode: str = "rules_only",
    *,
    dataset_path: str = "data/benchmark_v1.jsonl",
    dataset_version: str = "v1.0",
    model_name: str | None = None,
    max_samples: int | None = None,
) -> BenchmarkRunResult:
    """Run benchmark evaluation over the given dataset.

    Parameters
    ----------
    dataset:
        Sequence of loaded BenchmarkExample items.
    mode:
        Detection mode: ``"rules_only"``, ``"llm_only"``, or ``"hybrid"``.
    dataset_path:
        Path or identifier of the dataset.
    dataset_version:
        Version tag of the dataset.
    model_name:
        Model name to request (defaults to config OLLAMA_MODEL).
    max_samples:
        Optional limit on number of samples to process.

    Returns
    -------
    BenchmarkRunResult:
        Results containing per-sample outcomes and aggregate metrics.
    """
    if mode not in ("rules_only", "llm_only", "hybrid"):
        raise ValueError(
            f"Unsupported benchmark mode: '{mode}'. Must be rules_only, llm_only, or hybrid."
        )

    resolved_model = model_name or (OLLAMA_MODEL if mode != "rules_only" else "none (rules only)")
    timestamp = datetime.now(timezone.utc).isoformat()

    samples = dataset[:max_samples] if max_samples is not None else dataset

    evaluations: list[dict[str, Any]] = []
    latencies: list[float] = []

    failed_count = 0
    timeout_count = 0
    skipped_count = 0

    for example in samples:
        t0 = time.perf_counter()

        detector_statuses: list[DetectorStatus] = []
        raw_findings: list[dict[str, Any]] = []
        sample_failed = False
        sample_timeout = False

        if mode == "rules_only":
            raw_findings = detect_with_rules(example.text)
            detector_statuses.append(
                DetectorStatus(name="rules", status="ok", available=True)
            )

        elif mode == "llm_only":
            llm_res = detect_with_llm(example.text, model=model_name)
            stat = DetectorStatus(
                name="llm",
                status=llm_res.status,
                available=llm_res.is_ok,
                error=llm_res.error,
            )
            detector_statuses.append(stat)
            raw_findings = llm_res.findings

            if not llm_res.is_ok:
                sample_failed = True
                if llm_res.error and "time" in llm_res.error.lower():
                    sample_timeout = True

        elif mode == "hybrid":
            rule_findings = detect_with_rules(example.text)
            rule_stat = DetectorStatus(name="rules", status="ok", available=True)

            llm_res = detect_with_llm(example.text, model=model_name)
            llm_stat = DetectorStatus(
                name="llm",
                status=llm_res.status,
                available=llm_res.is_ok,
                error=llm_res.error,
            )
            detector_statuses.extend([rule_stat, llm_stat])

            if llm_res.is_ok:
                raw_findings = merge_findings(rule_findings, llm_res.findings)
            else:
                raw_findings = rule_findings
                sample_failed = True
                if llm_res.error and "time" in llm_res.error.lower():
                    sample_timeout = True

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        latencies.append(elapsed_ms)

        if sample_timeout:
            timeout_count += 1
        elif sample_failed:
            failed_count += 1

        # Evaluate policy
        policy_res = evaluate_policy(
            raw_findings,
            detector_statuses=detector_statuses,
            mode=mode,
        )

        decision = policy_res["decision"]
        risk_score = policy_res["risk_score"]

        # Classification decision: 'review' or 'block' indicates attack detected
        predicted_attack = decision in ("review", "block")

        is_correct = (predicted_attack == example.is_attack)

        detected_cats = sorted(
            list({f.get("category") for f in raw_findings if f.get("category")})
        )

        status_summary = {
            ds.name: ds.status for ds in detector_statuses
        }

        # Privacy guard: record only sample ID, labels, metrics, rationale (never full text)
        evaluations.append(
            {
                "id": example.id,
                "is_attack": example.is_attack,
                "expected_label": example.expected_label,
                "expected_categories": example.categories,
                "predicted_attack": predicted_attack,
                "predicted_decision": decision,
                "risk_score": risk_score,
                "detected_categories": detected_cats,
                "is_correct": is_correct,
                "detector_status": status_summary,
                "latency_ms": elapsed_ms,
                "rationale": example.rationale,
            }
        )

    metrics = compute_metrics(
        evaluations=evaluations,
        latencies=latencies,
        failed_count=failed_count,
        timeout_count=timeout_count,
        skipped_count=skipped_count,
    )

    return BenchmarkRunResult(
        mode=mode,
        model_name=resolved_model,
        dataset_path=dataset_path,
        dataset_version=dataset_version,
        timestamp=timestamp,
        evaluations=evaluations,
        metrics=metrics,
        failed_count=failed_count,
        timeout_count=timeout_count,
        skipped_count=skipped_count,
    )
