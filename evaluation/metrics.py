"""Security evaluation metrics and decision mapping for PromptFence.

This module provides deterministic calculation of standard binary classification
security metrics (Precision, Recall, F1, Accuracy, FPR, FNR, Latency, Coverage)
and implements conservative mapping from 3-way policy decisions (allow, review, block)
to binary threat predictions.
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PredictionRecord:
    """Individual benchmark prediction record for a single test case under a specific mode."""

    case_id: str
    ground_truth: str  # 'benign' or 'malicious'
    attack_category: str  # 'none', 'instruction_override', etc.
    difficulty: str  # 'basic', 'intermediate', 'adversarial'
    mode: str  # 'rules', 'llm', 'hybrid'
    predicted: str  # 'benign', 'malicious', or 'error'
    decision: str  # 'allow', 'review', 'block', or 'error'
    risk_score: int
    detector_status: str  # 'ok', 'degraded', 'error'
    findings_count: int
    finding_categories: List[str] = field(default_factory=list)
    finding_detectors: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    error_message: Optional[str] = None


@dataclass
class MetricResult:
    """Calculated security evaluation metrics for a specific detector mode."""

    mode: str
    total_cases: int
    evaluated_cases: int
    error_cases: int
    coverage: float
    tp: int
    tn: int
    fp: int
    fn: int
    accuracy: Optional[float]
    precision: Optional[float]
    recall: Optional[float]
    f1_score: Optional[float]
    false_positive_rate: Optional[float]
    false_negative_rate: Optional[float]
    mean_latency_ms: float
    median_latency_ms: float
    category_metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    difficulty_metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to a JSON-serializable dictionary."""
        return asdict(self)


def map_decision_to_prediction(decision: str) -> str:
    """Map a PromptFence 3-way policy decision to a binary security classification.

    Binary Classification Mapping:
    - 'allow' -> 'benign'
      The policy engine evaluated the text and determined it contains no actionable
      security threats. The text is permitted to proceed.

    - 'review' -> 'malicious'
      The policy engine flagged detected indicator findings (e.g. instruction overrides,
      medium/low indicators) and withheld automatic clearance, halting autonomous execution
      to demand human review. In a binary security gateway, flagging risk is a positive
      threat detection.

    - 'block' -> 'malicious'
      The policy engine confirmed high-severity injection indicators in critical threat
      categories and blocked execution immediately.

    - Any other status (e.g. 'error', 'unavailable') -> 'error'
      Inference failure, connection timeout, or unavailable service is treated strictly as an
      error. Detector failures are NEVER mapped to 'benign'.

    Args:
        decision: The decision string ('allow', 'review', 'block', 'error').

    Returns:
        'benign', 'malicious', or 'error'.
    """
    dec_lower = str(decision).strip().lower()
    if dec_lower == "allow":
        return "benign"
    elif dec_lower in ("review", "block"):
        return "malicious"
    else:
        return "error"


def calculate_metrics(
    records: List[PredictionRecord],
    mode_name: Optional[str] = None,
) -> MetricResult:
    """Calculate security evaluation metrics from a collection of prediction records.

    Zero Denominator Handling:
    - Precision is None if (TP + FP) == 0 (no positive predictions were made).
    - Recall is None if (TP + FN) == 0 (no actual positive cases in sample).
    - F1 Score is None if Precision or Recall is None, or if (Precision + Recall) == 0.
    - Accuracy is None if no valid cases were evaluated.
    - FPR is None if (FP + TN) == 0 (no actual benign cases).
    - FNR is None if (FN + TP) == 0 (no actual malicious cases).

    Args:
        records: List of PredictionRecord objects.
        mode_name: Optional detector mode filter ('rules', 'llm', 'hybrid').

    Returns:
        MetricResult populated with counts, rates, and latency statistics.
    """
    filtered = [r for r in records if mode_name is None or r.mode == mode_name]
    total_cases = len(filtered)
    target_mode = mode_name or (filtered[0].mode if filtered else "unknown")

    if total_cases == 0:
        return MetricResult(
            mode=target_mode,
            total_cases=0,
            evaluated_cases=0,
            error_cases=0,
            coverage=0.0,
            tp=0,
            tn=0,
            fp=0,
            fn=0,
            accuracy=None,
            precision=None,
            recall=None,
            f1_score=None,
            false_positive_rate=None,
            false_negative_rate=None,
            mean_latency_ms=0.0,
            median_latency_ms=0.0,
        )

    # Separate valid evaluations from errors
    valid_records = [r for r in filtered if r.predicted in ("benign", "malicious")]
    error_records = [r for r in filtered if r.predicted == "error"]

    evaluated_cases = len(valid_records)
    error_cases = len(error_records)
    coverage = round(evaluated_cases / total_cases, 4)

    # Compute confusion matrix over evaluated cases
    tp = sum(1 for r in valid_records if r.ground_truth == "malicious" and r.predicted == "malicious")
    tn = sum(1 for r in valid_records if r.ground_truth == "benign" and r.predicted == "benign")
    fp = sum(1 for r in valid_records if r.ground_truth == "benign" and r.predicted == "malicious")
    fn = sum(1 for r in valid_records if r.ground_truth == "malicious" and r.predicted == "benign")

    # Safe metric calculations
    total_valid = tp + tn + fp + fn
    accuracy = round((tp + tn) / total_valid, 4) if total_valid > 0 else None

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else None

    if precision is not None and recall is not None and (precision + recall) > 0:
        f1_score = round(2 * (precision * recall) / (precision + recall), 4)
    else:
        f1_score = None

    actual_benign = fp + tn
    fpr = round(fp / actual_benign, 4) if actual_benign > 0 else None

    actual_malicious = fn + tp
    fnr = round(fn / actual_malicious, 4) if actual_malicious > 0 else None

    # Latency statistics
    latencies = [r.latency_ms for r in valid_records if r.latency_ms >= 0]
    mean_lat = round(statistics.mean(latencies), 3) if latencies else 0.0
    med_lat = round(statistics.median(latencies), 3) if latencies else 0.0

    # Category breakdowns
    categories = sorted({r.attack_category for r in valid_records})
    cat_metrics: Dict[str, Dict[str, Any]] = {}
    for cat in categories:
        cat_items = [r for r in valid_records if r.attack_category == cat]
        cat_total = len(cat_items)
        if cat == "none":
            # For benign, compute correct rejection rate (specificity)
            correct = sum(1 for r in cat_items if r.predicted == "benign")
            cat_metrics[cat] = {
                "total": cat_total,
                "correct_benign": correct,
                "accuracy": round(correct / cat_total, 4) if cat_total > 0 else None,
            }
        else:
            detected = sum(1 for r in cat_items if r.predicted == "malicious")
            cat_metrics[cat] = {
                "total": cat_total,
                "detected": detected,
                "recall": round(detected / cat_total, 4) if cat_total > 0 else None,
            }

    # Difficulty breakdowns
    difficulties = ["basic", "intermediate", "adversarial"]
    diff_metrics: Dict[str, Dict[str, Any]] = {}
    for diff in difficulties:
        diff_items = [r for r in valid_records if r.difficulty == diff]
        diff_total = len(diff_items)
        if diff_total > 0:
            diff_correct = sum(1 for r in diff_items if r.predicted == r.ground_truth)
            diff_metrics[diff] = {
                "total": diff_total,
                "correct": diff_correct,
                "accuracy": round(diff_correct / diff_total, 4),
            }

    return MetricResult(
        mode=target_mode,
        total_cases=total_cases,
        evaluated_cases=evaluated_cases,
        error_cases=error_cases,
        coverage=coverage,
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        mean_latency_ms=mean_lat,
        median_latency_ms=med_lat,
        category_metrics=cat_metrics,
        difficulty_metrics=diff_metrics,
    )


def format_markdown_table(metrics_list: List[MetricResult]) -> str:
    """Format a list of MetricResult objects as a GitHub-flavored markdown comparison table."""
    headers = [
        "Mode",
        "Coverage",
        "Accuracy",
        "Precision",
        "Recall",
        "F1 Score",
        "FPR",
        "FNR",
        "Mean Latency",
        "Median Latency",
        "Errors",
    ]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]

    for m in metrics_list:
        acc_str = f"{m.accuracy:.2%}" if m.accuracy is not None else "N/A"
        prec_str = f"{m.precision:.2%}" if m.precision is not None else "N/A"
        rec_str = f"{m.recall:.2%}" if m.recall is not None else "N/A"
        f1_str = f"{m.f1_score:.2%}" if m.f1_score is not None else "N/A"
        fpr_str = f"{m.false_positive_rate:.2%}" if m.false_positive_rate is not None else "N/A"
        fnr_str = f"{m.false_negative_rate:.2%}" if m.false_negative_rate is not None else "N/A"
        cov_str = f"{m.coverage:.1%}"
        mean_lat_str = f"{m.mean_latency_ms:.2f} ms"
        med_lat_str = f"{m.median_latency_ms:.2f} ms"

        row = [
            f"**{m.mode}**",
            cov_str,
            acc_str,
            prec_str,
            rec_str,
            f1_str,
            fpr_str,
            fnr_str,
            mean_lat_str,
            med_lat_str,
            str(m.error_cases),
        ]
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines)
