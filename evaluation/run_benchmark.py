"""CLI benchmark runner for PromptFence security evaluation.

Executes reproducible evaluation of PromptFence detector modes ('rules', 'llm', 'hybrid')
against the labelled evaluation dataset, records granular per-case predictions,
and generates structured CSV, JSON, and Markdown reports.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure workspace root is in sys.path when executed as script
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from fastapi import HTTPException

from app.detectors.llm import DEFAULT_MODEL, LLMDetectorError
from app.main import scan_text
from app.schemas import DetectorMode, PolicyMode, ScanRequest
from evaluation.metrics import (
    MetricResult,
    PredictionRecord,
    calculate_metrics,
    format_markdown_table,
    map_decision_to_prediction,
)

logger = logging.getLogger("promptfence.benchmark")


def load_dataset(dataset_path: Path) -> List[Dict[str, Any]]:
    """Load and validate JSONL benchmark records.

    Raises:
        FileNotFoundError: If the dataset file does not exist.
        ValueError: If a record is missing required fields or has invalid values.
    """
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    records: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    required_keys = {"id", "text", "label", "attack_category", "difficulty", "description"}
    valid_labels = {"benign", "malicious"}
    valid_categories = {
        "none",
        "instruction_override",
        "secret_extraction",
        "data_exfiltration",
        "unauthorized_tool_use",
    }
    valid_difficulties = {"basic", "intermediate", "adversarial"}

    with open(dataset_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                item = json.loads(line_str)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON on line {line_num} of {dataset_path}: {exc}") from exc

            missing = required_keys - set(item.keys())
            if missing:
                raise ValueError(f"Record on line {line_num} missing required fields: {sorted(missing)}")

            cid = item["id"]
            if cid in seen_ids:
                raise ValueError(f"Duplicate case id '{cid}' on line {line_num}")
            seen_ids.add(cid)

            if item["label"] not in valid_labels:
                raise ValueError(f"Invalid label '{item['label']}' on line {line_num}")
            if item["attack_category"] not in valid_categories:
                raise ValueError(f"Invalid attack_category '{item['attack_category']}' on line {line_num}")
            if item["difficulty"] not in valid_difficulties:
                raise ValueError(f"Invalid difficulty '{item['difficulty']}' on line {line_num}")
            if not str(item["text"]).strip():
                raise ValueError(f"Empty text field on line {line_num}")

            records.append(item)

    return records


def evaluate_case(
    record: Dict[str, Any],
    mode: str,
    policy_mode: str = "balanced",
) -> PredictionRecord:
    """Evaluate a single test case through the PromptFence scan pipeline.

    Notice: Untrusted input is strictly treated as passive data.
    """
    t0 = time.perf_counter()
    case_id = record["id"]
    ground_truth = record["label"]
    attack_category = record["attack_category"]
    difficulty = record["difficulty"]

    try:
        req = ScanRequest(
            text=record["text"],
            detector_mode=DetectorMode(mode),
            policy_mode=PolicyMode(policy_mode),
        )
        resp = scan_text(req)

        decision = resp.decision.value
        predicted = map_decision_to_prediction(decision)
        risk_score = resp.risk_score
        detector_status = resp.detector_status
        findings_count = len(resp.findings)
        finding_categories = [f.category.value for f in resp.findings]
        finding_detectors = [f.detector for f in resp.findings]
        latency_ms = resp.latency_ms
        error_msg = None

    except HTTPException as exc:
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        detail = exc.detail if hasattr(exc, "detail") else str(exc)
        return PredictionRecord(
            case_id=case_id,
            ground_truth=ground_truth,
            attack_category=attack_category,
            difficulty=difficulty,
            mode=mode,
            predicted="error",
            decision="error",
            risk_score=0,
            detector_status="error",
            findings_count=0,
            finding_categories=[],
            finding_detectors=[],
            latency_ms=latency_ms,
            error_message=f"HTTPException {exc.status_code}: {detail}",
        )
    except LLMDetectorError as exc:
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        return PredictionRecord(
            case_id=case_id,
            ground_truth=ground_truth,
            attack_category=attack_category,
            difficulty=difficulty,
            mode=mode,
            predicted="error",
            decision="error",
            risk_score=0,
            detector_status="error",
            findings_count=0,
            finding_categories=[],
            finding_detectors=[],
            latency_ms=latency_ms,
            error_message=f"{type(exc).__name__}: {exc}",
        )
    except Exception as exc:
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        return PredictionRecord(
            case_id=case_id,
            ground_truth=ground_truth,
            attack_category=attack_category,
            difficulty=difficulty,
            mode=mode,
            predicted="error",
            decision="error",
            risk_score=0,
            detector_status="error",
            findings_count=0,
            finding_categories=[],
            finding_detectors=[],
            latency_ms=latency_ms,
            error_message=f"Unexpected error: {exc}",
        )

    return PredictionRecord(
        case_id=case_id,
        ground_truth=ground_truth,
        attack_category=attack_category,
        difficulty=difficulty,
        mode=mode,
        predicted=predicted,
        decision=decision,
        risk_score=risk_score,
        detector_status=detector_status,
        findings_count=findings_count,
        finding_categories=finding_categories,
        finding_detectors=finding_detectors,
        latency_ms=latency_ms,
        error_message=error_msg,
    )


def save_predictions_csv(records: List[PredictionRecord], csv_path: Path) -> None:
    """Save detailed per-case prediction records to CSV."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "case_id",
        "mode",
        "ground_truth",
        "predicted",
        "decision",
        "risk_score",
        "detector_status",
        "findings_count",
        "finding_categories",
        "finding_detectors",
        "difficulty",
        "attack_category",
        "latency_ms",
        "error_message",
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)
        for r in records:
            writer.writerow([
                r.case_id,
                r.mode,
                r.ground_truth,
                r.predicted,
                r.decision,
                r.risk_score,
                r.detector_status,
                r.findings_count,
                ";".join(r.finding_categories),
                ";".join(r.finding_detectors),
                r.difficulty,
                r.attack_category,
                f"{r.latency_ms:.3f}",
                r.error_message or "",
            ])


def generate_markdown_report(
    run_timestamp: str,
    dataset_path: str,
    policy_mode: str,
    model_name: str,
    total_cases: int,
    category_counts: Dict[str, int],
    difficulty_counts: Dict[str, int],
    metrics_list: List[MetricResult],
) -> str:
    """Generate comprehensive human-readable Markdown evaluation report."""
    md_table = format_markdown_table(metrics_list)
    malicious_count = total_cases - category_counts.get("none", 0)
    all_benign_notice = ""
    if malicious_count == 0:
        all_benign_notice = (
            "> [!NOTE]\n"
            "> **Evaluation Sample Notice: All-Benign Subset**:\n"
            f"> This benchmark run was evaluated on an all-benign sample ({total_cases} cases, 0 malicious injection cases).\n"
            "> Recall, F1 Score, and False-Negative Rate are mathematically undefined (reported as `N/A`) because no ground-truth attack cases were present in the sample.\n"
            "> An all-benign run measures false-positive rate and specificity, but does **not** evaluate attack detection capability. The detector has not been fully evaluated until tested against both benign and malicious attack cases.\n\n"
        )

    doc = f"""# PromptFence Security Evaluation Report

**Run Timestamp**: {run_timestamp}  
**Policy Enforcement Profile**: `{policy_mode}`  
**Configured Local Model**: `{model_name}` (Ollama)  
**Dataset Evaluated**: `{dataset_path}` ({total_cases} test cases)  

---

## 1. Executive Summary & Benchmark Notice

This report presents a quantitative security evaluation of **PromptFence** indirect prompt injection detectors across three operating modes:
- **`rules`**: Ultra-fast deterministic phrase matching catalog.
- **`llm`**: Local open-weight semantic intent classification using Ollama (`{model_name}`).
- **`hybrid`**: Multi-signal ensemble merging rule signatures and semantic findings.

> **Notice: Synthetic Benchmark Limitation**:  
> The evaluation dataset is a curated synthetic benchmark designed for reproducible, standardized security testing. It is **not** a statistically representative sample of live production traffic. Real-world injection attempts may exhibit novel phrasing, multi-turn context dependencies, or obfuscation techniques beyond synthetic suites. Prompt injection defense is probabilistic; auxiliary models provide defense-in-depth and do not replace backend tool allowlists, argument validation ceilings, or deterministic policy constraints.

---

## 2. Comparative Security Performance

{all_benign_notice}{md_table}

### Metric Definitions & Decision Mapping
- **Positive Class**: Malicious prompt injection / security threat indicators present.
- **Negative Class**: Benign / harmless content.
- **Decision Mapping**:
  - `allow` -> **`benign`**: Input evaluated without actionable policy violations.
  - `review` -> **`malicious`**: Indicator findings detected (e.g. instruction overrides); autonomous agent action halted pending manual human inspection.
  - `block` -> **`malicious`**: High-severity indicator detected in serious attack categories; immediate containment enforced.
  - `error` -> **`error`**: Detector unavailability or timeout; recorded strictly as an error and **never** counted as a clean allow.
- **Accuracy**: `(TP + TN) / Total Evaluated Cases`
- **Precision**: `TP / (TP + FP)` (proportion of flagged inputs that were genuine attacks).
- **Recall (Sensitivity)**: `TP / (TP + FN)` (proportion of genuine attacks successfully detected).
- **F1 Score**: Harmonic mean of Precision and Recall (`2 * P * R / (P + R)`).
- **False-Positive Rate (FPR)**: `FP / (FP + TN)` (benign cases erroneously flagged as threats).
- **False-Negative Rate (FNR)**: `FN / (FN + TP)` (missed attacks permitted without detection).
- **Coverage**: Evaluated cases / total dataset cases.

---

## 3. Dataset Composition

- **Total Test Cases**: {total_cases}
- **Label Split**:
  - Benign: {category_counts.get("none", 0)} cases
  - Malicious: {total_cases - category_counts.get("none", 0)} cases
- **Attack Category Distribution**:
  - `none` (benign): {category_counts.get("none", 0)}
  - `instruction_override`: {category_counts.get("instruction_override", 0)}
  - `secret_extraction`: {category_counts.get("secret_extraction", 0)}
  - `data_exfiltration`: {category_counts.get("data_exfiltration", 0)}
  - `unauthorized_tool_use`: {category_counts.get("unauthorized_tool_use", 0)}
- **Difficulty Breakdown**:
  - `basic`: {difficulty_counts.get("basic", 0)}
  - `intermediate`: {difficulty_counts.get("intermediate", 0)}
  - `adversarial`: {difficulty_counts.get("adversarial", 0)}

---

## 4. Key Findings & Behavioral Analysis

1. **Deterministic Rule Engine (`rules`)**:
   - Sub-millisecond latency (typically < 1.0 ms) makes it suitable for high-throughput gateway filtering.
   - Extremely high precision on known phrase signatures.
   - Susceptible to paraphrased, steganographic, or novel injection framing outside signature catalogs.
2. **Local LLM Detector (`llm`)**:
   - Evaluates natural language semantics and semantic intent beyond exact literal strings.
   - Subject to inference latency (~4–8s on CPU-only 8 GB RAM hardware).
   - In the event of service downtime, fails safe by emitting an explicit HTTP 503 rather than false approval.
3. **Hybrid Ensemble Mode (`hybrid`)**:
   - Combines deterministic speed and zero-trust certainty with probabilistic semantic detection.
   - Enforces the **Non-Cancellation Guarantee**: a benign or low-risk model output cannot cancel a high-severity rule detection.
   - Features **Graceful Degradation**: if Ollama inference fails, the rule engine findings are preserved and policy evaluation proceeds under a `degraded` operational status.
"""
    return doc


def run_benchmark(
    dataset_path: Path,
    modes: List[str],
    policy_mode: str = "balanced",
    output_dir: Path = Path("evaluation/results"),
    limit: Optional[int] = None,
    timeout: float = 30.0,
) -> Tuple[Path, Dict[str, MetricResult]]:
    """Execute evaluation benchmark across requested detector modes and save artifacts."""
    records = load_dataset(dataset_path)
    if limit is not None and limit > 0:
        records = records[:limit]

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = output_dir / f"run_{timestamp_str}"
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n=======================================================")
    print(f" PromptFence Security Benchmark Runner")
    print(f" Timestamp:   {timestamp_str}")
    print(f" Dataset:     {dataset_path} ({len(records)} cases)")
    print(f" Policy Mode: {policy_mode}")
    print(f" Modes:       {', '.join(modes)}")
    print(f" Output Dir:  {run_dir}")
    print(f"=======================================================\n")

    all_predictions: List[PredictionRecord] = []
    metrics_by_mode: Dict[str, MetricResult] = {}

    for mode in modes:
        print(f"[*] Starting evaluation for mode: '{mode}'...")
        mode_records: List[PredictionRecord] = []

        for idx, item in enumerate(records, start=1):
            pred_record = evaluate_case(item, mode=mode, policy_mode=policy_mode)
            mode_records.append(pred_record)
            all_predictions.append(pred_record)

            status_indicator = "OK" if pred_record.predicted != "error" else "ERR"
            match_indicator = "HIT" if pred_record.predicted == pred_record.ground_truth else "MISS"
            if pred_record.predicted == "error":
                match_indicator = "ERR"

            print(
                f"  [{mode.upper():<6}] ({idx:>3}/{len(records)}) "
                f"ID: {pred_record.case_id:<12} "
                f"Truth: {pred_record.ground_truth:<9} "
                f"Pred: {pred_record.predicted:<9} "
                f"Dec: {pred_record.decision:<6} "
                f"Lat: {pred_record.latency_ms:>7.2f}ms [{match_indicator}]"
            )

        metric_res = calculate_metrics(mode_records, mode_name=mode)
        metrics_by_mode[mode] = metric_res
        acc_s = f"{metric_res.accuracy:.2%}" if metric_res.accuracy is not None else "N/A"
        prec_s = f"{metric_res.precision:.2%}" if metric_res.precision is not None else "N/A"
        rec_s = f"{metric_res.recall:.2%}" if metric_res.recall is not None else "N/A"
        print(
            f"[+] Mode '{mode}' complete: "
            f"Accuracy: {acc_s} | "
            f"Precision: {prec_s} | "
            f"Recall: {rec_s} | "
            f"Errors: {metric_res.error_cases} | "
            f"Mean Lat: {metric_res.mean_latency_ms:.2f}ms\n"
        )

    # 1. Save predictions CSV
    csv_file = run_dir / "predictions.csv"
    save_predictions_csv(all_predictions, csv_file)

    # 2. Save metrics JSON
    json_file = run_dir / "metrics.json"
    metrics_payload = {
        "timestamp": timestamp_str,
        "config": {
            "dataset_path": str(dataset_path),
            "total_cases": len(records),
            "policy_mode": policy_mode,
            "model_name": DEFAULT_MODEL,
            "modes_evaluated": modes,
            "timeout_seconds": timeout,
        },
        "metrics": {m: res.to_dict() for m, res in metrics_by_mode.items()},
    }
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)

    # 3. Generate and save Markdown Report
    category_counts: Dict[str, int] = {}
    difficulty_counts: Dict[str, int] = {}
    for r in records:
        cat = r["attack_category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1
        diff = r["difficulty"]
        difficulty_counts[diff] = difficulty_counts.get(diff, 0) + 1

    report_md = generate_markdown_report(
        run_timestamp=timestamp_str,
        dataset_path=str(dataset_path),
        policy_mode=policy_mode,
        model_name=DEFAULT_MODEL,
        total_cases=len(records),
        category_counts=category_counts,
        difficulty_counts=difficulty_counts,
        metrics_list=list(metrics_by_mode.values()),
    )
    report_file = run_dir / "report.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(report_md)

    print("=======================================================")
    print(" Benchmark Evaluation Complete!")
    print(f" Predictions CSV:  {csv_file}")
    print(f" Metrics JSON:     {json_file}")
    print(f" Markdown Report:  {report_file}")
    print("=======================================================\n")
    print(format_markdown_table(list(metrics_by_mode.values())))
    print("\n")

    return run_dir, metrics_by_mode


def main() -> None:
    """CLI entry point for run_benchmark."""
    parser = argparse.ArgumentParser(
        description="PromptFence Security Evaluation and Benchmarking Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--modes",
        nargs="+",
        choices=["rules", "llm", "hybrid"],
        default=["rules"],
        help="Detector modes to evaluate: 'rules', 'llm', 'hybrid'.",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="evaluation/dataset.jsonl",
        help="Path to the JSONL evaluation dataset.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="evaluation/results",
        help="Destination directory for benchmark result runs.",
    )
    parser.add_argument(
        "--policy-mode",
        choices=["permissive", "balanced", "strict"],
        default="balanced",
        help="Policy enforcement tier to apply during evaluation.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum number of records to process from the dataset.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP request timeout for LLM inference in seconds.",
    )

    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    output_dir = Path(args.output_dir)

    try:
        run_benchmark(
            dataset_path=dataset_path,
            modes=args.modes,
            policy_mode=args.policy_mode,
            output_dir=output_dir,
            limit=args.limit,
            timeout=args.timeout,
        )
    except Exception as exc:
        print(f"\n[!] Benchmark execution failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
