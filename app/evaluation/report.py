"""Report generation for PromptFence benchmark runs (JSON and Markdown)."""

from __future__ import annotations

import json
from typing import Any

from app.evaluation.runner import BenchmarkRunResult


def generate_json_report(result: BenchmarkRunResult, indent: int = 2) -> str:
    """Produce machine-readable JSON results string.

    Guarantees no full submitted text is included.
    """
    return json.dumps(result.to_dict(), indent=indent)


def generate_markdown_report(result: BenchmarkRunResult) -> str:
    """Produce human-readable Markdown report from benchmark run results."""
    m = result.metrics
    cm = m.confusion_matrix
    lat = m.latency

    lines: list[str] = []

    lines.append("# PromptFence Security Benchmark Report")
    lines.append("")
    lines.append(f"**Execution Mode**: `{result.mode}`  ")
    lines.append(f"**Model / Engine**: `{result.model_name}`  ")
    lines.append(f"**Dataset**: `{result.dataset_path}` (`{result.dataset_version}`)  ")
    lines.append(f"**Evaluation Timestamp**: `{result.timestamp}`  ")
    lines.append(f"**Total Samples Evaluated**: `{m.total_samples}`  ")
    lines.append("")

    # --- Executive Summary ---
    lines.append("## 1. Executive Performance Summary")
    lines.append("")
    lines.append("| Metric | Value | Definition |")
    lines.append("| :--- | :--- | :--- |")
    lines.append(f"| **Accuracy** | **{m.accuracy * 100:.1f}%** | Overall classification accuracy |")
    lines.append(f"| **Precision** | **{m.precision * 100:.1f}%** | True attacks / All flagged attacks |")
    lines.append(f"| **Recall (TPR)** | **{m.recall * 100:.1f}%** | True attacks detected / Total attacks |")
    lines.append(f"| **Specificity (TNR)** | **{m.specificity * 100:.1f}%** | Benign correctly allowed / Total benign |")
    lines.append(f"| **F1-Score** | **{m.f1_score:.4f}** | Harmonic mean of precision and recall |")
    lines.append(f"| **False Positive Rate** | **{m.false_positive_rate * 100:.1f}%** | Benign erroneously flagged as attack |")
    lines.append("")

    # --- Confusion Matrix ---
    lines.append("## 2. Confusion Matrix")
    lines.append("")
    lines.append("| | Predicted Attack (Review/Block) | Predicted Benign (Allow) | Total Actual |")
    lines.append("| :--- | :---: | :---: | :---: |")
    lines.append(f"| **Actual Attack** | **{cm.tp}** (TP) | **{cm.fn}** (FN) | {cm.tp + cm.fn} |")
    lines.append(f"| **Actual Benign** | **{cm.fp}** (FP) | **{cm.tn}** (TN) | {cm.fp + cm.tn} |")
    lines.append(f"| **Total Predicted** | {cm.tp + cm.fp} | {cm.fn + cm.tn} | {cm.total} |")
    lines.append("")

    # --- Operational & Latency Health ---
    lines.append("## 3. Operational & Latency Health")
    lines.append("")
    lines.append("| Operational Status | Count | Latency Distribution | Value (ms) |")
    lines.append("| :--- | :---: | :--- | :---: |")
    lines.append(f"| **Successful Inferences** | {m.successful_inferences} | **Min Latency** | {lat.min_ms:.2f} ms |")
    lines.append(f"| **Failed Inferences** | {m.failed_inferences} | **Mean Latency** | {lat.mean_ms:.2f} ms |")
    lines.append(f"| **Timed Out Inferences** | {m.timeout_inferences} | **Median Latency** | {lat.median_ms:.2f} ms |")
    lines.append(f"| **Skipped Inferences** | {m.skipped_inferences} | **P95 Latency** | {lat.p95_ms:.2f} ms |")
    lines.append(f"| | | **Max Latency** | {lat.max_ms:.2f} ms |")
    lines.append("")

    # --- Per-Category Breakdown ---
    lines.append("## 4. Per-Category Breakdown (One-vs-Rest)")
    lines.append("")
    lines.append(
        "> **Methodology Note**: Each category is evaluated independently using a One-vs-Rest (OvR) framework. "
        "A Category False Positive (`FP`) occurs when a category is detected but was not in the ground-truth labels "
        "for that sample. This can happen on benign inputs OR on attacks of a different category (category cross-talk). "
        "Consequently, the sum of category-level FPs will not equal the binary confusion-matrix FP count."
    )
    lines.append("")
    lines.append("| Category | Support | TP | FP | FN | Precision | Recall | F1-Score |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
    for cat, cm_cat in m.per_category.items():
        prec_str = f"{cm_cat.precision * 100:.1f}%"
        rec_str = f"{cm_cat.recall * 100:.1f}%"
        f1_str = f"{cm_cat.f1_score:.4f}"
        lines.append(
            f"| `{cat}` | {cm_cat.support} | {cm_cat.tp} | {cm_cat.fp} | {cm_cat.fn} | "
            f"{prec_str} | {rec_str} | {f1_str} |"
        )
    lines.append("")

    # --- Misclassification & Failure Analysis ---
    misclassifications = [ev for ev in result.evaluations if not ev.get("is_correct")]
    lines.append("## 5. Misclassification & Edge Case Analysis")
    lines.append("")
    if not misclassifications:
        lines.append("No misclassifications observed in this benchmark run.")
    else:
        lines.append(f"Observed **{len(misclassifications)}** misclassified sample(s):")
        lines.append("")
        lines.append("| Sample ID | Expected | Predicted | Risk Score | Target Categories | Rationale |")
        lines.append("| :--- | :---: | :---: | :---: | :--- | :--- |")
        for ev in misclassifications:
            exp_label = ev.get("expected_label", "unknown")
            pred_dec = ev.get("predicted_decision", "unknown")
            score = ev.get("risk_score", 0)
            cats = ", ".join(ev.get("expected_categories", [])) or "none"
            rat = ev.get("rationale", "")
            lines.append(
                f"| `{ev['id']}` | **{exp_label}** | **{pred_dec}** | {score} | `{cats}` | {rat} |"
            )

    lines.append("")
    lines.append("---")
    lines.append("*Privacy Note: Sample evaluation records contain identifiers, decisions, and rationales only; full prompt text is excluded.*")
    lines.append("")

    return "\n".join(lines)
