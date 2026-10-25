"""CLI entry point for running PromptFence security benchmarks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.evaluation.dataset import DatasetParseError, load_dataset
from app.evaluation.report import generate_json_report, generate_markdown_report
from app.evaluation.runner import run_evaluation


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser for the benchmark runner."""
    parser = argparse.ArgumentParser(
        prog="promptfence-benchmark",
        description="PromptFence Reproducible Security Evaluation Benchmark",
    )
    parser.add_argument(
        "--mode",
        choices=["rules_only", "llm_only", "hybrid"],
        default="rules_only",
        help="Detection mode to evaluate (default: rules_only).",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="data/benchmark_v1.jsonl",
        help="Path to the JSONL dataset file (default: data/benchmark_v1.jsonl).",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="v1.0",
        help="Dataset version identifier (default: v1.0).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Ollama model name override (for llm_only or hybrid modes).",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Maximum number of dataset samples to evaluate.",
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default="benchmark_results.json",
        help="Path to write machine-readable JSON results (default: benchmark_results.json).",
    )
    parser.add_argument(
        "--output-md",
        type=str,
        default="benchmark_report.md",
        help="Path to write human-readable Markdown report (default: benchmark_report.md).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console progress and summaries.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute benchmark CLI with parsed arguments."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.quiet:
        print("=" * 70)
        print(" PromptFence Security Benchmark Runner")
        print(f" Mode: {args.mode} | Dataset: {args.dataset}")
        print("=" * 70)

    # 1. Load dataset
    try:
        dataset = load_dataset(args.dataset)
    except FileNotFoundError:
        print(f"Error: Dataset file not found at '{args.dataset}'", file=sys.stderr)
        return 1
    except DatasetParseError as exc:
        print(f"Error parsing dataset: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"Loaded {len(dataset)} examples from {args.dataset}")
        print(f"Running evaluation in '{args.mode}' mode...")

    # 2. Run evaluation
    result = run_evaluation(
        dataset=dataset,
        mode=args.mode,
        dataset_path=args.dataset,
        dataset_version=args.version,
        model_name=args.model,
        max_samples=args.max_samples,
    )

    # 3. Write reports
    json_path = Path(args.output_json)
    md_path = Path(args.output_md)

    json_content = generate_json_report(result)
    md_content = generate_markdown_report(result)

    json_path.write_text(json_content, encoding="utf-8")
    md_path.write_text(md_content, encoding="utf-8")

    if not args.quiet:
        m = result.metrics
        print("\n--- Benchmark Results ---")
        print(f"Total Evaluated: {m.total_samples}")
        print(f"Accuracy:        {m.accuracy * 100:.1f}%")
        print(f"Precision:       {m.precision * 100:.1f}%")
        print(f"Recall (TPR):    {m.recall * 100:.1f}%")
        print(f"F1-Score:        {m.f1_score:.4f}")
        print(f"FPR:             {m.false_positive_rate * 100:.1f}%")
        print(f"Mean Latency:    {m.latency.mean_ms:.2f} ms")
        print(f"Failed Inferences: {result.failed_count}")
        print(f"\nSaved JSON results to: {json_path.resolve()}")
        print(f"Saved Markdown report to: {md_path.resolve()}")
        print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
