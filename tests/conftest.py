"""Pytest configuration and custom marker definitions for PromptFence."""

from __future__ import annotations

import os
import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register custom CLI options."""
    parser.addoption(
        "--run-live-ollama",
        action="store_true",
        default=False,
        help="Execute live integration tests that require a running local Ollama service and qwen2.5:1.5b",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "live_ollama: mark test as requiring local Ollama service with qwen2.5:1.5b model",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip live_ollama tests unless explicitly requested via CLI flag or env var."""
    run_live = config.getoption("--run-live-ollama") or (
        os.environ.get("PROMPTFENCE_LIVE_OLLAMA", "").strip() == "1"
    )

    if not run_live:
        skip_live = pytest.mark.skip(
            reason="Live Ollama tests skipped in default offline test run. Use --run-live-ollama or set PROMPTFENCE_LIVE_OLLAMA=1 to run."
        )
        for item in items:
            if "live_ollama" in item.keywords:
                item.add_marker(skip_live)
