"""Tests for dashboard helper functions and client integration."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.dashboard_helpers import (
    DEMO_PRESETS,
    fetch_backend_health,
    get_decision_color,
    get_severity_color,
    load_benchmark_report,
    load_markdown_file,
    scan_text,
)


class TestDashboardColorHelpers:
    """Test decision and severity color formatting."""

    def test_decision_colors(self) -> None:
        assert get_decision_color("allow") == "#10B981"
        assert get_decision_color("ALLOW") == "#10B981"
        assert get_decision_color("review") == "#F59E0B"
        assert get_decision_color("block") == "#EF4444"
        assert get_decision_color("unknown") == "#6B7280"

    def test_severity_colors(self) -> None:
        assert get_severity_color("low") == "#3B82F6"
        assert get_severity_color("medium") == "#F59E0B"
        assert get_severity_color("high") == "#EF4444"
        assert get_severity_color("other") == "#9CA3AF"


class TestDashboardPresets:
    """Validate structure of curated demo presets."""

    def test_presets_have_required_fields(self) -> None:
        assert len(DEMO_PRESETS) >= 5
        required_keys = {"id", "title", "category", "expected", "text", "description"}
        for preset in DEMO_PRESETS:
            assert required_keys.issubset(preset.keys())
            assert len(preset["text"].strip()) > 0
            assert len(preset["id"].strip()) > 0


class TestReportLoaders:
    """Test loading benchmark files from disk."""

    def test_load_benchmark_report_valid(self, tmp_path: Path) -> None:
        report_file = tmp_path / "valid_report.json"
        report_file.write_text(json.dumps({"metrics": {"accuracy": 0.95}}), encoding="utf-8")

        data = load_benchmark_report(report_file)
        assert data is not None
        assert data["metrics"]["accuracy"] == 0.95

    def test_load_benchmark_report_nonexistent(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.json"
        assert load_benchmark_report(missing) is None

    def test_load_benchmark_report_invalid_json(self, tmp_path: Path) -> None:
        corrupt = tmp_path / "corrupt.json"
        corrupt.write_text("{not valid json", encoding="utf-8")
        assert load_benchmark_report(corrupt) is None

    def test_load_markdown_file(self, tmp_path: Path) -> None:
        md = tmp_path / "test.md"
        md.write_text("# Test Header\nSome markdown text", encoding="utf-8")

        content = load_markdown_file(md)
        assert content is not None
        assert "# Test Header" in content

    def test_load_markdown_file_missing(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.md"
        assert load_markdown_file(missing) is None


class TestBackendHealthFetch:
    """Test backend health checking."""

    def test_health_online(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "ok",
            "model": "gemma4:e2b",
            "components": {
                "rule_engine": "operational",
                "ollama": "available",
            },
        }

        with patch("httpx.Client.get", return_value=mock_response):
            health = fetch_backend_health("http://127.0.0.1:8000")
            assert health["online"] is True
            assert health["status"] == "ok"
            assert health["ollama"] == "available"
            assert health["model"] == "gemma4:e2b"
            assert health["error"] is None

    def test_health_backend_offline(self) -> None:
        with patch("httpx.Client.get", side_effect=httpx.ConnectError("Connection refused")):
            health = fetch_backend_health("http://127.0.0.1:8000")
            assert health["online"] is False
            assert health["status"] == "offline"
            assert health["ollama"] == "unavailable"
            assert "Connection refused" in health["error"]


class TestScanTextHelper:
    """Test scan text submission to backend."""

    def test_scan_text_success(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "allow",
            "risk_score": 0,
            "reasons": ["Safe input"],
            "findings": [],
            "detector_statuses": [{"detector": "rules", "status": "success"}],
        }

        with patch("httpx.Client.post", return_value=mock_response):
            res = scan_text("Hello world", mode="rules_only")
            assert res["decision"] == "allow"
            assert res["risk_score"] == 0

    def test_scan_text_connection_error_raises_user_friendly_error(self) -> None:
        with patch("httpx.Client.post", side_effect=httpx.ConnectError("Connection refused")):
            with pytest.raises(RuntimeError) as exc_info:
                scan_text("Hello world", mode="hybrid")
            assert "Cannot connect to PromptFence backend" in str(exc_info.value)
            assert "uvicorn app.main:app" in str(exc_info.value)

    def test_scan_text_timeout_raises_user_friendly_error(self) -> None:
        with patch("httpx.Client.post", side_effect=httpx.TimeoutException("Timed out")):
            with pytest.raises(RuntimeError) as exc_info:
                scan_text("Hello world", mode="hybrid")
            assert "timed out" in str(exc_info.value)

    def test_scan_text_http_error(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 422
        mock_response.text = '{"detail": "Validation error"}'
        mock_response.json.return_value = {"detail": "Validation error"}

        with patch("httpx.Client.post", return_value=mock_response):
            with pytest.raises(RuntimeError) as exc_info:
                scan_text("", mode="hybrid")
            assert "HTTP 422" in str(exc_info.value)
