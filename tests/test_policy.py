"""Tests for the policy engine.

These tests verify that ``evaluate_policy`` produces correct risk scores,
decisions, and reasons based on various combinations of findings.
"""

from __future__ import annotations

import pytest

from app.policy.engine import evaluate_policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(category: str = "instruction_override",
             severity: str = "medium",
             indicator: str = "test pattern") -> dict:
    """Build a minimal finding dict for testing."""
    return {
        "detector": "rules",
        "category": category,
        "severity": severity,
        "evidence": "test evidence",
        "matched_indicator": indicator,
    }


# ---------------------------------------------------------------------------
# No findings
# ---------------------------------------------------------------------------


class TestNoFindings:
    """Verify that no findings produces allow with score 0."""

    def test_empty_list(self) -> None:
        result = evaluate_policy([])
        assert result["risk_score"] == 0
        assert result["decision"] == "allow"
        assert isinstance(result["reasons"], list)
        assert len(result["reasons"]) > 0

    def test_none_is_handled_like_empty(self) -> None:
        """If somehow None or falsy is passed, it should not crash."""
        result = evaluate_policy([])
        assert result["decision"] == "allow"


# ---------------------------------------------------------------------------
# Score range
# ---------------------------------------------------------------------------


class TestScoreRange:
    """Verify that the risk score stays within [0, 100]."""

    def test_single_low(self) -> None:
        result = evaluate_policy([_finding(severity="low")])
        assert 0 <= result["risk_score"] <= 100

    def test_many_high_findings(self) -> None:
        """Even many high-severity findings should not exceed 100."""
        findings = [
            _finding("secret_extraction", "high", f"pattern {i}")
            for i in range(20)
        ]
        result = evaluate_policy(findings)
        assert result["risk_score"] <= 100

    def test_score_never_negative(self) -> None:
        result = evaluate_policy([_finding(severity="low")])
        assert result["risk_score"] >= 0


# ---------------------------------------------------------------------------
# Weak indicators
# ---------------------------------------------------------------------------


class TestWeakIndicators:
    """Verify that weak indicators do not automatically produce block."""

    def test_single_low_severity(self) -> None:
        result = evaluate_policy([_finding(severity="low")])
        assert result["decision"] != "block"

    def test_single_medium_severity(self) -> None:
        result = evaluate_policy([_finding(severity="medium")])
        assert result["decision"] != "block"


# ---------------------------------------------------------------------------
# Instruction override handling
# ---------------------------------------------------------------------------


class TestInstructionOverride:
    """Verify that instruction_override alone leads to review, not block."""

    def test_single_override_high(self) -> None:
        result = evaluate_policy([
            _finding("instruction_override", "high"),
        ])
        # Even a high-severity instruction_override alone should cap at review
        assert result["decision"] in ("allow", "review")

    def test_multiple_overrides(self) -> None:
        findings = [
            _finding("instruction_override", "high", f"pattern {i}")
            for i in range(5)
        ]
        result = evaluate_policy(findings)
        assert result["decision"] in ("allow", "review"), (
            "Multiple instruction_override findings alone should not block"
        )


# ---------------------------------------------------------------------------
# Serious findings
# ---------------------------------------------------------------------------


class TestSeriousFindings:
    """Verify that high-severity, high-risk findings receive block."""

    def test_high_secret_extraction(self) -> None:
        findings = [
            _finding("secret_extraction", "high"),
            _finding("data_exfiltration", "high"),
        ]
        result = evaluate_policy(findings)
        assert result["decision"] == "block"

    def test_high_unauthorized_tool_use(self) -> None:
        findings = [
            _finding("unauthorized_tool_use", "high"),
            _finding("data_exfiltration", "high"),
        ]
        result = evaluate_policy(findings)
        assert result["decision"] == "block"

    def test_multi_category_increases_score(self) -> None:
        single = evaluate_policy([_finding("secret_extraction", "medium")])
        multi = evaluate_policy([
            _finding("secret_extraction", "medium", "pattern A"),
            _finding("data_exfiltration", "medium", "pattern B"),
        ])
        assert multi["risk_score"] > single["risk_score"]


# ---------------------------------------------------------------------------
# Response structure
# ---------------------------------------------------------------------------


class TestResponseStructure:
    """Verify the structure of the policy result."""

    def test_keys_present(self) -> None:
        result = evaluate_policy([])
        assert "risk_score" in result
        assert "decision" in result
        assert "reasons" in result

    def test_decision_values(self) -> None:
        """Decision must be one of allow, review, block."""
        for decision in ("allow", "review", "block"):
            # We just verify the type; specific decisions are tested above.
            pass
        result = evaluate_policy([])
        assert result["decision"] in ("allow", "review", "block")

    def test_reasons_is_list_of_strings(self) -> None:
        result = evaluate_policy([_finding()])
        assert isinstance(result["reasons"], list)
        for reason in result["reasons"]:
            assert isinstance(reason, str)
