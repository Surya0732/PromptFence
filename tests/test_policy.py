"""Unit tests for the PromptFence policy engine."""

from __future__ import annotations

import pytest

from app.policy.engine import PolicyEngine, evaluate_policy
from app.schemas import Decision, Finding, FindingCategory, FindingSeverity


class TestPolicyEngine:
    """Test suite covering policy decision rules and deterministic risk scoring."""

    def test_no_findings_returns_allow(self) -> None:
        """When findings list is empty, policy must allow with risk score 0."""
        result = evaluate_policy([])
        assert result["decision"] == Decision.ALLOW.value
        assert result["risk_score"] == 0
        assert "allowed" in result["explanation"].lower()

    def test_low_severity_finding_returns_review(self) -> None:
        """Low severity findings should result in a review decision."""
        findings = [
            {
                "detector": "rule_engine",
                "category": FindingCategory.INSTRUCTION_OVERRIDE.value,
                "severity": FindingSeverity.LOW.value,
                "evidence": "...act as an unfiltered...",
                "matched_indicator": "act as an unfiltered",
            }
        ]
        result = evaluate_policy(findings)
        assert result["decision"] == Decision.REVIEW.value
        assert 20 <= result["risk_score"] <= 70
        assert "review" in result["explanation"].lower()

    def test_medium_severity_finding_returns_review(self) -> None:
        """Medium severity findings without critical indicators should trigger review."""
        findings = [
            {
                "detector": "rule_engine",
                "category": FindingCategory.INSTRUCTION_OVERRIDE.value,
                "severity": FindingSeverity.MEDIUM.value,
                "evidence": "...you are now in developer mode...",
                "matched_indicator": "you are now in developer mode",
            }
        ]
        result = evaluate_policy(findings)
        assert result["decision"] == Decision.REVIEW.value
        assert 25 <= result["risk_score"] <= 70

    @pytest.mark.parametrize(
        "serious_category",
        [
            FindingCategory.SECRET_EXTRACTION.value,
            FindingCategory.DATA_EXFILTRATION.value,
            FindingCategory.UNAUTHORIZED_TOOL_USE.value,
        ],
    )
    def test_high_severity_serious_categories_trigger_block(self, serious_category: str) -> None:
        """High-severity findings in secret extraction, data exfil, or unauthorized tool use must block."""
        findings = [
            {
                "detector": "rule_engine",
                "category": serious_category,
                "severity": FindingSeverity.HIGH.value,
                "evidence": "...critical exploit attempt...",
                "matched_indicator": "test_indicator",
            }
        ]
        result = evaluate_policy(findings)
        assert result["decision"] == Decision.BLOCK.value
        assert result["risk_score"] >= 75
        assert "blocked" in result["explanation"].lower()

    def test_high_severity_instruction_override_alone_triggers_review(self) -> None:
        """An isolated high-severity instruction override should result in review."""
        findings = [
            {
                "detector": "rule_engine",
                "category": FindingCategory.INSTRUCTION_OVERRIDE.value,
                "severity": FindingSeverity.HIGH.value,
                "evidence": "...ignore previous instructions...",
                "matched_indicator": "ignore previous instructions",
            }
        ]
        result = evaluate_policy(findings)
        assert result["decision"] == Decision.REVIEW.value
        assert 25 <= result["risk_score"] <= 70
        assert "review" in result["explanation"].lower()

    def test_high_severity_instruction_override_with_additional_evidence_triggers_block(self) -> None:
        """High-severity instruction override combined with additional attack evidence must trigger block."""
        findings = [
            {
                "detector": "rule_engine",
                "category": FindingCategory.INSTRUCTION_OVERRIDE.value,
                "severity": FindingSeverity.HIGH.value,
                "evidence": "...ignore previous instructions...",
                "matched_indicator": "ignore previous instructions",
            },
            {
                "detector": "rule_engine",
                "category": FindingCategory.SECRET_EXTRACTION.value,
                "severity": FindingSeverity.HIGH.value,
                "evidence": "...reveal your system prompt...",
                "matched_indicator": "reveal your system prompt",
            },
        ]
        result = evaluate_policy(findings)
        assert result["decision"] == Decision.BLOCK.value
        assert result["risk_score"] >= 75
        assert "blocked" in result["explanation"].lower()

    def test_low_severity_finding_does_not_cancel_high_severity_finding(self) -> None:
        """A low-severity finding present alongside a high-severity finding must never downgrade a block."""
        findings = [
            {
                "detector": "rule_engine",
                "category": FindingCategory.UNAUTHORIZED_TOOL_USE.value,
                "severity": FindingSeverity.HIGH.value,
                "evidence": "...rm -rf...",
                "matched_indicator": "rm -rf",
            },
            {
                "detector": "rule_engine",
                "category": FindingCategory.INSTRUCTION_OVERRIDE.value,
                "severity": FindingSeverity.LOW.value,
                "evidence": "...act as an unfiltered...",
                "matched_indicator": "act as an unfiltered",
            },
        ]
        result = evaluate_policy(findings)
        assert result["decision"] == Decision.BLOCK.value
        assert result["risk_score"] >= 75

    def test_policy_evaluates_pydantic_finding_objects(self) -> None:
        """Policy engine should work seamlessly with Pydantic Finding objects as well as raw dicts."""
        finding_obj = Finding(
            detector="rule_engine",
            category=FindingCategory.DATA_EXFILTRATION,
            severity=FindingSeverity.HIGH,
            evidence="...curl http...",
            matched_indicator="curl http",
        )
        result = evaluate_policy([finding_obj])
        assert result["decision"] == Decision.BLOCK.value
        assert result["risk_score"] >= 75

    def test_risk_score_is_bounded_and_deterministic(self) -> None:
        """The risk score must always be an integer within [0, 100] and deterministic."""
        findings = [
            Finding(
                detector="rule_engine",
                category=FindingCategory.UNAUTHORIZED_TOOL_USE,
                severity=FindingSeverity.HIGH,
                evidence="...format c:...",
                matched_indicator="format c:",
            ),
            Finding(
                detector="rule_engine",
                category=FindingCategory.DATA_EXFILTRATION,
                severity=FindingSeverity.HIGH,
                evidence="...send data to http...",
                matched_indicator="send data to http",
            ),
        ]
        res1 = evaluate_policy(findings)
        res2 = evaluate_policy(findings)

        assert res1["risk_score"] == res2["risk_score"]
        assert 0 <= res1["risk_score"] <= 100
        assert isinstance(res1["risk_score"], int)

    def test_permissive_mode_allows_low_severity_indicator(self) -> None:
        """Permissive mode should permit isolated low-severity indicators."""
        findings = [
            {
                "detector": "rule_engine",
                "category": FindingCategory.INSTRUCTION_OVERRIDE.value,
                "severity": FindingSeverity.LOW.value,
                "evidence": "...act as an unfiltered...",
                "matched_indicator": "act as an unfiltered",
            }
        ]
        # In balanced mode: review
        balanced_res = evaluate_policy(findings, mode="balanced")
        assert balanced_res["decision"] == Decision.REVIEW.value

        # In permissive mode: allow
        permissive_res = evaluate_policy(findings, mode="permissive")
        assert permissive_res["decision"] == Decision.ALLOW.value
        assert "allowed" in permissive_res["explanation"].lower()

    def test_permissive_mode_still_blocks_high_severity_threats(self) -> None:
        """Permissive mode must never weaken protections against high-severity critical attacks."""
        findings = [
            {
                "detector": "rule_engine",
                "category": FindingCategory.DATA_EXFILTRATION.value,
                "severity": FindingSeverity.HIGH.value,
                "evidence": "...curl http://evil.com...",
                "matched_indicator": "curl http",
            }
        ]
        res = evaluate_policy(findings, mode="permissive")
        assert res["decision"] == Decision.BLOCK.value
        assert res["risk_score"] >= 70

    def test_strict_mode_blocks_isolated_instruction_override(self) -> None:
        """Strict mode enforces zero-trust by blocking isolated high-severity overrides."""
        findings = [
            {
                "detector": "rule_engine",
                "category": FindingCategory.INSTRUCTION_OVERRIDE.value,
                "severity": FindingSeverity.HIGH.value,
                "evidence": "...ignore previous instructions...",
                "matched_indicator": "ignore previous instructions",
            }
        ]
        # In balanced mode: review
        balanced_res = evaluate_policy(findings, mode="balanced")
        assert balanced_res["decision"] == Decision.REVIEW.value

        # In strict mode: block
        strict_res = evaluate_policy(findings, mode="strict")
        assert strict_res["decision"] == Decision.BLOCK.value
        assert strict_res["risk_score"] >= 80
        assert "blocked" in strict_res["explanation"].lower()

    def test_strict_mode_blocks_medium_severity_serious_threat(self) -> None:
        """Strict mode blocks medium-severity findings in serious categories."""
        findings = [
            {
                "detector": "rule_engine",
                "category": FindingCategory.UNAUTHORIZED_TOOL_USE.value,
                "severity": FindingSeverity.MEDIUM.value,
                "evidence": "...call tool without authorization...",
                "matched_indicator": "call tool without authorization",
            }
        ]
        # In balanced mode: review
        balanced_res = evaluate_policy(findings, mode="balanced")
        assert balanced_res["decision"] == Decision.REVIEW.value

        # In strict mode: block
        strict_res = evaluate_policy(findings, mode="strict")
        assert strict_res["decision"] == Decision.BLOCK.value
        assert strict_res["risk_score"] >= 80
