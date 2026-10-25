"""Configurable policy engine for PromptFence.

This module evaluates security findings against configurable policy rules
to arrive at an enforcement decision ('allow', 'review', or 'block'),
a deterministic heuristic risk score (0-100), and an explanatory rationale.

Supports three policy enforcement modes:
- permissive: Permits low-severity indicators; reserves block for confirmed serious threats.
- balanced: Baseline security; blocks high-severity serious threats; flags overrides and low/medium findings for review.
- strict: Zero-trust; blocks all high-severity overrides immediately and blocks medium-severity serious threats.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union

from app.schemas import Decision, FindingCategory, FindingSeverity, PolicyMode

# Category groupings for policy enforcement
SERIOUS_ATTACK_CATEGORIES: Set[str] = {
    FindingCategory.SECRET_EXTRACTION.value,
    FindingCategory.DATA_EXFILTRATION.value,
    FindingCategory.UNAUTHORIZED_TOOL_USE.value,
}

# Base heuristic point allocations by severity
SEVERITY_WEIGHTS: Dict[str, int] = {
    FindingSeverity.LOW.value: 15,
    FindingSeverity.MEDIUM.value: 35,
    FindingSeverity.HIGH.value: 60,
}

# Category-specific heuristic threat adjustments
CATEGORY_ADJUSTMENTS: Dict[str, int] = {
    FindingCategory.INSTRUCTION_OVERRIDE.value: 5,
    FindingCategory.SECRET_EXTRACTION.value: 10,
    FindingCategory.DATA_EXFILTRATION.value: 15,
    FindingCategory.UNAUTHORIZED_TOOL_USE.value: 15,
}


@dataclass
class PolicyConfig:
    """Configurable policy parameters governing decision rules and scoring thresholds.

    Attributes:
        mode: PolicyMode identifier.
        block_categories: Threat categories subject to automated blocking.
        block_isolated_override: Whether an isolated high-severity instruction override triggers block.
        block_medium_serious: Whether medium-severity findings in serious categories trigger block.
        allow_low_severity: Whether isolated low-severity findings are permitted without review.
        multi_finding_compounding: Point increment per additional finding beyond the first.
        cross_category_bonus: Additional risk increment when multiple categories are attacked.
        block_floor_score: Minimum risk score guaranteed when a block decision is made.
        review_floor_score: Minimum risk score assigned when a review decision is made.
        review_ceiling_score: Maximum risk score allowed for review without triggering block.
    """

    mode: PolicyMode = PolicyMode.BALANCED
    block_categories: Set[str] = field(default_factory=lambda: set(SERIOUS_ATTACK_CATEGORIES))
    block_isolated_override: bool = False
    block_medium_serious: bool = False
    allow_low_severity: bool = False
    multi_finding_compounding: int = 5
    cross_category_bonus: int = 10
    block_floor_score: int = 75
    review_floor_score: int = 25
    review_ceiling_score: int = 70


def get_policy_config(mode: Union[PolicyMode, str] = PolicyMode.BALANCED) -> PolicyConfig:
    """Construct a documented PolicyConfig profile for the requested mode.

    Modes:
    - permissive:
        - Blocks high-severity in serious categories (secret_extraction, data_exfiltration, unauthorized_tool_use).
        - Allows low-severity indicators without blocking or forcing review.
        - Review for medium-severity and isolated overrides.
        - Score floors: block=70, review=20.
    - balanced (default):
        - Standard baseline policy.
        - Blocks high-severity serious categories.
        - Blocks high-severity instruction override if secondary attack evidence exists.
        - Review for isolated override and low/medium findings.
        - Score floors: block=75, review=25.
    - strict:
        - Zero-trust defense posture.
        - Immediately blocks ANY high-severity finding (including isolated instruction overrides).
        - Immediately blocks medium-severity findings in serious attack categories.
        - Review for remaining low/medium indicators.
        - Score floors: block=80, review=35.
    """
    mode_str = mode.value if isinstance(mode, PolicyMode) else str(mode).lower()

    if mode_str == PolicyMode.PERMISSIVE.value:
        return PolicyConfig(
            mode=PolicyMode.PERMISSIVE,
            block_categories=set(SERIOUS_ATTACK_CATEGORIES),
            block_isolated_override=False,
            block_medium_serious=False,
            allow_low_severity=True,
            block_floor_score=70,
            review_floor_score=20,
            review_ceiling_score=60,
        )
    elif mode_str == PolicyMode.STRICT.value:
        return PolicyConfig(
            mode=PolicyMode.STRICT,
            block_categories=set(SERIOUS_ATTACK_CATEGORIES),
            block_isolated_override=True,
            block_medium_serious=True,
            allow_low_severity=False,
            block_floor_score=80,
            review_floor_score=35,
            review_ceiling_score=75,
        )
    else:  # Default: BALANCED
        return PolicyConfig(
            mode=PolicyMode.BALANCED,
            block_categories=set(SERIOUS_ATTACK_CATEGORIES),
            block_isolated_override=False,
            block_medium_serious=False,
            allow_low_severity=False,
            block_floor_score=75,
            review_floor_score=25,
            review_ceiling_score=70,
        )


class PolicyEngine:
    """Evaluates findings to produce decisions and heuristic risk scores."""

    def __init__(
        self,
        config: Optional[PolicyConfig] = None,
        mode: Optional[Union[PolicyMode, str]] = None,
    ) -> None:
        if config is not None:
            self.config = config
        elif mode is not None:
            self.config = get_policy_config(mode)
        else:
            self.config = get_policy_config(PolicyMode.BALANCED)

    @staticmethod
    def _extract_field(finding: Any, field_name: str) -> str:
        """Safely extract a string value from a dict or Pydantic finding object."""
        if isinstance(finding, dict):
            val = finding.get(field_name, "")
        else:
            val = getattr(finding, field_name, "")

        if hasattr(val, "value"):
            return str(val.value)
        return str(val)

    def calculate_risk_score(self, findings: List[Any], decision: Decision) -> int:
        """Compute a deterministic heuristic risk score between 0 and 100."""
        if not findings or decision == Decision.ALLOW:
            return 0

        score = 0
        categories_seen: Set[str] = set()

        for idx, finding in enumerate(findings):
            cat = self._extract_field(finding, "category")
            sev = self._extract_field(finding, "severity")

            score += SEVERITY_WEIGHTS.get(sev, 10)
            score += CATEGORY_ADJUSTMENTS.get(cat, 5)

            if cat:
                categories_seen.add(cat)

            if idx > 0 and (idx * self.config.multi_finding_compounding) <= 15:
                score += self.config.multi_finding_compounding

        if len(categories_seen) >= 2:
            score += self.config.cross_category_bonus

        if decision == Decision.BLOCK:
            final_score = max(self.config.block_floor_score, score)
        elif decision == Decision.REVIEW:
            final_score = max(self.config.review_floor_score, min(self.config.review_ceiling_score, score))
        else:
            final_score = min(20, score)

        return max(0, min(100, int(final_score)))

    def evaluate(self, findings: List[Any]) -> Dict[str, Any]:
        """Evaluate a list of findings against the active policy profile."""
        if not findings:
            return {
                "decision": Decision.ALLOW.value,
                "risk_score": 0,
                "explanation": f"[{self.config.mode.value.upper()}] No injection indicators detected. Input is allowed.",
            }

        high_findings: List[Any] = []
        medium_findings: List[Any] = []
        low_findings: List[Any] = []

        for f in findings:
            sev = self._extract_field(f, "severity")
            if sev == FindingSeverity.HIGH.value:
                high_findings.append(f)
            elif sev == FindingSeverity.MEDIUM.value:
                medium_findings.append(f)
            else:
                low_findings.append(f)

        # 1. Serious high-severity findings (immediate block across all modes)
        serious_high = [
            f
            for f in high_findings
            if self._extract_field(f, "category") in self.config.block_categories
        ]

        # 2. Instruction override high-severity findings
        override_high = [
            f
            for f in high_findings
            if self._extract_field(f, "category") == FindingCategory.INSTRUCTION_OVERRIDE.value
        ]

        # 3. Medium-severity in serious categories
        serious_medium = [
            f
            for f in medium_findings
            if self._extract_field(f, "category") in self.config.block_categories
        ]

        if serious_high:
            matched_cats = sorted({self._extract_field(f, "category") for f in serious_high})
            decision = Decision.BLOCK
            explanation = (
                f"[{self.config.mode.value.upper()}] Blocked: High-severity indicator detected in serious attack category "
                f"({', '.join(matched_cats)}). Immediate containment enforced."
            )
        elif override_high:
            serious_secondary = [
                f for f in findings if self._extract_field(f, "category") in self.config.block_categories
            ]
            has_multiple_high = len(high_findings) > 1

            # Strict mode blocks isolated overrides; balanced blocks if secondary evidence exists
            if self.config.block_isolated_override or serious_secondary or has_multiple_high:
                decision = Decision.BLOCK
                reason = (
                    "isolated override blocked under strict policy"
                    if self.config.block_isolated_override and not (serious_secondary or has_multiple_high)
                    else "high-severity override detected alongside secondary attack evidence"
                )
                explanation = f"[{self.config.mode.value.upper()}] Blocked: {reason}."
            else:
                decision = Decision.REVIEW
                explanation = (
                    f"[{self.config.mode.value.upper()}] Review required: High-severity instruction override detected without "
                    "secondary exploitation indicators. Manual inspection recommended."
                )
        elif self.config.block_medium_serious and serious_medium:
            # Strict mode blocks medium-severity serious threats
            matched_cats = sorted({self._extract_field(f, "category") for f in serious_medium})
            decision = Decision.BLOCK
            explanation = (
                f"[{self.config.mode.value.upper()}] Blocked: Medium-severity finding in serious category "
                f"({', '.join(matched_cats)}) blocked under zero-trust strict policy."
            )
        elif medium_findings:
            decision = Decision.REVIEW
            explanation = (
                f"[{self.config.mode.value.upper()}] Review required: Detected {len(findings)} indicator(s) "
                "with maximum severity 'medium'. Verification recommended."
            )
        elif low_findings:
            if self.config.allow_low_severity:
                # Permissive mode permits low-severity indicators
                decision = Decision.ALLOW
                explanation = (
                    f"[{self.config.mode.value.upper()}] Allowed: Low-severity indicator detected but permitted "
                    "under permissive policy profile."
                )
            else:
                decision = Decision.REVIEW
                explanation = (
                    f"[{self.config.mode.value.upper()}] Review required: Low-severity indicator detected. "
                    "Verification recommended."
                )
        else:
            decision = Decision.ALLOW
            explanation = f"[{self.config.mode.value.upper()}] Input evaluated without actionable policy violations."

        risk_score = self.calculate_risk_score(findings, decision)

        return {
            "decision": decision.value,
            "risk_score": risk_score,
            "explanation": f"{explanation} Risk score: {risk_score}/100 (deterministic heuristic).",
        }


def evaluate_policy(
    findings: List[Any],
    mode: Optional[Union[PolicyMode, str]] = None,
    config: Optional[PolicyConfig] = None,
) -> Dict[str, Any]:
    """Convenience function evaluating findings using the specified policy mode or config.

    Args:
        findings: List of finding dicts or Finding model instances.
        mode: Optional PolicyMode string or enum ('permissive', 'balanced', 'strict').
        config: Optional custom PolicyConfig instance.

    Returns:
        Dict with keys 'decision', 'risk_score', and 'explanation'.
    """
    engine = PolicyEngine(config=config, mode=mode)
    return engine.evaluate(findings)
