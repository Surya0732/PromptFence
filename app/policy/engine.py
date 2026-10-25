"""Policy engine for PromptFence.

The policy engine is deliberately **independent** of detector implementations.
It receives a list of findings (from any detector or merger) along with
optional detector status information, and returns a deterministic risk
assessment with a decision.

Scoring rules
-------------
- No findings and all detectors healthy → ``allow``, risk score 0.
- Each finding adds points based on severity and category.
- ``instruction_override`` alone is capped at ``review`` (never blocks alone) to
  reduce false positives on benign role-play or system prompt discussions.
- Multi-category bonus (+10) is applied when findings span distinct attack categories,
  suggesting coordinated or multi-vector manipulation.
- Contextual discounts are applied by the policy engine when evidence reflects benign
  task parameters (e.g. email drafts, calendar invites, flight filters) rather than
  system instructions or safety constraints.
- Unverified model evidence and low-confidence findings are discounted.
- Final score is clamped to [0, 100].

Decision thresholds
-------------------
    0–24  → ``allow``
   25–59  → ``review``
   60–100 → ``block`` (capped at ``review`` if only instruction_override is present)

Degraded operation / Failure handling
-------------------------------------
- Detector failure is **never** interpreted as proof of safety.
- When an active detector reports ``unavailable`` or ``invalid_response``:
  - If rule findings or remaining evidence already warrant ``block`` or ``review``,
    that decision is preserved.
  - If no findings were detected (which would normally produce ``allow``), the policy
    engine escalates the decision to ``review`` (risk score at least 25) with a clear
    degraded-scan explanation.
  - Requests are not blocked indiscriminately solely due to model unavailability.

Limitations
-----------
- Scoring is heuristic and deterministic; it does not guarantee detection of novel,
  obfuscated, or multi-turn attacks.
- Confidence scores from models are uncalibrated and are not used as true probabilities.
- Human review is recommended whenever the engine returns ``review`` or operates in a degraded state.
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Severity → base score mapping
# ---------------------------------------------------------------------------

_SEVERITY_SCORES: dict[str, int] = {
    "low": 10,
    "medium": 20,
    "high": 35,
}

# ---------------------------------------------------------------------------
# Category modifiers
# ---------------------------------------------------------------------------

_CATEGORY_WEIGHT: dict[str, float] = {
    "instruction_override": 0.75,
    "secret_extraction": 1.0,
    "data_exfiltration": 1.0,
    "unauthorized_tool_use": 1.0,
}

_MULTI_CATEGORY_BONUS: int = 10

# ---------------------------------------------------------------------------
# Decision thresholds
# ---------------------------------------------------------------------------

_REVIEW_THRESHOLD: int = 25
_BLOCK_THRESHOLD: int = 60


# ---------------------------------------------------------------------------
# Contextual evaluation helpers
# ---------------------------------------------------------------------------

_ADVERSARIAL_TARGETS_PATTERN = re.compile(
    r"\b(?:instructions?|prompts?|rules?|guidelines?|safety|policies|policy|"
    r"constraints?|directives?|unfiltered|unrestricted|jailbreak|developer\s+mode|"
    r"dan|persona|bypass|system\s+message)\b",
    re.IGNORECASE,
)

_TASK_ARTIFACTS_PATTERN = re.compile(
    r"\b(?:drafts?|emails?|calendar(?:\s+invites?|\s+events?)?|meetings?|appointments?|"
    r"schedules?|flights?(?:\s+search)?|hotel|bookings?|search\s+(?:parameters?|filters?)|"
    r"query\s+parameters?)\b",
    re.IGNORECASE,
)


def _is_benign_task_context(category: str, evidence: str, indicator: str) -> bool:
    """Determine whether an override finding references benign task parameters rather than AI rules.

    Returns True ONLY if:
    1. The category is instruction_override.
    2. The evidence/indicator explicitly targets user task artifacts (drafts, calendar, flights).
    3. The evidence/indicator does NOT contain any adversarial targets (prompts, rules, safety).
    """
    if category != "instruction_override":
        return False

    combined = f"{evidence} {indicator}"

    # If it mentions any AI safety or prompt target, it is an attack (do not suppress)
    if _ADVERSARIAL_TARGETS_PATTERN.search(combined):
        return False

    # If it references user task artifacts and no adversarial targets, it is benign task management
    if _TASK_ARTIFACTS_PATTERN.search(combined):
        return True

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_policy(
    findings: list[dict[str, Any]],
    *,
    detector_statuses: list[dict[str, Any] | Any] | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
    """Evaluate detector findings and health status to produce a policy decision.

    Parameters
    ----------
    findings:
        List of finding dicts from one or more detectors. Each finding must
        contain at least ``category`` and ``severity``.
    detector_statuses:
        Optional list of detector status objects or dicts (e.g. from
        ``DetectorStatus``).
    mode:
        Optional scan mode identifier (``"rules_only"``, ``"llm_only"``, ``"hybrid"``).

    Returns
    -------
    dict:
        A dict with keys:
        - ``risk_score`` (int, 0–100)
        - ``decision`` (``"allow"`` | ``"review"`` | ``"block"``)
        - ``reasons`` (list[str])
    """
    reasons: list[str] = []
    raw_score: float = 0.0
    categories_seen: set[str] = set()

    # --- 1. Evaluate Findings ---
    if findings:
        for finding in findings:
            category = finding.get("category", "unknown")
            severity = finding.get("severity", "low")
            indicator = finding.get("matched_indicator", "unknown pattern")
            evidence = finding.get("evidence", "")
            confidence = finding.get("confidence")
            evidence_verified = finding.get("evidence_verified")
            detector = finding.get("detector", "")

            base = _SEVERITY_SCORES.get(severity, 10)
            weight = _CATEGORY_WEIGHT.get(category, 1.0)

            # Check contextual benign task management (Task 4)
            if _is_benign_task_context(category, evidence, indicator):
                weight = 0.0
                reasons.append(
                    f"[CONTEXT DISCOUNT] {category}: Evidence targets task parameters "
                    f"('{evidence[:40]}…') rather than system instructions or safety constraints; discounted."
                )
            else:
                # Evidence verification discount (Task 5)
                if evidence_verified is False:
                    weight *= 0.5
                    reasons.append(
                        f"[UNVERIFIED EVIDENCE] {category}: Model evidence was not found in input; "
                        "risk contribution discounted."
                    )

                # Low model confidence discount (Task 5)
                if confidence is not None and confidence < 0.6:
                    weight *= 0.7
                    reasons.append(
                        f"[LOW CONFIDENCE] {category}: Model reported low confidence ({confidence:.2f}); "
                        "risk contribution discounted."
                    )

                # Note multi-detector concurrence
                if "rules,llm" in detector:
                    reasons.append(
                        f"[CONFIRMED] {category}: Concurrence between deterministic rules and model detector."
                    )

            contribution = base * weight
            raw_score += contribution

            if contribution > 0:
                categories_seen.add(category)
                reasons.append(f"[{severity.upper()}] {category}: {indicator}")

        # Multi-category bonus
        if len(categories_seen) > 1:
            raw_score += _MULTI_CATEGORY_BONUS
            reasons.append(
                f"Multiple indicator categories detected ({len(categories_seen)}); "
                "risk score increased."
            )
    else:
        reasons.append("No indicators detected.")

    # Special handling: instruction_override alone caps at review to avoid false-positive blocks
    only_override = bool(categories_seen and categories_seen == {"instruction_override"})

    risk_score = max(0, min(100, int(round(raw_score))))

    # Base decision from evidence (clean thresholds)
    if risk_score >= _BLOCK_THRESHOLD:
        decision = "review" if only_override else "block"
    elif risk_score >= _REVIEW_THRESHOLD:
        decision = "review"
    else:
        decision = "allow"

    if decision == "allow" and findings:
        reasons.append(
            "Risk score is below the review threshold; allowing with caution."
        )

    # --- 2. Check Detector Health & Handle Failures ---
    has_detector_failure = False
    if detector_statuses:
        for ds in detector_statuses:
            status_val = (
                getattr(ds, "status", None)
                or (ds.get("status") if isinstance(ds, dict) else None)
                or "ok"
            )
            name_val = (
                getattr(ds, "name", None)
                or (ds.get("name") if isinstance(ds, dict) else None)
                or "detector"
            )
            err_val = (
                getattr(ds, "error", None)
                or (ds.get("error") if isinstance(ds, dict) else None)
            )

            if status_val in ("unavailable", "invalid_response", "timeout", "error"):
                has_detector_failure = True
                err_suffix = f": {err_val}" if err_val else ""
                reasons.append(
                    f"Detector '{name_val}' failed ({status_val}{err_suffix}). "
                    "Scan operated in degraded mode."
                )

    # Detector failure must never be mistaken for proof of safety!
    if has_detector_failure:
        if decision == "allow":
            decision = "review"
            risk_score = max(risk_score, _REVIEW_THRESHOLD)
            reasons.append(
                "Degraded scan: one or more detectors failed; input cannot be confirmed safe. "
                "Escalating to review."
            )
        else:
            reasons.append(
                f"Degraded scan noted; existing findings justified decision '{decision}'."
            )

    return {
        "risk_score": risk_score,
        "decision": decision,
        "reasons": reasons,
    }
