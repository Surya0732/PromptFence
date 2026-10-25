"""Finding merger for hybrid detection mode.

When both the rule-based and LLM detectors run on the same input, their
findings are merged deterministically:

1. Deduplicate findings with the same category and overlapping evidence or indicator.
2. Preserve all rule-based findings; never allow the model to erase or downgrade them.
3. Upgrade severity if the model reports higher severity on an equivalent finding.
4. Record multi-detector attribution (e.g. ``"rules,llm"``) on merged findings.
5. Append non-overlapping, independent LLM findings.
6. Do not simply stack duplicate findings to artificially inflate risk scores.

Limitations
-----------
- Equivalence matching relies on category matching and normalized evidence overlap.
- Separate indicators within the same category on distinct text spans are preserved as independent.
"""

from __future__ import annotations

import re
from typing import Any, Iterable


# Severity ordering for comparison.
_SEVERITY_RANK: dict[str, int] = {"low": 1, "medium": 2, "high": 3}


def _normalize_evidence(text: str) -> str:
    """Normalize evidence string for overlap comparison."""
    cleaned = text.lower().strip()
    cleaned = re.sub(r'[\'"`“”‘’«»]+', "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned


def _are_equivalent(rule_f: dict[str, Any], llm_f: dict[str, Any]) -> bool:
    """Determine whether two findings represent the same underlying indicator.

    Two findings are considered equivalent if:
    1. They share the same category, AND
    2. Either their evidence excerpts overlap, or their indicator descriptions
       refer to the same pattern.
    """
    if rule_f.get("category") != llm_f.get("category"):
        return False

    rule_ev = _normalize_evidence(rule_f.get("evidence", ""))
    llm_ev = _normalize_evidence(llm_f.get("evidence", ""))

    # If evidence is substantially overlapping (one contains the other)
    if rule_ev and llm_ev:
        if rule_ev in llm_ev or llm_ev in rule_ev:
            return True

    # If indicators match on category and indicator prefix
    rule_ind = rule_f.get("matched_indicator", "").lower().strip()[:40]
    llm_ind = llm_f.get("matched_indicator", "").lower().strip()[:40]
    if rule_ind and llm_ind and rule_ind == llm_ind:
        return True

    return False


def merge_findings(
    rule_findings: Iterable[dict[str, Any]],
    llm_findings: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge rule-based and LLM findings deterministically.

    Parameters
    ----------
    rule_findings:
        Findings from the deterministic rule detector.
    llm_findings:
        Findings from the LLM detector (or an ``LLMDetectorResult``).

    Returns
    -------
    list[dict]:
        Merged findings. Rule findings are always preserved. Overlapping
        LLM findings upgrade severity if higher, and non-overlapping
        LLM findings are appended.
    """
    # Start with a shallow copy of rule findings so original lists are never mutated.
    merged: list[dict[str, Any]] = [dict(f) for f in rule_findings]

    for llm_f in llm_findings:
        llm_item = dict(llm_f)
        matched_existing = False

        for existing in merged:
            if _are_equivalent(existing, llm_item):
                matched_existing = True
                # Upgrade severity if LLM reports higher
                new_rank = _SEVERITY_RANK.get(llm_item.get("severity", "low"), 1)
                old_rank = _SEVERITY_RANK.get(existing.get("severity", "low"), 1)
                if new_rank > old_rank:
                    existing["severity"] = llm_item["severity"]

                # Mark multi-detector attribution
                curr_det = existing.get("detector", "rules")
                if "llm" not in curr_det:
                    existing["detector"] = f"{curr_det},llm"

                # Attach uncalibrated confidence if reported
                if "confidence" in llm_item and llm_item["confidence"] is not None:
                    existing["confidence"] = llm_item["confidence"]

                break

        if not matched_existing:
            # Independent finding from LLM
            merged.append(llm_item)

    return merged
