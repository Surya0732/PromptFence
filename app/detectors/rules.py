"""Rule-based prompt-injection detector for PromptFence.

This module implements deterministic, pattern-matching detection for four
categories of potential prompt-injection indicators:

1. **instruction_override** — attempts to override, ignore, or replace
   the system prompt or safety instructions.
2. **secret_extraction** — attempts to reveal system prompts, credentials,
   API keys, passwords, or other protected information.
3. **data_exfiltration** — attempts to send, disclose, or transfer private
   information to an unauthorized destination.
4. **unauthorized_tool_use** — attempts to invoke tools, execute commands,
   or access resources without proper authorization.

Limitations
-----------
- Pattern-based detection can never guarantee identification of every attack.
  Sophisticated adversaries can rephrase prompts to evade static rules.
- These rules are designed as a *baseline* layer. A future model-assisted
  detector (Phase 2) will improve recall and precision.
- The rules aim to minimise false positives on legitimate security-education
  content and code examples, but some edge cases may still be flagged.
- A keyword match alone is NOT treated as conclusive proof of an attack;
  rules look for *imperative phrasing* and *contextual markers* that
  suggest malicious intent rather than mere discussion.
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    """Return a lowercased, whitespace-collapsed copy for matching.

    The original text is preserved in findings as evidence.
    """
    return re.sub(r"\s+", " ", text.lower().strip())


def _extract_evidence(text: str, match_start: int, match_end: int,
                      context_chars: int = 80) -> str:
    """Extract a short excerpt around a match position.

    The excerpt is capped to avoid leaking large amounts of user input.
    """
    start = max(0, match_start - context_chars // 4)
    end = min(len(text), match_end + context_chars)
    excerpt = text[start:end].strip()
    if len(excerpt) > 120:
        excerpt = excerpt[:120] + "…"
    return excerpt


def _make_finding(category: str, severity: str, evidence: str,
                  matched_indicator: str) -> dict[str, Any]:
    """Build a finding dict with the required fields."""
    return {
        "detector": "rules",
        "category": category,
        "severity": severity,
        "evidence": evidence,
        "matched_indicator": matched_indicator,
    }


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------
# Each pattern is a tuple of (compiled_regex, severity, indicator_description).
# Patterns are designed to match imperative/instructional phrasing rather than
# mere mentions of security concepts.  This reduces false positives on
# educational or research text.
#
# IMPORTANT: Regex patterns use word boundaries (\b) and contextual anchors
# to avoid matching inside unrelated words.  They are applied to the
# *normalized* (lowercased, whitespace-collapsed) text.

_INSTRUCTION_OVERRIDE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # Direct instruction to ignore previous prompts / instructions
    (
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass|skip|suppress|abandon)"
            r"\s+(?:all\s+|your\s+|any\s+|the\s+)*(?:previous|prior|above|earlier|existing|original|old|initial)"
            r"\s+(?:instructions?|prompts?|rules?|guidelines?|constraints?|directives?|context)",
            re.IGNORECASE,
        ),
        "high",
        "Imperative phrase directing the model to ignore prior instructions.",
    ),
    # Adversarial / jailbreak persona reassignment
    (
        re.compile(
            r"\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|switch\s+to\s+(?:a\s+)?new\s+persona\s+named)\s+"
            r"(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|chaosgpt|dan\b)",
            re.IGNORECASE,
        ),
        "high",
        "Imperative directive to adopt an unrestricted, jailbroken, or adversarial persona.",
    ),
    # "You are now …" / "Act as …" role reassignment
    (
        re.compile(
            r"\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as\s+if\s+you\s+(?:are|were)|"
            r"pretend\s+(?:you\s+are|to\s+be)|roleplay\s+as|switch\s+to\s+(?:a\s+)?new\s+(?:role|persona|mode))",
            re.IGNORECASE,
        ),
        "medium",
        "Attempt to reassign the model's role or persona.",
    ),
    # "New instructions:" / "System prompt:" override
    (
        re.compile(
            r"(?:^|\n)\s*(?:new\s+(?:system\s+)?instructions?|updated?\s+(?:system\s+)?prompt|"
            r"replacement\s+(?:system\s+)?prompt|override\s+prompt)\s*[:\-]",
            re.IGNORECASE,
        ),
        "high",
        "Header-style marker introducing replacement instructions.",
    ),
    # Jailbreak-style: "DAN", "Developer Mode", etc.
    (
        re.compile(
            r"\b(?:enable\s+(?:developer|dev|debug|god|jailbreak|unrestricted)\s+mode|"
            r"activate\s+(?:dan|developer|unrestricted)\s+mode|"
            r"entering\s+(?:developer|unrestricted|unfiltered)\s+mode)\b",
            re.IGNORECASE,
        ),
        "high",
        "Jailbreak-style mode activation phrase.",
    ),
    # "Do not follow your rules / safety guidelines"
    (
        re.compile(
            r"\b(?:do\s+not|don'?t|never)\s+follow\s+(?:your|the|any)\s+"
            r"(?:rules?|guidelines?|safety|restrictions?|policies|instructions?)\b",
            re.IGNORECASE,
        ),
        "medium",
        "Instruction to disregard safety rules or guidelines.",
    ),
]

_SECRET_EXTRACTION_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # "Reveal / show / output your system prompt"
    (
        re.compile(
            r"\b(?:reveal|show|display|output|print|repeat|echo|recite|leak|expose|disclose|dump|share)"
            r"\s+(?:me\s+)?(?:your\s+)?(?:full\s+|complete\s+|entire\s+|original\s+)?"
            r"(?:system\s+prompt|system\s+message|initial\s+prompt|hidden\s+(?:prompt|instructions?)|"
            r"internal\s+instructions?|secret\s+instructions?|confidential\s+instructions?)\b",
            re.IGNORECASE,
        ),
        "high",
        "Request to reveal the system prompt or internal instructions.",
    ),
    # "What is / tell me / show me your system prompt"
    (
        re.compile(
            r"\b(?:what\s+(?:is|are)|tell\s+me|give\s+me|show\s+me|list|provide)"
            r"\s+(?:your\s+)?(?:full\s+|complete\s+|entire\s+|original\s+)?"
            r"(?:system\s+prompt|system\s+message|initial\s+instructions?|hidden\s+instructions?|"
            r"api\s+keys?|secret\s+keys?|credentials?|passwords?|tokens?|private\s+keys?)\b",
            re.IGNORECASE,
        ),
        "high",
        "Direct question attempting to extract secrets or system prompt.",
    ),
    # Asking to include API keys / passwords in the response
    (
        re.compile(
            r"\b(?:include|embed|insert|put|place|add)\s+(?:the\s+|your\s+|any\s+)?"
            r"(?:api\s+keys?|secret\s+keys?|credentials?|passwords?|tokens?|private\s+keys?)"
            r"\s+(?:in|into|within|inside)\s+(?:your\s+)?(?:response|output|reply|answer|message)\b",
            re.IGNORECASE,
        ),
        "high",
        "Request to embed secrets in the model's output.",
    ),
    # "Repeat everything above" — common extraction technique
    (
        re.compile(
            r"\b(?:repeat|copy|reproduce|echo)\s+(?:everything|all\s+(?:text|content))"
            r"\s+(?:above|before|preceding|from\s+the\s+(?:start|beginning))\b",
            re.IGNORECASE,
        ),
        "medium",
        "Request to repeat earlier content, which may include system prompt text.",
    ),
]

_DATA_EXFILTRATION_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # "Send / post / transmit data to <URL>"
    (
        re.compile(
            r"\b(?:send|post|transmit|upload|forward|exfiltrate|transfer|submit|deliver)"
            r"\s+(?:(?:all|the|this|that|any|user|private|sensitive|confidential|session|customer)\s+)*"
            r"(?:data|information|content|results?|details?|records?|files?|logs?|tokens?|credentials?)"
            r"\s+(?:to|via|through|using)\s+"
            r"(?:https?://|ftp://)",
            re.IGNORECASE,
        ),
        "high",
        "Instruction to send data to an external URL.",
    ),
    # Exfiltrate sensitive data to an external server/endpoint/webhook
    (
        re.compile(
            r"\b(?:send|post|transmit|upload|forward|exfiltrate|transfer|submit|deliver)"
            r"\s+(?:(?:all\s+|the\s+|this\s+|any\s+)?(?:user|private|sensitive|confidential|session|customer|internal|secret)\s+)"
            r"(?:data|information|content|results?|details?|records?|files?|logs?|tokens?|credentials?)"
            r"\s+(?:to|via|through|using)\s+"
            r"an?\s+(?:external|remote|third.party)\s+(?:server|endpoint|url|api|service|webhook)",
            re.IGNORECASE,
        ),
        "high",
        "Instruction to transmit sensitive or user data to an external destination.",
    ),
    # Explicit exfiltration verbs (exfiltrate, exfiltration) targeting remote endpoints
    (
        re.compile(
            r"\b(?:exfiltrate|exfiltrating|exfiltration)\s+.*?"
            r"\b(?:to|via|through|using|endpoint|server|url|webhook)\b",
            re.IGNORECASE,
        ),
        "high",
        "Explicit exfiltration instruction targeting an external destination.",
    ),
    # Markdown image / link exfiltration — ![](http://evil.com/img?data=...)
    (
        re.compile(
            r"!\[.*?\]\(\s*https?://.*?\?.*?(?:data|secret|key|token|password|prompt)\s*=",
            re.IGNORECASE,
        ),
        "high",
        "Markdown image/link with query parameter exfiltration pattern.",
    ),
    # "Encode and send" / "base64 encode ... then send"
    (
        re.compile(
            r"\b(?:base64|hex|url)\s*(?:encode|encrypt)\b.*?"
            r"\b(?:send|post|transmit|upload|forward|transfer)\b",
            re.IGNORECASE,
        ),
        "medium",
        "Instruction to encode data before sending, suggesting covert exfiltration.",
    ),
    # "Write data to <external URL / webhook>"
    (
        re.compile(
            r"\b(?:write|append|log|store|save)\s+(?:(?:all|the|this|user|private|sensitive)\s+)?"
            r"(?:data|information|content|input|conversation)\s+(?:to|into)\s+"
            r"(?:https?://|an?\s+(?:external|remote|third.party))",
            re.IGNORECASE,
        ),
        "medium",
        "Instruction to write data to an external location.",
    ),
    # Asking to include private data in a URL
    (
        re.compile(
            r"\b(?:include|embed|append|add|put)\s+(?:(?:the|user|private|sensitive|secret)\s+)*"
            r"(?:data|info|information|password|key|token|credential)\s+"
            r"(?:in|into|as\s+part\s+of)\s+(?:a\s+|the\s+)?(?:url|link|query\s+(?:string|parameter))\b",
            re.IGNORECASE,
        ),
        "high",
        "Request to embed sensitive data in a URL or query parameter.",
    ),
]

_UNAUTHORIZED_TOOL_USE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # "Execute / run <shell command>"
    (
        re.compile(
            r"\b(?:execute|run|invoke|call|launch|start|spawn|perform)\s+"
            r"(?:the\s+|this\s+|a\s+)?(?:following\s+)?"
            r"(?:shell\s+command|terminal\s+command|system\s+command|bash\s+command|"
            r"powershell\s+command|cmd\s+command|os\s+command|command\s+line)\b",
            re.IGNORECASE,
        ),
        "high",
        "Instruction to execute a shell or system command.",
    ),
    # "Use os.system / subprocess / exec / eval"
    (
        re.compile(
            r"\b(?:use|call|invoke|run|execute)\s+"
            r"(?:os\.system|subprocess|exec|eval|__import__|importlib|"
            r"os\.popen|os\.exec[a-z]*|shutil\.rmtree)\b",
            re.IGNORECASE,
        ),
        "high",
        "Instruction to use dangerous Python functions for code execution.",
    ),
    # "Access / read / write / delete <filesystem path>"
    (
        re.compile(
            r"\b(?:access|read|write|delete|remove|modify|overwrite|create)\s+"
            r"(?:the\s+|a\s+)?(?:file|directory|folder|path)\s+"
            r"(?:at\s+|named?\s+|located\s+at\s+)?(?:[a-zA-Z]:\\|/(?:etc|var|home|tmp|usr|root|windows|system))\b",
            re.IGNORECASE,
        ),
        "high",
        "Instruction to access, modify, or delete filesystem paths.",
    ),
    # "Send an email / make an HTTP request / open a socket"
    (
        re.compile(
            r"\b(?:send\s+an?\s+email|make\s+(?:an?\s+)?(?:http|api|network)\s+(?:request|call)|"
            r"open\s+(?:a\s+)?(?:socket|connection|port)|"
            r"connect\s+to\s+(?:a\s+)?(?:database|server|remote))\b",
            re.IGNORECASE,
        ),
        "medium",
        "Instruction to initiate external network activity.",
    ),
    # "Install <package> / pip install / npm install"
    # Matches imperative commands to install packages or execute package managers.
    (
        re.compile(
            r"\b(?:install|download\s+and\s+install)\s+"
            r"(?:(?:an?|the)\s+)?(?:[a-zA-Z0-9_\-'\"]+\s+)*(?:package|module|library|dependency)\b.*?\b(?:using|with|via)\s+(?:pip|npm|apt|yum|brew|choco)\b|"
            r"\b(?:pip|npm|apt|yum|brew|choco)\s+install\b|"
            r"\b(?:run|execute)\s+(?:pip|npm|apt|yum|brew|choco)\s+install\b|"
            r"\b(?:install|setup)\s+(?:(?:an?|the)\s+)?(?:[a-zA-Z0-9_\-'\"]+\s+)*(?:unverified|third-party|untrusted|malicious)\b.*?\bpackage\b",
            re.IGNORECASE,
        ),
        "high",
        "Instruction to install packages or execute package managers.",
    ),
]


# ---------------------------------------------------------------------------
# Main detection function
# ---------------------------------------------------------------------------

def detect_with_rules(text: str) -> list[dict[str, Any]]:
    """Scan *text* for potential prompt-injection indicators using rules.

    Parameters
    ----------
    text:
        The untrusted input to analyse.  This text is treated as **data**
        and is never executed.

    Returns
    -------
    list[dict]:
        A list of finding dicts.  Each contains the keys ``detector``,
        ``category``, ``severity``, ``evidence``, and ``matched_indicator``.
        An empty list means no indicators were detected (which does **not**
        guarantee the input is safe — rule-based detection has inherent
        limitations).

    Notes
    -----
    - The function normalises text for matching but preserves the original
      wording in the ``evidence`` field.
    - Duplicate findings (same category + same indicator description) are
      suppressed.
    - Very long inputs are safely handled; the function does not attempt to
      store or log the full input.
    """
    if not text or not text.strip():
        return []

    # Normalize for pattern matching; keep original for evidence extraction.
    normalized = _normalize(text)

    # Collect all pattern groups with their categories.
    _pattern_groups: list[tuple[str, list[tuple[re.Pattern[str], str, str]]]] = [
        ("instruction_override", _INSTRUCTION_OVERRIDE_PATTERNS),
        ("secret_extraction", _SECRET_EXTRACTION_PATTERNS),
        ("data_exfiltration", _DATA_EXFILTRATION_PATTERNS),
        ("unauthorized_tool_use", _UNAUTHORIZED_TOOL_USE_PATTERNS),
    ]

    findings: list[dict[str, Any]] = []
    # Track (category, indicator_description) to avoid duplicates.
    seen: set[tuple[str, str]] = set()

    for category, patterns in _pattern_groups:
        for pattern, severity, indicator_desc in patterns:
            match = pattern.search(normalized)
            if match is None:
                continue

            dedup_key = (category, indicator_desc)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            evidence = _extract_evidence(
                text, match.start(), match.end()
            )

            findings.append(
                _make_finding(
                    category=category,
                    severity=severity,
                    evidence=evidence,
                    matched_indicator=indicator_desc,
                )
            )

    return findings
