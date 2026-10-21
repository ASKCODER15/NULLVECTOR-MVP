"""Severity / confidence derivation.

Severity and confidence are distinct (see docs/PROJECT_CONTEXT.md §6):

  severity    = how dangerous the vulnerability could be
  confidence  = how certain we are the test demonstrated the vulnerability
"""


SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

REVERSE_SEVERITY = {rank: name for name, rank in SEVERITY_RANK.items()}


def score_level(score: float) -> str:
    if score >= 0.9:
        return "CRITICAL"
    if score >= 0.6:
        return "HIGH"
    if score >= 0.3:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "SAFE"


def severity(level: str) -> str:
    """Map an internal risk level to a user-facing severity (low/medium/high)."""
    return {
        "SAFE": "low",
        "LOW": "low",
        "MEDIUM": "medium",
        "HIGH": "high",
        "CRITICAL": "high",
    }.get(level, "low")


def confidence(level: str) -> str:
    """How sure we are the observed behavior demonstrates the issue.

    NOTE: this maps a *detector* score, so it cannot express the difference
    between "we saw the canary in the response" (objective) and "the reply
    looked cooperative" (a judgement call). Response-side evaluators set
    confidence from the evidence class directly rather than calling this.
    """
    return {
        "SAFE": "low",
        "LOW": "low",
        "MEDIUM": "medium",
        "HIGH": "high",
        "CRITICAL": "high",
    }.get(level, "low")


def overall_risk(findings) -> str:
    """Highest severity across a finding set, or 'info' when empty."""
    findings = list(findings or [])
    if not findings:
        return "info"
    rank = max(SEVERITY_RANK.get(f.get("severity", "info"), 0) for f in findings)
    return REVERSE_SEVERITY[rank]