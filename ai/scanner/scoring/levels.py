"""Severity / confidence derivation.

Severity and confidence are distinct (see docs/PROJECT_CONTEXT.md §6):

  severity    = how dangerous the vulnerability could be
  confidence  = how certain we are the test demonstrated the vulnerability
"""


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
    """How sure we are the observed behavior demonstrates the issue."""
    return {
        "SAFE": "low",
        "LOW": "low",
        "MEDIUM": "medium",
        "HIGH": "high",
        "CRITICAL": "high",
    }.get(level, "low")