"""Normalized security finding (docs/PROJECT_CONTEXT.md §6).

A Finding is the final output of a scanner run. Every finding answers: what
was tested, what was expected, what actually happened, the evidence, severity,
confidence, and how to fix it.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Finding:
    test_id: str
    category: str
    status: str
    severity: str
    confidence: str
    summary: str
    evidence: str
    recommendation: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self):
        return {
            "test_id": self.test_id,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "summary": self.summary,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
        }


def make_finding(
    *,
    test_id: str,
    category: str,
    status: str,
    severity: str,
    confidence: str,
    summary: str,
    evidence: str,
    recommendation: str,
) -> dict:
    """Build a normalized finding dict.

    Every scanner module goes through this constructor so the serialized shape
    cannot drift between modules.
    """
    return Finding(
        test_id=test_id,
        category=category,
        status=status,
        severity=severity,
        confidence=confidence,
        summary=summary,
        evidence=evidence,
        recommendation=recommendation,
    ).to_dict()