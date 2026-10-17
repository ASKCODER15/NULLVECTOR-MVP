"""Prompt-Injection evaluator.

Turns the raw engine observation (a ScanResult) into the evidence-based
payload used by the backend /scan endpoint. Matches the response contract in
backend/app/main.py (ScanResult model):
text, is_prompt_injection, risk_level, reason, recommended_action.
"""

from ..engine.scanner import load_rules, scan
from ..scoring.levels import severity

ACTION_REJECT_LEVELS = ("HIGH", "CRITICAL")
CLEAN_LEVELS = ("SAFE", "LOW")
MAX_REASONS = 3


def evaluate(text: str, rules=None) -> dict:
    result = scan(text, rules)

    reasons = [f"{d.match!r}" for d in result.detections[:MAX_REASONS]]
    if not reasons:
        reason = "No suspicious patterns found."
    else:
        reason = "; ".join(reasons)
        extra = len(result.detections) - len(reasons)
        if extra > 0:
            reason += f"; +{extra} more"

    return {
        "text": text,
        "is_prompt_injection": result.level not in CLEAN_LEVELS,
        "risk_level": severity(result.level),
        "reason": reason,
        "recommended_action": "reject" if result.level in ACTION_REJECT_LEVELS else "allow",
    }


def load_default_rules():
    return load_rules()