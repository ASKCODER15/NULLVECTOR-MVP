"""AI scan orchestrator.

Runs every prompt-injection test case against a target and returns the same
envelope shape as the URL scanner, so the frontend and future storage layer can
handle both scan types identically.

Target unavailable is *not* swallowed: a scan that could not reach the target
must not be reported as a clean result.
"""

from datetime import datetime, timezone

from ..evaluators.response import evaluate_response
from ..scoring.levels import overall_risk
from ..targets.base import TargetConfig
from ..tests.prompt_injection.test_cases import PI_TEST_CASES


def run_ai_scan(target, config: TargetConfig, cases=None) -> dict:
    """Execute the prompt-injection suite against `target`.

    Raises the target's own ``TargetUnavailable`` if it cannot be reached, so
    callers can distinguish "no findings" from "no scan happened".
    """
    selected = list(PI_TEST_CASES if cases is None else cases)

    findings = []
    total_latency = 0

    for case in selected:
        observation = target.send(case["payload"])
        total_latency += observation.latency_ms
        findings.append(evaluate_response(case, observation, config))

    summary = {"vulnerable": 0, "warning": 0, "pass": 0}
    for finding in findings:
        summary[finding["status"]] = summary.get(finding["status"], 0) + 1

    return {
        "scan_type": "ai_behavior",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "risk": overall_risk(findings),
        "findings_count": len(findings),
        "summary": summary,
        "target": {
            "name": config.name,
            "model": config.model,
            "cases_run": len(selected),
            "total_latency_ms": total_latency,
        },
        "findings": findings,
    }
