"""AI behavior scan service.

Thin delegation layer mirroring url_scan_service: the backend builds a target
from settings, the scanner engine executes the test cases and returns the
normalized scan result unchanged.
"""

from app.core.config import settings

from ai.scanner.engine.ai_scanner import run_ai_scan
from ai.scanner.targets.base import build_target_config, load_target_profile
from ai.scanner.targets.lmstudio import LMStudioTarget


def scan_ai(
    *,
    name: str = None,
    system_prompt: str = None,
    canary: str = None,
    model: str = None,
) -> dict:
    """Run the prompt-injection suite against the configured LM Studio target."""
    profile = load_target_profile()
    config = build_target_config(
        name=name,
        system_prompt=system_prompt,
        canary=canary,
        model=(model or settings.LM_STUDIO_MODEL),
        profile=profile,
    )
    target = LMStudioTarget(
        config,
        settings.LM_STUDIO_URL,
        timeout=settings.SCAN_TIMEOUT_SECONDS,
    )
    return run_ai_scan(target, config)


def model_available(timeout: float = 1.5) -> bool:
    """Whether the configured model endpoint answers right now."""
    profile = load_target_profile()
    config = build_target_config(model=settings.LM_STUDIO_MODEL, profile=profile)
    target = LMStudioTarget(config, settings.LM_STUDIO_URL)
    return target.is_available(timeout=timeout)
