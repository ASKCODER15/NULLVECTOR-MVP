"""Target adapters: the systems a scan executes test cases against.

A target turns a payload into an Observation. Everything else in the scanner
works on Observations, so new target types can be added without touching the
evaluators or the reporting layer (docs/PROJECT_CONTEXT.md §5).
"""

from .base import (
    Observation,
    TargetConfig,
    TargetUnavailable,
    build_target_config,
    load_target_profile,
)

__all__ = [
    "Observation",
    "TargetConfig",
    "TargetUnavailable",
    "build_target_config",
    "load_target_profile",
]
