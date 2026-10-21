"""LM Studio target adapter.

Speaks the OpenAI-compatible ``/chat/completions`` API that LM Studio exposes,
so the same adapter works against any compatible local server. Every failure is
surfaced as ``TargetUnavailable`` with a message the API layer can turn into a
503 instead of leaking a stack trace.
"""

import time
from typing import Optional

import requests

from .base import Observation, TargetConfig, TargetUnavailable

DEFAULT_TIMEOUT = 15
MAX_RESPONSE_CHARS = 20_000


class LMStudioTarget:
    """A chat-completions target backed by LM Studio."""

    def __init__(
        self,
        config: TargetConfig,
        base_url: str,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        session: Optional[requests.Session] = None,
    ):
        self.config = config
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = session or requests.Session()

    def send(self, prompt: str, *, temperature: float = 0.0) -> Observation:
        """Send one payload and return the target's response."""
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": self.config.system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "stream": False,
        }

        started = time.perf_counter()
        try:
            response = self._session.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout as exc:
            raise TargetUnavailable(
                f"Target did not respond within {self.timeout}s."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise TargetUnavailable(
                f"Target is unreachable at {self.base_url}: "
                f"{exc.__class__.__name__}."
            ) from exc

        latency_ms = int((time.perf_counter() - started) * 1000)

        if response.status_code >= 400:
            raise TargetUnavailable(
                f"Target returned HTTP {response.status_code} for model "
                f"{self.config.model!r}."
            )

        try:
            data = response.json()
            text = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise TargetUnavailable(
                "Target returned a response the scanner could not parse."
            ) from exc

        if not isinstance(text, str):
            raise TargetUnavailable("Target returned a non-text response.")

        return Observation(
            prompt=prompt,
            response=text[:MAX_RESPONSE_CHARS],
            latency_ms=latency_ms,
            model=self.config.model,
        )

    def is_available(self, *, timeout: float = 1.5) -> bool:
        """Cheap reachability probe used by the health endpoint."""
        try:
            response = self._session.get(f"{self.base_url}/models", timeout=timeout)
        except requests.exceptions.RequestException:
            return False
        return response.status_code < 400
