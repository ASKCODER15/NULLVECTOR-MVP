import requests
from app.core.config import settings

# A chat answer can legitimately take longer than a scan's per-call budget.
REQUEST_TIMEOUT = 60


def ask_llm(prompt: str):
    payload = {
        "model": settings.LM_STUDIO_MODEL,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
        "temperature": 0.7,
    }

    response = requests.post(
        f"{settings.LM_STUDIO_URL}/chat/completions",
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    data = response.json()

    return data["choices"][0]["message"]["content"]
