import requests
from app.core.config import settings


def ask_llm(prompt: str):

    payload = {
        "model": "qwen/qwen3-8b",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.7
    }

    response = requests.post(
        f"{settings.LM_STUDIO_URL}/chat/completions",
        json=payload,
        timeout=120
    )

    response.raise_for_status()

    data = response.json()

    return data["choices"][0]["message"]["content"]