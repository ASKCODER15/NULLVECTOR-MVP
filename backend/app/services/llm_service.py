import requests

LM_STUDIO_URL = "http://127.0.0.1:1234/v1/chat/completions"

MODEL = "qwen/qwen3-8b"


def ask_llm(prompt: str):
    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
        "temperature": 0.3,
        "max_tokens": 512,
    }

    response = requests.post(
        LM_STUDIO_URL,
        json=payload,
        timeout=120,
    )

    response.raise_for_status()

    data = response.json()

    return data["choices"][0]["message"]["content"]