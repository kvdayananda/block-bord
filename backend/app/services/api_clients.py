import os
import httpx
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

class GeminiClient:
    """Simple wrapper for Google Gemini text generation.
    Reads ``GEMINI_API_KEY`` from environment.
    """

    def __init__(self, model: str = "gemini-1.5-flash"):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not set in environment")
        self.base_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        self.headers = {"Content-Type": "application/json"}
        self.client = httpx.AsyncClient(timeout=30)
        self.model = model

    async def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> Dict[str, Any]:
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "temperature": temperature,
        }
        try:
            response = await self.client.post(
                f"{self.base_url}?key={self.api_key}", json=payload, headers=self.headers
            )
            response.raise_for_status()
            data = response.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError("Gemini returned no candidates")
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)
            return {"text": text, "raw": data}
        except httpx.HTTPError as exc:
            logger.error(f"Gemini request failed: {exc}")
            raise

class OpenAIClient:
    """Fallback wrapper for OpenAI chat completions.
    Reads ``OPENAI_API_KEY`` from environment.
    """

    def __init__(self, model: str = "gpt-4o-mini"):
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not set in environment")
        self.base_url = "https://api.openai.com/v1/chat/completions"
        self.headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        self.client = httpx.AsyncClient(timeout=30)
        self.model = model

    async def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
        }
        try:
            response = await self.client.post(self.base_url, json=payload, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError("OpenAI returned no choices")
            text = choices[0]["message"]["content"]
            return {"text": text, "raw": data}
        except httpx.HTTPError as exc:
            logger.error(f"OpenAI request failed: {exc}")
            raise
