from backend.app.config import settings

class GeminiBadRequestError(Exception):
    """Exception raised when Gemini API returns a 400 Bad Request.
    Carries the response body for debugging.
    """
    def __init__(self, message: str, status_code: int = 400, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body

import httpx
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

class GeminiClient:
    """Simple wrapper for Google Gemini text generation.
    Reads ``GEMINI_API_KEY`` from environment.
    """

    def __init__(self, model: str = "gemini-2.0-flash"):
        self.api_key = settings.gemini_api_key
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
            if isinstance(exc, httpx.HTTPStatusError) and exc.response is not None:
                # If Gemini returns 400 Bad Request, raise a specific exception with details
                if exc.response.status_code == 400:
                    raise GeminiBadRequestError(
                        f"Gemini API returned 400 Bad Request",
                        status_code=exc.response.status_code,
                        body=exc.response.text,
                    ) from exc
                logger.error(
                    f"Gemini request failed: {exc} - Status: {exc.response.status_code} - Body: {exc.response.text}"
                )
            else:
                logger.error(f"Gemini request failed: {exc}")
            raise

class OpenAIClient:
    """Fallback wrapper for OpenAI chat completions.
    Reads ``OPENAI_API_KEY`` from environment.
    """

    def __init__(self, model: str = "gpt-4o-mini"):
        self.api_key = settings.openai_api_key
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
