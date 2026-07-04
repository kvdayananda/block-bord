import logging
from typing import Any, Dict
from .api_clients import GeminiClient, OpenAIClient

logger = logging.getLogger(__name__)

class AIToolsService:
    """Service exposing AI-powered security features.
    Uses GeminiClient (fallback to OpenAIClient if Gemini unavailable).
    """

    def __init__(self):
        try:
            self.client = GeminiClient()
            self.provider = "gemini"
        except Exception as e:
            logger.warning(f"Gemini init failed ({e}), falling back to OpenAI")
            self.client = OpenAIClient()
            self.provider = "openai"

    async def detect_scam(self, input_text: str) -> Dict[str, Any]:
        system_prompt = "You are a cybersecurity analyst. Assess whether the given input is a scam, phishing, or malicious. Respond with a concise verdict (Scam, Legitimate, or Unclear) and a short reason."
        response = await self.client.generate(system_prompt, input_text)
        # Simple parsing: assume first line is verdict, rest is reason
        lines = response["text"].splitlines()
        verdict = lines[0].strip() if lines else "Unclear"
        reason = "\n".join(lines[1:]).strip() if len(lines) > 1 else ""
        return {"verdict": verdict, "reason": reason, "raw": response}

    async def chat_assistant(self, query: str) -> Dict[str, Any]:
        system_prompt = "You are an expert security assistant. Answer the user's security‑related question in a clear, concise, and professional tone."
        response = await self.client.generate(system_prompt, query)
        return {"answer": response["text"].strip(), "raw": response}

    async def explain_risk(self, payload: str) -> Dict[str, Any]:
        system_prompt = "You are a cybersecurity risk analyst. Explain the risk factors for the given risk payload, including impact, attack vectors, and mitigations."
        response = await self.client.generate(system_prompt, payload)
        return {"explanation": response["text"].strip(), "raw": response}
