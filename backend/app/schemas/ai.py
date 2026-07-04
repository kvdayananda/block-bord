from pydantic import BaseModel
from typing import Any, Dict, List, Optional

class ScamRequest(BaseModel):
    input_text: str

class ScamResult(BaseModel):
    verdict: str
    reason: str
    score: int
    raw: Optional[Dict[str, Any]] = None

class ChatMessage(BaseModel):
    role: str  # user | assistant
    content: str

class AssistantRequest(BaseModel):
    message: str
    history: List[ChatMessage] = []

class ChatResponse(BaseModel):
    answer: str
    raw: Optional[Dict[str, Any]] = None

class RiskExplanationRequest(BaseModel):
    payload: Dict[str, Any]

class RiskExplanationResponse(BaseModel):
    explanation: str
    raw: Optional[Dict[str, Any]] = None
