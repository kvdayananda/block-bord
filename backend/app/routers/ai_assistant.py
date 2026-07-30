import logging
from fastapi import APIRouter, Request, Depends, HTTPException, Form
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db, require_user
from backend.app.config import settings

logger = logging.getLogger("blockbord.ai_assistant")
router = APIRouter(prefix="/api/ai", tags=["AI Assistant"])

@router.post("/chat")
async def chat_with_assistant(
    request: Request,
    message: str = Form(...),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Simulated AI Security Assistant response.
    Connects to AIToolsService (Gemini/OpenAI) if configured, 
    otherwise falls back to keyword-based simulation.
    """
    msg_lower = message.lower()
    
    try:
        from backend.app.services.ai_tools import AIToolsService
        ai_service = AIToolsService()
        result = await ai_service.chat_assistant(message)
        reply = result.get("answer", "I couldn't process that.")
        return {"reply": reply}
    except Exception as e:
        logger.warning(f"AI Service unavailable ({e}), falling back to simulated responses.")
        
        # Simple keyword-based responses to simulate an AI
        if "phishing" in msg_lower or "scam" in msg_lower:
            reply = "Phishing attempts often use urgency and impersonation to steal credentials. Always verify the sender's email address and avoid clicking suspicious links."
        elif "password" in msg_lower:
            reply = "Strong passwords should be at least 12 characters long and include a mix of uppercase, lowercase, numbers, and special characters. Consider using a password manager."
        elif "ssl" in msg_lower or "https" in msg_lower:
            reply = "SSL certificates encrypt data between your browser and the server. Always ensure the sites you visit use HTTPS, especially when entering sensitive information."
        elif "hello" in msg_lower or "hi" in msg_lower:
            reply = "Hello! I am your AI Security Assistant. How can I help you secure your online presence today?"
        else:
            reply = "I'm analyzing your request. Security is a continuous process. Make sure to monitor your accounts regularly and use 2FA where possible."
            
        return {"reply": reply}
