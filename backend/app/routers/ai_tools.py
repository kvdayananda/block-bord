import logging
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db, get_current_user, require_user, require_pro, validate_csrf
from backend.app.services.ai_tools import AIToolsService
from backend.app.schemas.ai import (
    ScamRequest,
    ScamResult,
    AssistantRequest,
    ChatResponse,
    RiskExplanationRequest,
    RiskExplanationResponse
)

logger = logging.getLogger("blockbord.routers.ai_tools")
router = APIRouter(prefix="/ai", tags=["AI Tools"])
templates = Jinja2Templates(directory="frontend/templates")
service = AIToolsService()

# ──────────────────────────────────────────────────────────────
# FRONTEND TEMPLATE
# ──────────────────────────────────────────────────────────────
@router.get("", response_class=HTMLResponse)
def ai_hub_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("ai.html", {"request": request, "user": user, "plan": getattr(user, "plan", "free")})

# ──────────────────────────────────────────────────────────────
# API ENDPOINTS
# ──────────────────────────────────────────────────────────────
@router.post("/api/scam")
async def api_detect_scam(
    req: ScamRequest,
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    try:
        res = await service.detect_scam(req.input_text)
        # Determine a simulated risk score based on verdict
        score = 0
        if res["verdict"].lower() == "scam":
            score = 90
        elif res["verdict"].lower() == "suspicious" or "suspicious" in res["reason"].lower():
            score = 50
        else:
            score = 10
            
        return ScamResult(
            verdict=res["verdict"],
            reason=res["reason"],
            score=score,
            raw=res.get("raw")
        )
    except Exception as e:
        logger.error(f"AI Scam Detector Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/assistant")
async def api_assistant(
    req: AssistantRequest,
    request: Request,
    db: Session = Depends(get_db),

):
    try:
        # Pass conversation history if supported, or just the main message
        res = await service.chat_assistant(req.message)
        return ChatResponse(
            answer=res["answer"],
            raw=res.get("raw")
        )
    except Exception as e:
        # If the underlying service raised a GeminiBadRequestError, expose its details
        from backend.app.services.api_clients import GeminiBadRequestError
        if isinstance(e, GeminiBadRequestError):
            logger.error(f"Gemini request failed: {e.body}")
            raise HTTPException(status_code=500, detail=f"Gemini error: {e.body}")
        logger.error(f"AI Assistant Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/risk")
async def api_explain_risk(
    req: RiskExplanationRequest,
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_pro) # Premium Gated
):
    try:
        import json
        payload_str = json.dumps(req.payload)
        res = await service.explain_risk(payload_str)
        return RiskExplanationResponse(
            explanation=res["explanation"],
            raw=res.get("raw")
        )
    except Exception as e:
        logger.error(f"AI Risk Explainer Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
