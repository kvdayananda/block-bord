"""
Block Bord AI — Tools Router
Routes: /leak-checker (Have I Been Pwned), /scam-map (Analytics Stats), 
        /api/assistant (Chatbot), /api/check-leak, /api/scam-stats
"""
import logging
import os
import httpx
import json
from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db, get_current_user, validate_csrf
from backend.app.models import ScanHistory

logger = logging.getLogger("blockbord.tools")
router = APIRouter(tags=["Tools"])
templates = Jinja2Templates(directory="frontend/templates")


# ──────────────────────────────────────────────────────────────
# LEAK CHECKER (HIBP)
# ──────────────────────────────────────────────────────────────
@router.get("/leak-checker", response_class=HTMLResponse)
def leak_checker_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("leak_checker.html", {"request": request, "user": user})


@router.post("/api/check-leak")
async def check_leak(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
         raise HTTPException(status_code=401, detail="Unauthorized")

    email = email.strip().lower()
    hibp_key = os.getenv("HIBP_API_KEY")

    if not hibp_key:
        # Simulation Mode / Fallback
        is_leaked = hash(email) % 3 == 0  # Deterministic simulation
        return {
            "leaked": is_leaked,
            "source": "SIMULATION (No API Key)",
            "details": "Your email appeared in 3 data breaches (Facebook 2019, Canva 2020) in this simulation." if is_leaked else "No leaks found in simulation."
        }

    async with httpx.AsyncClient() as client:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {"hibp-api-key": hibp_key, "user-agent": "BlockBord-AI"}
        resp = await client.get(url, headers=headers)
        
        if resp.status_code == 404:
            return {"leaked": False, "details": "No leaks found in the HIBP database."}
        elif resp.status_code == 200:
            return {"leaked": True, "details": resp.json()}
        else:
            return {"error": "HIBP API error", "status": resp.status_code}


# ──────────────────────────────────────────────────────────────
# SCAM MAP / STATS
# ──────────────────────────────────────────────────────────────
@router.get("/scam-map", response_class=HTMLResponse)
def scam_map_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("scam_map.html", {"request": request, "user": user})


@router.get("/api/scam-stats")
def scam_stats_api(db: Session = Depends(get_db)):
    """
    Aggregated stats for the global 'Scam Map' visualization.
    Returns the exact structure expected by the frontend templates/scam_map.html.
    """
    from datetime import datetime, timezone, timedelta
    import random

    total_scans = db.query(ScanHistory).count()
    
    # Mock data for global visualization (in a real app, this would be derived from IP geodata)
    countries_data = {
        "IN": random.randint(1500, 3000), 
        "US": random.randint(1000, 2000), 
        "GB": random.randint(500, 1500),
        "BR": random.randint(300, 900),
        "NG": random.randint(400, 1000),
        "AU": random.randint(200, 600)
    }
    
    # Generate a dynamic feed for more "live" feeling
    event_types = ["Phishing Attempt", "UPI Scam", "Vishing Blocked", "Malicious Link"]
    cities = ["Mumbai", "New York", "London", "Lagos", "São Paulo", "Sydney", "Delhi", "Chicago"]
    
    feed = []
    now = datetime.now(timezone.utc)
    for i in range(10):
        event_time = now - timedelta(minutes=random.randint(0, 60))
        feed.append({
            "type": random.choice(event_types),
            "city": random.choice(cities),
            "time": event_time.strftime("%H:%M")
        })

    return {
        "total_today": total_scans + random.randint(100, 500), # Simulating high traffic
        "top_country": "IN",
        "countries": countries_data,
        "feed": feed
    }


# ──────────────────────────────────────────────────────────────
# AI CHATBOT (Gemini)
# ──────────────────────────────────────────────────────────────
@router.post("/api/assistant")
async def assistant_api(request: Request, prompt: str = Form(...), db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
         raise HTTPException(status_code=401, detail="Unauthorized")

    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key:
        return {"response": "I am currently in rule-based mode. How can I help you with your account today? (Add GEMINI_API_KEY for full AI capability)"}

    # Integration with Google Generative AI (Gemini)
    try:
        import google.generativeai as genai
        genai.configure(api_key=gemini_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        system_prompt = (
            "You are Block Bord AI, a cyber intelligence assistant. "
            "Help the user understand scams, phishing, and online safety. "
            "Be professional, direct, and security-focused."
        )
        
        response = model.generate_content(f"{system_prompt}\n\nUser: {prompt}")
        return {"response": response.text}
    except Exception as e:
        logger.error(f"Gemini AI error: {e}")
        return {"response": "Sorry, I'm having trouble connecting to my brain right now."}
