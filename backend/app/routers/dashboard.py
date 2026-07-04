"""
Block Bord AI — Dashboard Router
Routes: /app, /history, /analytics, /settings, /extension-setup,
        /api/stats, /api/analytics, /api/export/scans, /api/generate_key
"""
import json
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import csv
import io

from backend.app.dependencies import get_db, get_current_user
from backend.app.services.plan_service import get_user_plan, get_plan_limit, PLAN_LIMITS
from backend.app.models import ScanHistory, User
from backend.app.utils.common import get_today_scan_count, norm_risk_level

logger = logging.getLogger("blockbord.dashboard")
router = APIRouter(tags=["Dashboard"])
templates = Jinja2Templates(directory="frontend/templates")




# ──────────────────────────────────────────────────────────────
# DASHBOARD
# ──────────────────────────────────────────────────────────────
@router.get("/app", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    plan = get_user_plan(user)
    today_count = get_today_scan_count(db, user.id)
    limit = PLAN_LIMITS.get(plan)
    display_limit = limit if limit is not None else "∞"

    recent_scans = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(5)
        .all()
    )
    all_scans = db.query(ScanHistory).filter(ScanHistory.user_id == user.id).all()
    total_scans = len(all_scans)

    high_risk = sum(1 for s in all_scans if norm_risk_level(s.risk_level) == "High")
    suspicious_count = sum(1 for s in all_scans if norm_risk_level(s.risk_level) == "Suspicious")
    safe_count = sum(1 for s in all_scans if norm_risk_level(s.risk_level) == "OK")

    # 7-day timeline
    today = datetime.now(timezone.utc).date()
    timeline = {
        (today - timedelta(days=i)).strftime("%b %d"): {"High": 0, "Suspicious": 0, "OK": 0}
        for i in range(6, -1, -1)
    }
    for s in all_scans:
        if s.created_at:
            date_str = s.created_at.date().strftime("%b %d")
            if date_str in timeline:
                timeline[date_str][norm_risk_level(s.risk_level)] += 1

    # Security score
    if total_scans == 0:
        security_score = 90
    else:
        penalty = (high_risk * 8) + (suspicious_count * 3)
        bonus = safe_count * 2
        security_score = max(10, min(100, 90 - penalty + bonus))

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "plan": plan,
        "today_count": today_count,
        "plan_limit": display_limit,
        "total_scans": total_scans,
        "high_risk": high_risk,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "security_score": security_score,
        "recent_scans": recent_scans,
        "timeline_labels": list(timeline.keys()),
        "timeline_high": [t["High"] for t in timeline.values()],
        "timeline_susp": [t["Suspicious"] for t in timeline.values()],
        "timeline_safe": [t["OK"] for t in timeline.values()],
        "remaining_scans": max(0, limit - today_count) if limit is not None else "∞",
    })


# ──────────────────────────────────────────────────────────────
# HISTORY
# ──────────────────────────────────────────────────────────────
@router.get("/history", response_class=HTMLResponse)
def scan_history_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    scans = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user.id)
        .order_by(ScanHistory.created_at.desc())
        .all()
    )
    return templates.TemplateResponse("history.html", {
        "request": request, "user": user,
        "scans": scans, "plan": get_user_plan(user),
    })


# ──────────────────────────────────────────────────────────────
# ANALYTICS PAGE
# ──────────────────────────────────────────────────────────────
@router.get("/analytics", response_class=HTMLResponse)
def analytics_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("analytics.html", {"request": request, "user": user})


# ──────────────────────────────────────────────────────────────
# SETTINGS
# ──────────────────────────────────────────────────────────────
@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    plan = get_user_plan(user)
    today_count = get_today_scan_count(db, user.id)
    limit = PLAN_LIMITS.get(plan)
    return templates.TemplateResponse("settings.html", {
        "request": request, "user": user, "plan": plan,
        "today_count": today_count,
        "plan_limit": limit if limit is not None else "∞",
        "api_key": user.api_key,
    })


# ──────────────────────────────────────────────────────────────
# EXTENSION SETUP
# ──────────────────────────────────────────────────────────────
@router.get("/extension-setup", response_class=HTMLResponse)
def extension_setup_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("extension_setup.html", {"request": request, "user": user})


# ──────────────────────────────────────────────────────────────
# BLOCK LIST PAGE
# ──────────────────────────────────────────────────────────────
@router.get("/block-list", response_class=HTMLResponse)
def block_list_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("block_list.html", {
        "request": request, "user": user, "plan": get_user_plan(user)
    })


# ──────────────────────────────────────────────────────────────
# API: GENERATE API KEY
# ──────────────────────────────────────────────────────────────
@router.post("/api/generate_key")
def generate_api_key(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_pro:
        return JSONResponse({"error": "Pro Plan Required"}, status_code=403)
    user.api_key = f"bb_live_{secrets.token_urlsafe(32)}"
    db.commit()
    logger.info(f"API key regenerated for user: {user.username}")
    return {"api_key": user.api_key}


# ──────────────────────────────────────────────────────────────
# API: SECURITY STATS
# ──────────────────────────────────────────────────────────────
@router.get("/api/stats")
def get_security_stats(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    all_scans = db.query(ScanHistory).filter(ScanHistory.user_id == user.id).all()
    total = len(all_scans)
    high = sum(1 for s in all_scans if norm_risk_level(s.risk_level) == "High")
    susp = sum(1 for s in all_scans if norm_risk_level(s.risk_level) == "Suspicious")
    safe = sum(1 for s in all_scans if norm_risk_level(s.risk_level) == "OK")
    cats: dict = {}
    for s in all_scans:
        cat = getattr(s, "category", None) or "General"
        cats[cat] = cats.get(cat, 0) + 1
    return {
        "total_scans": total,
        "high_risk": high,
        "suspicious": susp,
        "safe": safe,
        "blocked_pct": round(float(high) / total * 100, 1) if total else 0,
        "categories": cats,
    }


# ──────────────────────────────────────────────────────────────
# API: THREAT ANALYTICS (30-day timeline)
# ──────────────────────────────────────────────────────────────
@router.get("/api/analytics")
def get_threat_analytics(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    today = datetime.now(timezone.utc).date()
    timeline = {
        (today - timedelta(days=i)).strftime("%b %d"): {"High": 0, "Suspicious": 0, "OK": 0}
        for i in range(29, -1, -1)
    }
    all_scans = db.query(ScanHistory).filter(ScanHistory.user_id == user.id).all()
    for s in all_scans:
        if s.created_at:
            key = s.created_at.date().strftime("%b %d")
            if key in timeline:
                timeline[key][norm_risk_level(s.risk_level)] += 1
    return {
        "labels": list(timeline.keys()),
        "high": [v["High"] for v in timeline.values()],
        "suspicious": [v["Suspicious"] for v in timeline.values()],
        "safe": [v["OK"] for v in timeline.values()],
    }


# ──────────────────────────────────────────────────────────────
# API: EXPORT SCANS AS CSV
# ──────────────────────────────────────────────────────────────
@router.get("/api/export/scans")
def export_scans_csv(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    scans = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user.id)
        .order_by(ScanHistory.created_at.desc())
        .all()
    )
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Content", "Risk Level", "Risk Score", "Category", "Date"])
    for s in scans:
        writer.writerow([
            s.id,
            (s.content or "")[:200],
            s.risk_level,
            s.risk_score,
            getattr(s, "category", "") or "",
            s.created_at.strftime("%Y-%m-%d %H:%M:%S") if s.created_at else "",
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=blockbord_scans.csv"},
    )


# ──────────────────────────────────────────────────────────────
# API: EXTENSION STATUS FOR PREMIUM FLOWS
# ──────────────────────────────────────────────────────────────
@router.get("/api/ext/status")
def get_extension_status(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return {"logged_in": False, "username": None, "plan": "free", "is_pro": False, "today_count": 0, "limit": 10}
    plan = get_user_plan(user)
    limit = get_plan_limit(plan)
    today_count = get_today_scan_count(db, user.id)
    return {
        "logged_in": True,
        "username": user.username,
        "plan": plan,
        "is_pro": user.is_pro,
        "today_count": today_count,
        "limit": limit if limit is not None else -1
    }
