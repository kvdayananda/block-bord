"""
Block Bord AI — Admin Router
Routes: /admin, /admin/api/stats, /admin/api/bulk-action, /admin/export/scans,
        /admin/blacklist, /admin/whitelist, etc.
"""
import logging
import csv
import io
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.dependencies import get_db, require_admin
from backend.app.utils.limiter import limiter
from backend.app.services.plan_service import set_user_plan
from backend.app.models import User, ScanHistory, BlacklistDomain, WhitelistDomain, Feedback, UserReport

logger = logging.getLogger("blockbord.admin")
router = APIRouter(prefix="/admin", tags=["Admin"])
templates = Jinja2Templates(directory="frontend/templates")

# ──────────────────────────────────────────────────────────────
# ADMIN DASHBOARD
# ──────────────────────────────────────────────────────────────
@router.get("", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    total_users = db.query(User).count()
    pro_users = db.query(User).filter(User.is_pro == True).count()
    total_scans = db.query(ScanHistory).count()
    recent_reports = db.query(UserReport).order_by(UserReport.created_at.desc()).limit(10).all()
    
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "admin": admin,
        "total_users": total_users,
        "pro_users": pro_users,
        "total_scans": total_scans,
        "recent_reports": recent_reports,
    })

@router.get("/api/stats")
def get_admin_stats(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """API endpoint for live dashboard stats."""
    now = datetime.now(timezone.utc)
    scans_24h = db.query(ScanHistory).filter(ScanHistory.created_at >= now.replace(hour=0)).count()
    high_risk_24h = db.query(ScanHistory).filter(
        ScanHistory.created_at >= now.replace(hour=0),
        ScanHistory.risk_level == "High"
    ).count()
    
    return {
        "total_users": db.query(User).count(),
        "total_scans": db.query(ScanHistory).count(),
        "scans_24h": scans_24h,
        "high_risk_24h": high_risk_24h,
        "active_pro": db.query(User).filter(User.is_pro == True).count()
    }

# ──────────────────────────────────────────────────────────────
# USER MANAGEMENT
# ──────────────────────────────────────────────────────────────
@router.get("/users")
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    users = db.query(User).all()
    return [{
        "id": u.id, "username": u.username, "email": u.email,
        "is_pro": u.is_pro, "plan": u.plan, "is_active": u.is_active,
        "is_admin": u.is_admin, "created_at": u.created_at.isoformat() if u.created_at else None
    } for u in users]

@router.post("/api/bulk-action")
@limiter.limit("20/minute")
def bulk_user_action(
    request: Request,
    user_ids: List[int] = Form(...), 
    action: str = Form(...),
    db: Session = Depends(get_db), 
    admin: User = Depends(require_admin)
):
    """Perform bulk actions (delete, plan change, suspend) on multiple users."""
    users = db.query(User).filter(User.id.in_(user_ids)).all()
    
    for user in users:
        if action == "pro": set_user_plan(user, "pro")
        elif action == "free": set_user_plan(user, "free")
        elif action == "suspend": user.is_active = False
        elif action == "activate": user.is_active = True
        
    db.commit()
    logger.info(f"Admin {admin.username} performed bulk {action} on {len(users)} users.")
    return {"message": f"Successfully performed {action} on {len(users)} users."}

@router.post("/users/{user_id}/plan")
def update_user_plan(
    user_id: int, 
    plan: str = Form(...), 
    db: Session = Depends(get_db), 
    admin: User = Depends(require_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    set_user_plan(user, plan)
    db.commit()
    logger.info(f"Admin {admin.username} updated user {user.username} to plan: {plan}")
    return {"message": f"User {user.username} updated to {plan}"}

@router.post("/users/{user_id}/suspend")
def suspend_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot suspend yourself")
    
    user.is_active = False
    db.commit()
    logger.warning(f"Admin {admin.username} SUSPENDED user {user.username}")
    return {"message": "User suspended"}

# ──────────────────────────────────────────────────────────────
# DOMAIN LISTS (Blacklist/Whitelist)
# ──────────────────────────────────────────────────────────────
@router.get("/blacklist", response_class=HTMLResponse)
def blacklist_page(request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    items = db.query(BlacklistDomain).order_by(BlacklistDomain.created_at.desc()).all()
    return templates.TemplateResponse("admin_blacklist.html", {"request": request, "items": items, "admin": admin})

@router.post("/blacklist")
@limiter.limit("10/minute")
def add_to_blacklist(
    request: Request,
    domain: str = Form(...), 
    reason: str = Form(None), 
    db: Session = Depends(get_db), 
    admin: User = Depends(require_admin)
):
    domain = domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain required")
        
    if db.query(WhitelistDomain).filter(WhitelistDomain.domain == domain).first():
        raise HTTPException(status_code=400, detail="Domain is in Whitelist. Remove from whitelist first.")

    existing = db.query(BlacklistDomain).filter(BlacklistDomain.domain == domain).first()
    if existing:
        return {"message": "Domain already blacklisted"}
        
    db.add(BlacklistDomain(domain=domain, reason=reason, added_by_user_id=admin.id))
    db.commit()
    logger.info(f"Admin {admin.username} ADDED to blacklist: {domain}")
    return RedirectResponse("/admin/blacklist", status_code=303)

@router.get("/whitelist", response_class=HTMLResponse)
def whitelist_page(request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    items = db.query(WhitelistDomain).order_by(WhitelistDomain.created_at.desc()).all()
    return templates.TemplateResponse("admin_whitelist.html", {"request": request, "items": items, "admin": admin})

@router.post("/whitelist")
@limiter.limit("10/minute")
def add_to_whitelist(
    request: Request,
    domain: str = Form(...), 
    reason: str = Form(None), 
    db: Session = Depends(get_db), 
    admin: User = Depends(require_admin)
):
    domain = domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain required")

    db.query(BlacklistDomain).filter(BlacklistDomain.domain == domain).delete()
    
    existing = db.query(WhitelistDomain).filter(WhitelistDomain.domain == domain).first()
    if not existing:
        db.add(WhitelistDomain(domain=domain, reason=reason, added_by_user_id=admin.id))
        db.commit()
        logger.info(f"Admin {admin.username} ADDED to whitelist: {domain}")
        
    return RedirectResponse("/admin/whitelist", status_code=303)

# ──────────────────────────────────────────────────────────────
# EXPORT
# ──────────────────────────────────────────────────────────────
@router.get("/export/scans")
def export_scans_csv(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Export all scan history as a CSV file."""
    scans = db.query(ScanHistory).order_by(ScanHistory.created_at.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "URL/Content", "Risk Score", "Risk Level", "Category", "User ID", "Timestamp"])
    
    for s in scans:
        writer.writerow([s.id, s.content[:100], s.risk_score, s.risk_level, s.category, s.user_id, s.created_at])
    
    output.seek(0)
    return FileResponse(
        io.BytesIO(output.getvalue().encode()), 
        media_type="text/csv", 
        filename=f"blockbord_scans_{datetime.now().strftime('%Y%m%d')}.csv"
    )
