"""
Block Bord AI — Scan Router
Routes: POST /scan, GET /scan/{id}, GET /api/scan/{id},
        POST /feedback, POST /ml/retrain, POST /api/check-link, POST /report,
        GET /api/public/blacklist
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Request, Depends, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db, get_current_user, validate_csrf
from backend.app.services.plan_service import get_user_plan, PLAN_LIMITS
from backend.app.services.email_service import send_high_risk_alert
from database import ScanHistory, User, Feedback, BlacklistDomain, WhitelistDomain, UserReport
from risk_engine import calculate_risk, _extract_domains
from ml_spam import train_model_from_samples

logger = logging.getLogger("blockbord.scan")
router = APIRouter(tags=["Scan"])
templates = Jinja2Templates(directory="frontend/templates")
limiter = Limiter(key_func=get_remote_address)


# ── Pydantic Models ──
class ScanRequest(BaseModel):
    content: str
    url: Optional[str] = None
    formData: Optional[dict] = None
    telemetry: Optional[dict] = None
    hasRedirected: Optional[bool] = False


class FeedbackRequest(BaseModel):
    label: str  # spam | ham
    content: str
    scan_id: Optional[int] = None


class LinkAnalysisRequest(BaseModel):
    url: str
    source: Optional[str] = "web"
    content: Optional[str] = None


class UserReportRequest(BaseModel):
    url: str
    description: Optional[str] = None


def _get_today_scan_count(db: Session, user_id: int) -> int:
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user_id, ScanHistory.created_at >= today_start)
        .count()
    )


def _parse_reasons(raw: str) -> list:
    """Safely parse reasons from JSON (with legacy str(list) fallback)."""
    try:
        return json.loads(raw) if raw else []
    except (json.JSONDecodeError, TypeError):
        import ast
        try:
            return ast.literal_eval(raw) if raw else []
        except Exception:
            return [raw] if raw else []


# ──────────────────────────────────────────────────────────────
# POST /scan — Main scan endpoint (used by extension + web)
# ──────────────────────────────────────────────────────────────
@router.post("/scan")
@limiter.limit("30/minute")
def scan_content(
    data: ScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    _csrf: None = Depends(validate_csrf),
):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    plan = get_user_plan(user)
    limit = PLAN_LIMITS.get(plan)
    today_count = _get_today_scan_count(db, user.id)

    if limit is not None and today_count >= limit:
        return {
            "error": "Daily limit reached. Please upgrade your plan.",
            "upgrade_required": True,
            "plan": plan,
            "limit": limit,
        }

    urls, domains = _extract_domains(data.content)

    # Check whitelist first
    for d in domains:
        if db.query(WhitelistDomain).filter(WhitelistDomain.domain == d).first():
            result = {
                "risk_score": 0, "risk_level": "OK",
                "reasons": [f"Domain '{d}' is on the trusted whitelist."],
                "category": "Whitelisted",
            }
            _save_and_return(result, data, user, db)
            return result

    # Check blacklist
    for d in domains:
        hit = db.query(BlacklistDomain).filter(BlacklistDomain.domain == d).first()
        if hit:
            result = {
                "risk_score": 100, "risk_level": "High",
                "reasons": [
                    f"Domain '{d}' is strictly blacklisted by administrators.",
                    hit.reason or "Known dangerous domain.",
                ],
                "category": "Blacklisted Domain",
            }
            scan = _save_and_return(result, data, user, db)
            return {**result, "scan_id": scan.id}

    # Run full risk analysis
    result = calculate_risk(
        text=data.content,
        url_context=data.url,
        telemetry=data.telemetry,
        form_data=data.formData,
        has_redirected=data.hasRedirected,
    )

    scan = _save_and_return(result, data, user, db)
    logger.info(
        f"Scan #{scan.id} | user={user.username} | score={result['risk_score']} "
        f"| level={result['risk_level']} | url={data.url or 'text'}"
    )

    return {
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "reasons": result.get("reasons", []),
        "category": result.get("category", "General Threat"),
        "scam_intent": result.get("scam_intent", "None Detected"),
        "scan_id": scan.id,
    }


def _save_and_return(result: dict, data: ScanRequest, user: User, db: Session) -> ScanHistory:
    score_val = float(result.get("risk_score", 0))
    scan = ScanHistory(
        content=data.content,
        risk_score=score_val,
        risk_level=str(result["risk_level"]),
        reasons=json.dumps(result.get("reasons", [])),
        category=result.get("category", "General Threat"),
        scam_intent=result.get("scam_intent", "None Detected"),
        user_id=user.id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


# ──────────────────────────────────────────────────────────────
# GET /scan/{scan_id} — HTML Scan Detail Page
# ──────────────────────────────────────────────────────────────
@router.get("/scan/{scan_id}", response_class=HTMLResponse)
def scan_detail_page(request: Request, scan_id: int, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    scan = db.query(ScanHistory).filter(
        ScanHistory.id == scan_id, ScanHistory.user_id == user.id
    ).first()
    if not scan:
        return HTMLResponse("Scan not found", status_code=404)
    return templates.TemplateResponse("scan_detail.html", {
        "request": request, "scan": scan, "user": user,
        "plan": get_user_plan(user),
        "reasons_list": _parse_reasons(scan.reasons),
    })


# ──────────────────────────────────────────────────────────────
# GET /api/scan/{scan_id} — JSON Scan Detail API
# ──────────────────────────────────────────────────────────────
@router.get("/api/scan/{scan_id}")
def scan_details_api(scan_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    scan = db.query(ScanHistory).filter(
        ScanHistory.id == scan_id, ScanHistory.user_id == user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": scan.id, "content": scan.content,
        "risk_score": scan.risk_score, "risk_level": scan.risk_level,
        "reasons": _parse_reasons(scan.reasons),
        "category": scan.category, "scam_intent": scan.scam_intent,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }


# ──────────────────────────────────────────────────────────────
# POST /feedback — User labels a scan as spam/ham
# ──────────────────────────────────────────────────────────────
@router.post("/feedback")
def submit_feedback(
    data: FeedbackRequest,
    request: Request,
    db: Session = Depends(get_db),
    _csrf: None = Depends(validate_csrf),
):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    label = (data.label or "").strip().lower()
    if label not in {"spam", "ham"}:
        raise HTTPException(status_code=400, detail="Invalid label (must be 'spam' or 'ham')")
    content = (data.content or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Empty content")
    db.add(Feedback(user_id=user.id, label=label, content=content, source_scan_id=data.scan_id))
    db.commit()
    return {"ok": True}


# ──────────────────────────────────────────────────────────────
# POST /ml/retrain — Manually trigger ML retraining
# ──────────────────────────────────────────────────────────────
@router.post("/ml/retrain")
@limiter.limit("5/minute")
def retrain_ml(
    request: Request,
    db: Session = Depends(get_db),
    _csrf: None = Depends(validate_csrf),
):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    rows = db.query(Feedback).order_by(Feedback.created_at.desc()).limit(5000).all()
    samples = [(r.label, r.content) for r in rows]
    ok, message = train_model_from_samples(samples)
    return {"ok": ok, "message": message}


# ──────────────────────────────────────────────────────────────
# POST /api/check-link — Public link analysis (API key auth)
# ──────────────────────────────────────────────────────────────
@router.post("/api/check-link")
@limiter.limit("20/minute")
def check_link(
    data: LinkAnalysisRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    url = (data.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    # API key auth
    current_user = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer bb_live_"):
        api_key = auth_header[7:]
        current_user = db.query(User).filter(User.api_key == api_key).first()
        if not current_user:
            raise HTTPException(status_code=401, detail="Invalid API key")

    if not current_user:
        uid = request.session.get("user_id")
        if uid:
            current_user = db.query(User).filter(User.id == uid).first()

    text_to_scan = data.content if data.content else url
    result = calculate_risk(text_to_scan)

    if current_user and result.get("risk_level") == "High":
        background_tasks.add_task(send_high_risk_alert, current_user.email, url, result)

    return {
        "url": url, "source": data.source,
        "risk_score": result["risk_score"], "risk_level": result["risk_level"],
        "reasons": result.get("reasons", []), "category": result.get("category", "General"),
    }


# ──────────────────────────────────────────────────────────────
# POST /report — User-submitted URL report
# ──────────────────────────────────────────────────────────────
@router.post("/report")
@limiter.limit("10/minute")
def submit_user_report(
    data: UserReportRequest,
    request: Request,
    db: Session = Depends(get_db),
    _csrf: None = Depends(validate_csrf),
):
    user = get_current_user(request, db)
    url = (data.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    _, domains = _extract_domains(url)
    reported_domain = domains[0] if domains else None
    db.add(UserReport(
        reported_url=url, reported_domain=reported_domain,
        description=data.description, user_id=user.id if user else None,
    ))
    db.commit()
    return {"ok": True, "message": "Report submitted. Thank you for keeping the web safe!"}


# ──────────────────────────────────────────────────────────────
# GET /api/public/blacklist
# ──────────────────────────────────────────────────────────────
@router.get("/api/public/blacklist")
def list_public_blacklist(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    items = db.query(BlacklistDomain).order_by(BlacklistDomain.created_at.desc()).limit(100).all()
    return [{"id": i.id, "domain": i.domain, "reason": i.reason or "Phishing/Threat Detected"} for i in items]
