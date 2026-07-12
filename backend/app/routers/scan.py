"""
Block Bord AI — Scan Router
Routes: POST /scan, GET /scan/{id}, GET /api/scan/{id},
        POST /feedback, POST /ml/retrain, POST /api/check-link, POST /report,
        GET /api/public/blacklist
"""
import json
import logging
import hashlib
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Request, Depends, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from backend.app.utils.limiter import limiter
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db, get_current_user, require_user, validate_csrf
from backend.app.services.plan_service import get_user_plan, PLAN_LIMITS
from backend.app.services.email_service import send_high_risk_alert
from backend.app.models import ScanHistory, User, Feedback, BlacklistDomain, WhitelistDomain, UserReport
from backend.app.services.risk_engine import calculate_risk, _extract_domains
from backend.app.services.ml_engine import ml_engine
from backend.app.services.ml_training_service import train_model_from_samples
from backend.app.utils.common import get_today_scan_count, norm_risk_level


logger = logging.getLogger("blockbord.scan")
router = APIRouter(tags=["Scan"])
templates = Jinja2Templates(directory="frontend/templates")


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

# Simple In-Memory TTL Cache for Scans
_scan_cache = {}
_scan_cache_ttl = 60  # 60 seconds

def normalize_url(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        tracking_params = {'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'fbclid', 'gclid', 'sourceid', 'gs_lcrp'}
        qs = parse_qs(parsed.query)
        filtered_qs = {k: v for k, v in qs.items() if k.lower() not in tracking_params}
        new_query = urlencode(filtered_qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)).lower()
    except Exception:
        return url.lower()


# ──────────────────────────────────────────────────────────────
# POST /scan — Main scan endpoint (used by extension + web)
# ──────────────────────────────────────────────────────────────
@router.post("/scan")
@limiter.limit("30/minute")
async def scan_content(
    data: ScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
    _csrf: None = Depends(validate_csrf),
):

    plan = get_user_plan(user) if user else "free"
    limit = PLAN_LIMITS.get(plan)
    today_count = get_today_scan_count(db, user.id) if user else 0

    if limit is not None and today_count >= limit:
        return {
            "error": "Daily limit reached. Please upgrade your plan.",
            "upgrade_required": True,
            "plan": plan,
            "limit": limit,
        }

    # 1. URL Normalization & Hashing
    norm_url = normalize_url(data.url) if data.url else ""
    content_hash_input = (norm_url + (data.content or "")).encode('utf-8')
    content_hash = hashlib.sha256(content_hash_input).hexdigest()

    # 2. TTL Cache Check (In-memory bypass)
    now = time.time()
    # Cleanup naive cache occasionally
    if len(_scan_cache) > 5000:
        keys_to_del = [k for k, (ts, _) in _scan_cache.items() if now - ts > _scan_cache_ttl]
        for k in keys_to_del:
            del _scan_cache[k]

    if content_hash in _scan_cache:
        ts, cached_result = _scan_cache[content_hash]
        if now - ts < _scan_cache_ttl:
            logger.info(f"Scan hit TTL memory cache for user={user.username if user else 'anon'}")
            return cached_result

    five_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
    recent_scan = None
    if user:
        recent_scan = db.query(ScanHistory).filter(
            ScanHistory.user_id == user.id,
            ScanHistory.url_hash == content_hash,
            ScanHistory.created_at >= five_mins_ago
        ).order_by(ScanHistory.created_at.desc()).first()

    if recent_scan:
        logger.info(f"Scan #{recent_scan.id} | user={user.username} | Deduplicated DB hit.")
        result = {
            "risk_score": recent_scan.risk_score,
            "risk_level": recent_scan.risk_level,
            "reasons": _parse_reasons(recent_scan.reasons),
            "category": recent_scan.category,
            "scam_intent": recent_scan.scam_intent,
            "scan_id": recent_scan.id,
            "cached": True
        }
        _scan_cache[content_hash] = (now, result)
        return result

    urls, domains = _extract_domains(data.content)

    # Check whitelist first
    for d in domains:
        if db.query(WhitelistDomain).filter(WhitelistDomain.domain == d).first():
            result = {
                "risk_score": 0, "risk_level": "OK",
                "reasons": [f"Domain '{d}' is on the trusted whitelist."],
                "category": "Whitelisted",
            }
            scan_id = None
            if user:
                scan = _save_and_return(result, data, user, db, content_hash)
                scan_id = scan.id
            _scan_cache[content_hash] = (now, {**result, "scan_id": scan_id})
            return _scan_cache[content_hash][1]

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
            scan_id = None
            if user:
                scan = _save_and_return(result, data, user, db, content_hash)
                scan_id = scan.id
            _scan_cache[content_hash] = (now, {**result, "scan_id": scan_id})
            return _scan_cache[content_hash][1]

    # Run full risk analysis
    result = await calculate_risk(
        text=data.content,
        url=data.url,
        telemetry=data.telemetry,
        form_data=data.formData,
        has_redirected=data.hasRedirected,
    )

    scan_id = None
    if user:
        scan = _save_and_return(result, data, user, db, content_hash)
        scan_id = scan.id

    logger.info(
        f"Scan #{scan_id or 'anon'} | user={user.username if user else 'anon'} | score={result['risk_score']} "
        f"| level={result['risk_level']} | url={data.url or 'text'}"
    )

    final_resp = {
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "reasons": result.get("reasons", []),
        "category": result.get("category", "General Threat"),
        "scam_intent": result.get("scam_intent", "None Detected"),
        "scan_id": scan_id,
    }
    _scan_cache[content_hash] = (now, final_resp)
    return final_resp


def _save_and_return(result: dict, data: ScanRequest, user: User, db: Session, url_hash: str) -> ScanHistory:
    score_val = float(result.get("risk_score", 0))
    scan = ScanHistory(
        content=data.content,
        url_hash=url_hash,
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
async def check_link(
    data: LinkAnalysisRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
):
    url = (data.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    text_to_scan = data.content if data.content else url
    result = await calculate_risk(text=text_to_scan, url=url)

    if user and result.get("risk_level") == "High":
        background_tasks.add_task(send_high_risk_alert, user.email, url, result)

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
