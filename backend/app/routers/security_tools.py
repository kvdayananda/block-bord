import logging
from fastapi import APIRouter, Request, Depends, HTTPException, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db, get_current_user, require_user, require_pro, validate_csrf
from backend.app.services.security_tools import SecurityToolService
from backend.app.schemas.security import (
    URLScanResult,
    DomainInfo,
    IPReputation,
    EmailBreachInfo,
    SSLReport,
    DNSRecords,
    PasswordBreachInfo,
    QRInfo,
)

logger = logging.getLogger("blockbord.routers.security_tools")
router = APIRouter(prefix="/security", tags=["Security Tools"])
templates = Jinja2Templates(directory="frontend/templates")
service = SecurityToolService()

# ──────────────────────────────────────────────────────────────
# FRONTEND TEMPLATE
# ──────────────────────────────────────────────────────────────
@router.get("", response_class=HTMLResponse)
def security_suite_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("security.html", {"request": request, "user": user, "plan": getattr(user, "plan", "free")})

# ──────────────────────────────────────────────────────────────
# API ENDPOINTS
# ──────────────────────────────────────────────────────────────
@router.post("/api/scan-url", response_model=URLScanResult)
async def api_scan_url(
    request: Request,
    url: str = File(None) or File(...), # handles form submission / request body
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    try:
        # If url passed as a form parameter
        form = await request.form()
        target_url = form.get("url") or url
        if not target_url:
            raise HTTPException(status_code=400, detail="Missing url parameter")
        return await service.scan_url(str(target_url))
    except Exception as e:
        logger.error(f"URL Scan Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/lookup-domain", response_model=DomainInfo)
async def api_lookup_domain(
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    try:
        form = await request.form()
        domain = form.get("domain")
        if not domain:
            raise HTTPException(status_code=400, detail="Missing domain parameter")
        return await service.lookup_domain(str(domain))
    except Exception as e:
        logger.error(f"Domain Lookup Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/check-ip", response_model=IPReputation)
async def api_check_ip(
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    try:
        form = await request.form()
        ip = form.get("ip")
        if not ip:
            raise HTTPException(status_code=400, detail="Missing ip parameter")
        return await service.check_ip(str(ip))
    except Exception as e:
        logger.error(f"IP Check Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/check-email", response_model=EmailBreachInfo)
async def api_check_email(
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    try:
        form = await request.form()
        email = form.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Missing email parameter")
        return await service.check_email(str(email))
    except Exception as e:
        logger.error(f"Email Check Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ──────────────────────────────────────────────────────────────
# PRO / PREMIUM ONLY ENDPOINTS
# ──────────────────────────────────────────────────────────────
@router.post("/api/analyze-ssl", response_model=SSLReport)
async def api_analyze_ssl(
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_pro) # Premium gating
):
    try:
        form = await request.form()
        hostname = form.get("hostname")
        if not hostname:
            raise HTTPException(status_code=400, detail="Missing hostname parameter")
        return await service.analyze_ssl(str(hostname))
    except Exception as e:
        logger.error(f"SSL Analysis Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/dns-lookup", response_model=DNSRecords)
async def api_dns_lookup(
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_pro) # Premium gating
):
    try:
        form = await request.form()
        hostname = form.get("hostname")
        if not hostname:
            raise HTTPException(status_code=400, detail="Missing hostname parameter")
        return await service.dns_lookup(str(hostname))
    except Exception as e:
        logger.error(f"DNS Lookup Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/check-password", response_model=PasswordBreachInfo)
async def api_check_password(
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    try:
        form = await request.form()
        password = form.get("password")
        if not password:
            raise HTTPException(status_code=400, detail="Missing password parameter")
        return await service.check_password(str(password))
    except Exception as e:
        logger.error(f"Password Check Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/analyze-qr", response_model=QRInfo)
async def api_analyze_qr(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user = Depends(require_pro) # Premium gating
):
    try:
        image_bytes = await file.read()
        return await service.analyze_qr(image_bytes)
    except Exception as e:
        logger.error(f"QR Scan Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
