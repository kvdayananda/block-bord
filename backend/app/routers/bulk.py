"""
Block Bord AI — Bulk Scanner Router
Allows Pro/Business/Enterprise users to submit multiple URLs at once for scanning.
"""
import json
import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Request, Depends, HTTPException, File, UploadFile, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db, get_current_user, require_pro
from backend.app.models import BulkScanJob
from backend.app.services.scan_service import run_scan

logger = logging.getLogger("blockbord.bulk")
router = APIRouter(prefix="/bulk", tags=["Bulk Scanner"])
templates = Jinja2Templates(directory="frontend/templates")


@router.get("", response_class=HTMLResponse)
def bulk_scan_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/login", status_code=302)
    jobs = db.query(BulkScanJob).filter(BulkScanJob.user_id == user.id).order_by(BulkScanJob.created_at.desc()).limit(10).all()
    return templates.TemplateResponse("bulk_scanner.html", {
        "request": request,
        "user": user,
        "plan": getattr(user, "plan", "free"),
        "jobs": jobs
    })


@router.post("/api/submit")
async def submit_bulk_scan(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_pro)
):
    """Accept a newline-separated list of URLs and start processing."""
    form = await request.form()
    raw_urls = form.get("urls", "")
    
    urls = [u.strip() for u in raw_urls.strip().splitlines() if u.strip()]
    if not urls:
        raise HTTPException(status_code=400, detail="No URLs provided.")
    if len(urls) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 URLs per bulk job.")

    job = BulkScanJob(
        user_id=user.id,
        status="running",
        total_urls=len(urls),
        completed_urls=0,
        results_json=json.dumps([])
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Process synchronously (for simplicity — use Celery in production)
    results = []
    for url in urls:
        try:
            result = await run_scan(url, user_id=user.id, db=db)
            results.append({
                "url": url,
                "risk_score": result.get("risk_score", 0),
                "risk_level": result.get("risk_level", "unknown"),
                "status": "done"
            })
        except Exception as e:
            results.append({"url": url, "error": str(e), "status": "failed"})
        finally:
            job.completed_urls += 1

    job.status = "done"
    job.results_json = json.dumps(results)
    job.completed_at = datetime.now(timezone.utc)
    db.commit()

    return {"job_id": job.id, "total": len(urls), "results": results}


@router.get("/api/job/{job_id}")
def get_job_status(job_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    job = db.query(BulkScanJob).filter(BulkScanJob.id == job_id, BulkScanJob.user_id == user.id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "id": job.id,
        "status": job.status,
        "total_urls": job.total_urls,
        "completed_urls": job.completed_urls,
        "results": json.loads(job.results_json or "[]"),
        "created_at": str(job.created_at),
        "completed_at": str(job.completed_at) if job.completed_at else None
    }
