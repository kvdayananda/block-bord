"""
Block Bord AI — Support Tickets Router
Users can submit support tickets; admins can view and reply.
"""
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db, get_current_user, require_admin
from backend.app.models import SupportTicket

logger = logging.getLogger("blockbord.support")
router = APIRouter(prefix="/support", tags=["Support"])
templates = Jinja2Templates(directory="frontend/templates")


@router.get("", response_class=HTMLResponse)
def support_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    tickets = db.query(SupportTicket).filter(SupportTicket.user_id == user.id).order_by(SupportTicket.created_at.desc()).all()
    return templates.TemplateResponse("support.html", {
        "request": request,
        "user": user,
        "plan": getattr(user, "plan", "free"),
        "tickets": tickets
    })


@router.post("/submit")
async def submit_ticket(
    request: Request,
    subject: str = Form(...),
    message: str = Form(...),
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Login required")
    if not subject.strip() or not message.strip():
        raise HTTPException(status_code=400, detail="Subject and message are required.")
    if len(subject) > 200:
        raise HTTPException(status_code=400, detail="Subject too long (max 200 characters).")
    if len(message) > 5000:
        raise HTTPException(status_code=400, detail="Message too long (max 5000 characters).")

    ticket = SupportTicket(
        user_id=user.id,
        subject=subject.strip(),
        message=message.strip(),
        status="open"
    )
    db.add(ticket)
    db.commit()
    return RedirectResponse("/support?submitted=1", status_code=302)


@router.get("/admin", response_class=HTMLResponse)
def admin_support(request: Request, db: Session = Depends(get_db), admin=Depends(require_admin)):
    tickets = db.query(SupportTicket).order_by(SupportTicket.created_at.desc()).all()
    return templates.TemplateResponse("admin_support.html", {
        "request": request,
        "user": admin,
        "tickets": tickets
    })


@router.post("/admin/reply/{ticket_id}")
async def admin_reply(
    ticket_id: int,
    request: Request,
    admin_reply: str = Form(...),
    db: Session = Depends(get_db),
    admin=Depends(require_admin)
):
    ticket = db.query(SupportTicket).filter(SupportTicket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    ticket.admin_reply = admin_reply.strip()
    ticket.status = "in_progress"
    ticket.updated_at = datetime.now(timezone.utc)
    db.commit()
    return RedirectResponse("/support/admin", status_code=302)


@router.post("/admin/close/{ticket_id}")
async def admin_close(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_admin)
):
    ticket = db.query(SupportTicket).filter(SupportTicket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    ticket.status = "closed"
    ticket.is_resolved = True
    ticket.updated_at = datetime.now(timezone.utc)
    db.commit()
    return RedirectResponse("/support/admin", status_code=302)
