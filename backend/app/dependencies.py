"""
Block Bord AI — Shared FastAPI Dependencies
get_db, get_current_user, validate_csrf — injected across all routers.
"""
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.app.database.connection import SessionLocal

# Import models from root database.py (existing monolith — shared during migration)
from backend.app.models import User


# ──────────────────────────────────────────────────────────────
# DATABASE SESSION DEPENDENCY
# ──────────────────────────────────────────────────────────────
def get_db():
    """Yields a DB session and ensures it's closed after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────
# CURRENT USER DEPENDENCY
# ──────────────────────────────────────────────────────────────
def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """
    Resolves the current user via:
    1. Session cookie (browser users)
    2. X-API-Key or Bearer token (API / extension users)
    Returns None if not authenticated (use require_user for protected routes).
    """
    # 1. Session cookie
    user_id = request.session.get("user_id")
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            return user

    # 2. API Key / Bearer token
    api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "")
    if api_key.startswith("Bearer "):
        api_key = api_key[7:]
    if api_key:
        return db.query(User).filter(User.api_key == api_key).first()

    return None


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Strict version — raises 401 if not authenticated."""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user


def require_admin(request: Request, db: Session = Depends(get_db)) -> User:
    """Raises 403 if user is not authenticated or not an admin."""
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
    return user


# ──────────────────────────────────────────────────────────────
# CSRF VALIDATION DEPENDENCY
# ──────────────────────────────────────────────────────────────
import logging
csrf_logger = logging.getLogger("blockbord.csrf_val")

async def validate_csrf(request: Request, db: Session = Depends(get_db)):
    """
    Validates CSRF token on mutating requests (POST/PUT/PATCH/DELETE).
    Bypasses for:
    - Chrome extension requests (Origin: chrome-extension://)
    - Requests with a valid API Key
    """
    # Extension bypass
    origin = request.headers.get("Origin", "")
    bb_source = request.headers.get("X-BlockBord-Source", "")
    if origin.startswith("chrome-extension://") or bb_source == "extension":
        return

    # API key bypass
    api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "")
    if api_key.startswith("Bearer "):
        api_key = api_key[7:]
    if api_key:
        user = db.query(User).filter(User.api_key == api_key).first()
        if user:
            return

    # Check CSRF token from header or form
    token = request.headers.get("X-CSRF-Token")
    if not token and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            form = await request.form()
            token = form.get("csrf_token")
        except Exception as e:
            csrf_logger.warning(f"CSRF: Error parsing form data: {e}")
            token = None

    expected = request.session.get("csrf_token")
    if not expected or not token or token != expected:
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
