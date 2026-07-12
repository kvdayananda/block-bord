"""
Block Bord AI — Auth Router
Routes: /login, /register, /logout, /forgot-password, /reset-password/{token}
"""
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from backend.app.utils.limiter import limiter
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db, validate_csrf
from backend.app.config import settings
from backend.app.models import User, PasswordResetToken
from backend.app.models.report import EmailVerificationToken
from backend.app.services.email_service import send_password_reset_email, send_verification_email


logger = logging.getLogger("blockbord.auth")
router = APIRouter(tags=["Auth"])
templates = Jinja2Templates(directory="frontend/templates")
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def validate_password_strength(password: str) -> Optional[str]:
    """
    Returns an error message string if password is weak, otherwise None.
    Complexity requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 12:
        return "Password must be at least 12 characters long."
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number."
    special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
    if not any(c in special_chars for c in password):
        return "Password must contain at least one special character."
    return None


# ──────────────────────────────────────────────────────────────
# REGISTER
# ──────────────────────────────────────────────────────────────
@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@router.post("/register")
@limiter.limit("5/minute")
def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    username = username.strip()
    email = email.strip().lower()

    # Validate password strength
    pwd_err = validate_password_strength(password)
    if pwd_err:
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": pwd_err}
        )

    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": "Username already taken."}
        )
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": "Email already registered."}
        )

    new_user = User(
        username=username,
        email=email,
        password=pwd_context.hash(password),
        is_pro=False,
        plan="free",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Auto-login after registration
    request.session["user_id"] = new_user.id
    logger.info(f"New user registered: {username} ({email})")
    return RedirectResponse("/app", status_code=302)


# ──────────────────────────────────────────────────────────────
# LOGIN
# ──────────────────────────────────────────────────────────────
@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    message = request.query_params.get("message")
    return templates.TemplateResponse("login.html", {"request": request, "message": message})


@router.post("/login")
@limiter.limit("10/minute")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    username = username.strip()
    user = db.query(User).filter(User.username == username).first()

    if user and pwd_context.verify(password, user.password):
        if not user.is_active:
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Your account has been suspended. Contact support."},
            )
        request.session["user_id"] = user.id
        request.session["username"] = user.username
        logger.info(f"User logged in: {username}")
        return RedirectResponse("/app", status_code=302)

    logger.warning(f"Failed login attempt for username: {username}")
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": "Invalid credentials"}
    )


# ──────────────────────────────────────────────────────────────
# LOGOUT
# ──────────────────────────────────────────────────────────────
@router.get("/logout")
def logout(request: Request):
    username = request.session.get("username", "unknown")
    request.session.clear()
    logger.info(f"User logged out: {username}")
    return RedirectResponse("/", status_code=302)

@router.post("/verify-email")
@limiter.limit("5/minute")
def verify_email(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    """Placeholder email verification endpoint."""
    # In production, send verification email with token.
    logger.info(f"Email verification requested for {email}")
    return {"detail": "Verification email sent (simulated)."}


# ──────────────────────────────────────────────────────────────
# FORGOT PASSWORD
# ──────────────────────────────────────────────────────────────
@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})


@router.post("/forgot-password")
@limiter.limit("3/minute")
def forgot_password(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
    _csrf: None = Depends(validate_csrf),
):
    email = email.strip().lower()
    is_prod = settings.is_production
    user = db.query(User).filter(User.email == email).first()

    token = None
    if user:
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        # Invalidate old tokens
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used == False,
        ).update({"used": True})

        db.add(PasswordResetToken(token=token, user_id=user.id, expires_at=expires_at))
        db.commit()

        reset_link = f"{request.base_url}reset-password/{token}"
        if not is_prod:
            logger.info(f"[DEV] Password reset link for {user.username}: {reset_link}")

    msg = "If an account exists with that email, a reset link has been sent."
    if not is_prod and token and user:
        reset_link = f"{request.base_url}reset-password/{token}"
        msg += f" (Dev mode — Link: {reset_link})"

    return templates.TemplateResponse("forgot_password.html", {"request": request, "message": msg})


# ──────────────────────────────────────────────────────────────
# RESET PASSWORD
# ──────────────────────────────────────────────────────────────
@router.get("/reset-password/{token}", response_class=HTMLResponse)
def reset_password_page(request: Request, token: str, db: Session = Depends(get_db)):
    reset_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == token,
        PasswordResetToken.used == False,
        PasswordResetToken.expires_at > datetime.now(timezone.utc),
    ).first()

    if not reset_token:
        return templates.TemplateResponse(
            "forgot_password.html", {"request": request, "error": "Invalid or expired reset link."}
        )
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})


@router.post("/reset-password/{token}")
def reset_password(
    request: Request,
    token: str,
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
    _csrf: None = Depends(validate_csrf),
):
    if password != confirm_password:
        return templates.TemplateResponse(
            "reset_password.html",
            {"request": request, "token": token, "error": "Passwords do not match."},
        )

    pwd_err = validate_password_strength(password)
    if pwd_err:
        return templates.TemplateResponse(
            "reset_password.html",
            {"request": request, "token": token, "error": pwd_err},
        )

    reset_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == token,
        PasswordResetToken.used == False,
        PasswordResetToken.expires_at > datetime.now(timezone.utc),
    ).first()

    if not reset_token:
        return RedirectResponse("/forgot-password", status_code=302)

    user = db.query(User).filter(User.id == reset_token.user_id).first()
    if not user:
        return RedirectResponse("/forgot-password", status_code=302)

    user.password = pwd_context.hash(password)
    reset_token.used = True
    db.commit()
    logger.info(f"Password reset successful for user: {user.username}")
    return RedirectResponse("/login?message=Password reset successful. Please log in.", status_code=302)
