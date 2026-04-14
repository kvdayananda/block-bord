"""
Block Bord AI — CSRF Middleware (Modular)
Injects a CSRF token into session on every request.
Validation is handled as a FastAPI dependency (see dependencies.py).
"""
import secrets
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("blockbord.csrf")

class CSRFTokenMiddleware(BaseHTTPMiddleware):
    """Ensures a CSRF token exists in the session on every request."""

    async def dispatch(self, request: Request, call_next):
        try:
            if "csrf_token" not in request.session:
                request.session["csrf_token"] = secrets.token_urlsafe(32)
        except Exception:
            pass
        
        return await call_next(request)
