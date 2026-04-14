import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Secure headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

        # SECURITY FIX: CSP connect-src is now dynamic (reads BACKEND_URL from env).
        # In production, set BACKEND_URL=https://your-app.onrender.com in .env
        backend_url = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
        # Also allow localhost for local dev regardless of BACKEND_URL setting
        connect_src = (
            f"'self' {backend_url} http://127.0.0.1:8000 http://localhost:8000 "
            "chrome-extension://* https://safebrowsing.googleapis.com"
        )

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data: https:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            f"connect-src {connect_src}; "
            "frame-ancestors 'none'"
        )

        return response