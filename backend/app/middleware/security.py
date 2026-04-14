"""
Block Bord AI — Security Headers Middleware
Sets dynamic CSP, HSTS, and other security headers.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from backend.app.config import settings

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # 1. Content Security Policy (CSP)
        # Allows self, Google Fonts, and the configured backend URL
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://checkout.razorpay.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com; "
            f"connect-src 'self' {settings.backend_url} https://safebrowsing.googleapis.com; "
            "img-src 'self' data: https://*; "
            "frame-src 'self' https://checkout.razorpay.com;"
        )
        response.headers["Content-Security-Policy"] = csp
        
        # 2. Strict-Transport-Security (HSTS) - 1 year
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # 3. Prevent Clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # 4. Prevent MIME-type Sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # 5. Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # 6. Permissions Policy (Restrict dangerous APIs)
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response
