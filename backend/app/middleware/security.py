"""
Block Bord AI — Security Headers Middleware
Sets dynamic CSP, HSTS, and other security headers.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse
from backend.app.config import settings

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # 1. HTTPS Redirection (Specifically for production behind a proxy like Render)
        if settings.is_production:
            # Render/Heroku/AWS use X-Forwarded-Proto
            proto = request.headers.get("x-forwarded-proto")
            if proto == "http":
                url = request.url.replace(scheme="https")
                return RedirectResponse(str(url), status_code=301)

        response = await call_next(request)
        
        # 2. Content Security Policy (CSP)
        # Tightened to allow self, Google Fonts, and the configured backend URL
        # Added sandbox for extra protection
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://checkout.razorpay.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            f"connect-src 'self' {settings.backend_url} https://safebrowsing.googleapis.com; "
            "img-src 'self' data: https://*; "
            "frame-src 'self' https://checkout.razorpay.com; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        
        # 3. Strict-Transport-Security (HSTS) - 1 year
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        
        # 4. Prevent Clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # 5. Prevent MIME-type Sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # 6. Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # 7. Permissions Policy (Restrict dangerous APIs)
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"

        return response
