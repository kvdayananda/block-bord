"""
Block Bord AI — FastAPI Main Entry Point
Registers all modular routers, middleware, and exception handlers.
"""
import logging
import asyncio
import sentry_sdk
from contextlib import asynccontextmanager
from sentry_sdk.integrations.fastapi import FastApiIntegration

from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from backend.app.config import settings
from backend.app.middleware.security import SecurityHeadersMiddleware
from backend.app.middleware.csrf import CSRFTokenMiddleware
from backend.app.database.connection import engine, Base
from backend.app.utils.limiter import limiter
from backend.app.routers import (
    auth, public, dashboard, scan, admin, payments, tools
)
from backend.app import models # Ensure models are registered for Base.metadata.create_all


# ──────────────────────────────────────────────────────────────
# ERROR MONITORING (Sentry)
# ──────────────────────────────────────────────────────────────
if settings.sentry_dsn:
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        integrations=[FastApiIntegration()],
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
        environment=settings.env,
    )

# ──────────────────────────────────────────────────────────────
# LOGGING SETUP
# ──────────────────────────────────────────────────────────────
# Use a unified format, in production we could use a JSON formatter here
logging.basicConfig(
    level=logging.INFO if settings.is_production else logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("blockbord")

# ──────────────────────────────────────────────────────────────
# LIFESPAN (Background tasks)
# ──────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables if they don't exist
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    
    logger.info(f"Block Bord AI v{app.version} — Mode: {settings.env.upper()}")
    yield
    logger.info("Block Bord AI — Shutting down.")


# ──────────────────────────────────────────────────────────────
# APP INITIALIZATION
# ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="Block Bord AI",
    description="Cyber Intelligence for the Next Billion",
    version="2.0.0",
    lifespan=lifespan
)

# Set global limiter state
app.state.limiter = limiter

# 1. Rate Limiting Handler
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 2. CORS Middleware - Restrict to actual origins + Browser Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://localhost:3000",
        "https://blockbord.onrender.com" # Example production domain
    ],
    allow_origin_regex=r"chrome-extension://.*", # Dynamic allow for browser extension
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. CSRF Token Injection Middleware
app.add_middleware(CSRFTokenMiddleware)

# 4. Session Middleware (Required for auth + CSRF) - Outermost
app.add_middleware(
    SessionMiddleware, 
    secret_key=settings.session_secret,
    max_age=86400 * 30, # 30 days
    same_site="lax",
    https_only=settings.is_production
)

# 5. Security Headers Middleware (Dynamic CSP + HSTS)
app.add_middleware(SecurityHeadersMiddleware)

# 6. Static Files
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")


# ──────────────────────────────────────────────────────────────
# ROUTER REGISTRATION
# ──────────────────────────────────────────────────────────────
app.include_router(public.router)
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(scan.router)
app.include_router(admin.router)
app.include_router(payments.router)
app.include_router(tools.router)
