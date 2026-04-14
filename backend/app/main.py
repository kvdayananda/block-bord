"""
Block Bord AI — FastAPI Main Entry Point
Registers all modular routers, middleware, and exception handlers.
"""
import logging
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from backend.app.config import settings
from backend.app.middleware.security import SecurityHeadersMiddleware
from backend.app.middleware.csrf import CSRFTokenMiddleware
from backend.app.database.connection import engine, Base
from backend.app.routers import (
    auth, public, dashboard, scan, admin, payments, tools
)

# ──────────────────────────────────────────────────────────────
# LOGGING SETUP
# ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("blockbord")

# ──────────────────────────────────────────────────────────────
# LIFESPAN (Background tasks)
# ──────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup (only for simple dev/prod setup, Alembic used for migrations)
    # import backend.app.models # Ensure all models are loaded
    # Base.metadata.create_all(bind=engine)
    
    logger.info("Block Bord AI — Modular Backend started.")
    
    # Auto-retrain loop simulation (migrated from monolith)
    async def _auto_retrain_loop():
        while True:
            await asyncio.sleep(86400) # Daily
            logger.info("Triggering scheduled ML retrain...")
            # Logic here...
            
    # asyncio.create_task(_auto_retrain_loop())
    
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

# 1. CSRF Token Injection Middleware
app.add_middleware(CSRFTokenMiddleware)

# 2. Session Middleware (Required for auth + CSRF) - Outermost
app.add_middleware(
    SessionMiddleware, 
    secret_key=settings.session_secret,
    max_age=86400 * 30 # 30 days
)

# 3. Security Headers Middleware (Dynamic CSP)
app.add_middleware(SecurityHeadersMiddleware)

# 4. Rate Limiting Handler
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 5. Static Files & Templates (Updated to /frontend in Phase 3)
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

# Note: Routers will need to be updated to use "frontend/templates" or 
# we can define a global templates object in dependencies.py.
# For now, I'll update the router templates individually.


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
