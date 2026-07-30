"""
Block Bord AI — FastAPI Main Entry Point
Registers all modular routers, middleware, and exception handlers.
"""
import logging
import asyncio
import sentry_sdk
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from sentry_sdk.integrations.fastapi import FastApiIntegration

from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy.exc import OperationalError
from fastapi.responses import JSONResponse

from backend.app.config import settings
from backend.app.middleware.security import SecurityHeadersMiddleware
from backend.app.middleware.csrf import CSRFTokenMiddleware
from backend.app.database.connection import engine, Base
from backend.app.utils.limiter import limiter
from sqlalchemy.orm import Session
from backend.app.dependencies import get_db
from backend.app.routers import (
    auth, public, dashboard, scan, admin, payments, tools, security_tools, ai_tools, password, bulk, support, ai_assistant
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
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("blockbord")

# Silence noisy external loggers
logging.getLogger("python_multipart").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# ──────────────────────────────────────────────────────────────
# LIFESPAN (Background tasks)
# ──────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.is_production and settings.database_url.startswith("sqlite"):
        logger.error("CRITICAL CONFIGURATION ERROR: SQLite database is not allowed in production mode. Use a PostgreSQL database instead.")
        raise ValueError("SQLite database is not allowed in production mode.")

    # Initialize database tables if they don't exist (with retry logic)
    max_retries = 5
    for i in range(max_retries):
        try:
            logger.info(f"Initializing database tables (Attempt {i+1}/{max_retries})...")
            Base.metadata.create_all(bind=engine)
            logger.info("Database tables initialized successfully.")
            break
        except Exception as e:
            if i < max_retries - 1:
                logger.warning(f"DB Connection failed: {e}. Retrying in 5s...")
                import time
                time.sleep(5)
            else:
                logger.error("CRITICAL: Database initialization failed after all retries.")
    
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

# 2. Global Database Error Handler (Neon/Postgres Down)
@app.exception_handler(OperationalError)
async def db_exception_handler(request: Request, exc: OperationalError):
    logger.error(f"DATABASE ERROR: {exc}")
    return JSONResponse(
        status_code=503,
        content={"error": "Database temporarily unavailable. Please try again in a few moments."},
    )

# 3. Generic Exception Fallback
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"UNEXPECTED ERROR: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "An internal server error occurred. Our team has been notified."},
    )

# 2. CORS Middleware - Restrict to configured origins + Browser Extension
if settings.is_production:
    cors_origins = [origin.strip() for origin in settings.cors_allowed_origins_prod.split(",") if origin.strip()]
else:
    cors_origins = [origin.strip() for origin in settings.cors_allowed_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
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

# Serve favicon to avoid 404 errors
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("frontend/static/favicon.ico", media_type="image/x-icon")


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
app.include_router(security_tools.router)
app.include_router(ai_tools.router)
app.include_router(password.router)
app.include_router(bulk.router)
app.include_router(support.router)
app.include_router(ai_assistant.router)


# ──────────────────────────────────────────────────────────────
# WEBSOCKET THREAT FEED (Real-time admin broadcast)
# ──────────────────────────────────────────────────────────────
from fastapi import WebSocket, WebSocketDisconnect
from backend.app.utils.broadcaster import broadcaster

@app.websocket("/ws/threat-feed")
async def websocket_threat_feed(websocket: WebSocket):
    await broadcaster.connect(websocket)
    try:
        while True:
            # Maintain connection, read messages if sent (though it's unidirectional)
            await websocket.receive_text()
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)



# ──────────────────────────────────────────────────────────────
# HEALTH ENDPOINT
# ──────────────────────────────────────────────────────────────
@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    from sqlalchemy import text
    try:
        # Verify database connection is functional
        db.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        logger.error(f"Health check database query failed: {e}")
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "database": "disconnected"}
        )
