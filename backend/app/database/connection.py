"""
Block Bord AI — Database Connection
Single source of truth for engine, SessionLocal, and Base.
All models import Base from here to register with the same metadata.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.config import settings

# Use URL from settings (loaded from .env)
DATABASE_URL = settings.database_url

# Normalize postgres:// → postgresql:// (Heroku/Neon compatibility)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

is_sqlite = DATABASE_URL.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {}

# ──────────────────────────────────────────────────────────────
# ENGINE CONFIGURATION
# ──────────────────────────────────────────────────────────────
# pool_pre_ping=True is CRITICAL for serverless DBs like Neon/Heroku
# It checks the connection health before every request.
engine_kwargs: dict = {
    "connect_args": connect_args,
    "pool_pre_ping": True, 
    "future": True,
}

if is_sqlite and DATABASE_URL == "sqlite:///:memory:":
    engine_kwargs["poolclass"] = StaticPool

if not is_sqlite:
    engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "pool_timeout": 60,      # Give more time for DNS resolution
        "pool_recycle": 1200,    # Recycle connections before they are killed by serverless idle limits
    })

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()
