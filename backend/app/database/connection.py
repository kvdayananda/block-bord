"""
Block Bord AI — Database Connection
Single source of truth for engine, SessionLocal, and Base.
All models import Base from here to register with the same metadata.
"""
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.config import settings

logger = logging.getLogger("blockbord.db")

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
        "pool_timeout": 30,      # Timeout after 30s
        "pool_recycle": 1200,    # Recycle connections before serverless idle limits
    })

def create_db_engine(url, kwargs):
    return create_engine(url, **kwargs)

# Primary Engine Creation
try:
    engine = create_db_engine(DATABASE_URL, engine_kwargs)
    # Test initial connectivity if PostgreSQL
    if not is_sqlite:
        with engine.connect() as conn:
            pass
except Exception as err:
    if not settings.is_production:
        logger.warning(
            f"Unable to connect to primary database ({err}). "
            "Falling back to local SQLite database (sqlite:///./blockbord_dev.db)..."
        )
        DATABASE_URL = "sqlite:///./blockbord_dev.db"
        is_sqlite = True
        engine_kwargs = {
            "connect_args": {"check_same_thread": False},
            "pool_pre_ping": True,
            "future": True,
        }
        engine = create_db_engine(DATABASE_URL, engine_kwargs)
    else:
        raise err

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()
