"""
Block Bord AI — Database Connection
Single source of truth for engine, SessionLocal, and Base.
All models import Base from here to register with the same metadata.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Read DATABASE_URL (already loaded via .env in main.py)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./blockbord.db")

# Normalize postgres:// → postgresql:// (Heroku/Neon compatibility)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

is_sqlite = DATABASE_URL.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {}

engine_kwargs: dict = {
    "connect_args": connect_args,
    "pool_pre_ping": True,
    "future": True,
}

# PostgreSQL pooling — optimized for Neon serverless
if not is_sqlite:
    engine_kwargs.update({
        "pool_size": 5,
        "max_overflow": 10,
        "pool_timeout": 30,
        "pool_recycle": 1800,
    })

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()
