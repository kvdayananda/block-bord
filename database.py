import os
from datetime import datetime, timezone

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Boolean,
    ForeignKey,
    Text,
    Index,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# ──────────────────────────────────────────────────────────────
# DATABASE CONFIG
# ──────────────────────────────────────────────────────────────
# Production: Neon PostgreSQL (set DATABASE_URL in .env)
# Dev fallback: SQLite (only for local testing without Neon)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./blockbord.db")

# psycopg2 requires "postgresql://" — fix Heroku/Neon "postgres://" prefix if needed
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# PostgreSQL-specific engine args (connection pooling for Neon serverless)
is_sqlite = DATABASE_URL.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {}
engine_kwargs = {
    "connect_args": connect_args,
    "pool_pre_ping": True,  # Test connections before use (handles Neon cold starts)
    "future": True,
}

# For PostgreSQL (Neon): use NullPool to prevent connection exhaustion on serverless
if not is_sqlite:
    engine_kwargs["pool_size"] = 5
    engine_kwargs["max_overflow"] = 10
    engine_kwargs["pool_timeout"] = 30
    engine_kwargs["pool_recycle"] = 1800  # Recycle after 30min (Neon idle timeout)

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()


# ──────────────────────────────────────────────────────────────
# USER TABLE
# ──────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)

    is_active = Column(Boolean, default=True)
    is_pro = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    plan = Column(String, default="free")
    api_key = Column(String(100), unique=True, index=True, nullable=True)

    # Use timezone-aware UTC (PEP 495 — datetime.utcnow() deprecated in Python 3.12)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scans = relationship(
        "ScanHistory", back_populates="user", cascade="all, delete-orphan"
    )
    payments = relationship(
        "Payment", back_populates="user", cascade="all, delete-orphan"
    )


# ──────────────────────────────────────────────────────────────
# SCAN HISTORY TABLE
# ──────────────────────────────────────────────────────────────
class ScanHistory(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(50), nullable=False)
    reasons = Column(Text, nullable=True)       # stored as JSON string
    category = Column(String(100), nullable=True)
    scam_intent = Column(String(100), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="scans")


Index("idx_scans_user_created", ScanHistory.user_id, ScanHistory.created_at)


# ──────────────────────────────────────────────────────────────
# PAYMENTS TABLE
# ──────────────────────────────────────────────────────────────
class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="payments")

    plan = Column(String(50), nullable=False)   # starter | pro | business
    amount = Column(Integer, nullable=False)    # paise (INR)
    currency = Column(String(10), default="INR")

    razorpay_order_id = Column(String(255), nullable=False, index=True)
    razorpay_payment_id = Column(String(255), nullable=True)
    razorpay_signature = Column(String(255), nullable=True)

    status = Column(String(50), default="created")  # created | paid | failed
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


# ──────────────────────────────────────────────────────────────
# FEEDBACK TABLE
# ──────────────────────────────────────────────────────────────
class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", backref="feedback_items")

    label = Column(String(20), nullable=False)  # spam | ham
    content = Column(Text, nullable=False)

    source_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


# ──────────────────────────────────────────────────────────────
# BLACKLIST TABLE
# ──────────────────────────────────────────────────────────────
class BlacklistDomain(Base):
    __tablename__ = "blacklist_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    added_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    reason = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


# ──────────────────────────────────────────────────────────────
# WHITELIST TABLE
# ──────────────────────────────────────────────────────────────
class WhitelistDomain(Base):
    __tablename__ = "whitelist_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    added_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    reason = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


# ──────────────────────────────────────────────────────────────
# USER REPORTS TABLE
# ──────────────────────────────────────────────────────────────
class UserReport(Base):
    __tablename__ = "user_reports"

    id = Column(Integer, primary_key=True, index=True)
    reported_url = Column(String(1000), nullable=False)
    reported_domain = Column(String(255), nullable=True, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(50), default="pending")  # pending | reviewed | confirmed | dismissed
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", backref="reports")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


# ──────────────────────────────────────────────────────────────
# PASSWORD RESET TOKENS TABLE
# ──────────────────────────────────────────────────────────────
class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", backref="reset_tokens")


# ──────────────────────────────────────────────────────────────
# INITIALISE TABLES
# Creates all tables in Neon PostgreSQL if they don't exist.
# For production schema changes, use Alembic migrations (Phase 6).
# ──────────────────────────────────────────────────────────────
Base.metadata.create_all(bind=engine)