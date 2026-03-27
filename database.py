import os
from datetime import datetime

from sqlalchemy import DateTime


from sqlalchemy import Column, Integer, String, Boolean, DateTime



created_at = Column(DateTime, default=datetime.utcnow)

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
    text,
    Index,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# ---------------- DATABASE CONFIG ----------------

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./blockbord.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()

# ---------------- USER TABLE ----------------


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

    created_at = Column(DateTime, default=datetime.utcnow)  # ✅ CORRECT PLACE
    

    scans = relationship(
        "ScanHistory", back_populates="user", cascade="all, delete-orphan"
    )
    payments = relationship(
        "Payment", back_populates="user", cascade="all, delete-orphan"
    )


# ---------------- SCAN HISTORY TABLE ----------------


class ScanHistory(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    content = Column(Text, nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(50), nullable=False)
    reasons = Column(Text, nullable=True)       # stored as JSON string
    category = Column(String(100), nullable=True)  # e.g. "UPI Scam", "Brand Impersonation"

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="scans")


Index("idx_scans_user_created", ScanHistory.user_id, ScanHistory.created_at)


# ---------------- PAYMENTS TABLE ----------------


class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="payments")

    plan = Column(String(50), nullable=False)  # starter | pro | business
    amount = Column(Integer, nullable=False)  # paise
    currency = Column(String(10), default="INR")

    razorpay_order_id = Column(String(255), nullable=False, index=True)
    razorpay_payment_id = Column(String(255), nullable=True)
    razorpay_signature = Column(String(255), nullable=True)

    status = Column(String(50), default="created")  # created | paid | failed
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# ---------------- FEEDBACK TABLE ----------------


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", backref="feedback_items")

    label = Column(String(20), nullable=False)  # spam | ham
    content = Column(Text, nullable=False)

    source_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# ---------------- BLACKLIST TABLE ----------------

class BlacklistDomain(Base):
    __tablename__ = "blacklist_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    added_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    reason = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# ---------------- WHITELIST TABLE ----------------

class WhitelistDomain(Base):
    __tablename__ = "whitelist_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    added_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    reason = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# ---------------- USER REPORTS TABLE ----------------

class UserReport(Base):
    __tablename__ = "user_reports"

    id = Column(Integer, primary_key=True, index=True)
    reported_url = Column(String(1000), nullable=False)
    reported_domain = Column(String(255), nullable=True, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(50), default="pending")  # pending | reviewed | confirmed | dismissed
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", backref="reports")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# ---------------- PASSWORD RESET TABLE ----------------

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", backref="reset_tokens")


# ---------------- CREATE TABLES ----------------


Base.metadata.create_all(bind=engine)


# ---------------- SIMPLE SQLITE MIGRATIONS ----------------
def run_migrations():
    """Lightweight SQLite migration support (safe for production boot)."""
    if not DATABASE_URL.startswith("sqlite"):
        return
    try:
        with engine.connect() as conn:
            cols = [
                r[1]
                for r in conn.execute(text("PRAGMA table_info(users)")).fetchall()
            ]
            if "plan" not in cols:
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN plan VARCHAR DEFAULT 'free'")
                )
            if "is_admin" not in cols:
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0")
                )
            if "api_key" not in cols:
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN api_key VARCHAR(100) UNIQUE")
                )
            conn.commit()
    except Exception:
        pass


run_migrations()