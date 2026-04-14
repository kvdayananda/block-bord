from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.app.database.connection import Base

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

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scans = relationship("ScanHistory", back_populates="user", cascade="all, delete-orphan")
    payments = relationship("Payment", back_populates="user", cascade="all, delete-orphan")
