from sqlalchemy import Column, Integer, Float, String, Text, ForeignKey, DateTime, Index
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.app.database.connection import Base

class ScanHistory(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(50), nullable=False)
    reasons = Column(Text, nullable=True)       # Stored as JSON string
    category = Column(String(100), nullable=True)
    scam_intent = Column(String(100), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="scans")

Index("idx_scans_user_created", ScanHistory.user_id, ScanHistory.created_at)
