"""
Block Bord AI — Bulk Scan Job Model
Tracks bulk URL scanning jobs submitted by premium users.
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.app.database.connection import Base


class BulkScanJob(Base):
    __tablename__ = "bulk_scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(20), default="pending")  # pending, running, done, failed
    total_urls = Column(Integer, default=0)
    completed_urls = Column(Integer, default=0)
    results_json = Column(Text, nullable=True)   # JSON array of results
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="bulk_scans")
