from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.app.database.connection import Base

class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", backref="feedback_items")

    label = Column(String(20), nullable=False)  # spam | ham
    content = Column(Text, nullable=False)

    source_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
