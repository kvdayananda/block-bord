from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.app.database.connection import Base

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
