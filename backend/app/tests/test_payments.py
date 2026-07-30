# test_payments endpoints

import pytest
from fastapi import status
from backend.app.config import settings
from backend.app.models import User, Payment
from sqlalchemy.orm import Session

# Helper to create a test user in the DB
@pytest.fixture
def test_user(db: Session):
    user = User(username="testuser", email="test@example.com", hashed_password="hashed", plan="free", is_pro=False)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def test_pricing_page(client, test_user):
    response = client.get("/pricing")
    assert response.status_code == status.HTTP_200_OK
    # Simple check that the rendered page contains a known string
    assert "Pricing" in response.text

def test_checkout_test_mode(monkeypatch, client, test_user):
    # Force non‑production and test mode
    monkeypatch.setattr(settings, "is_production", False)
    monkeypatch.setattr(settings, "payment_test_mode", True)
    # Ensure razorpay is None to trigger test‑mode branch
    monkeypatch.setattr("backend.app.routers.payments.razorpay", None)

    response = client.get(f"/checkout/starter", allow_redirects=False)
    # Should redirect to app with success message
    assert response.status_code == status.HTTP_302_FOUND
    assert "/app?message=Plan upgraded successfully (Test Mode)" in response.headers["location"]

def test_verify_payment_signature(monkeypatch, client, db: Session, test_user):
    # Set up a mock payment record
    payment = Payment(
        user_id=test_user.id,
        plan="starter",
        amount=9900,
        razorpay_order_id="order_123",
        status="created",
    )
    db.add(payment)
    db.commit()
    db.refresh(payment)

    # Mock settings for secret
    monkeypatch.setattr(settings, "razorpay_key_secret", "secretkey")

    # Build a valid signature
    order_id = payment.razorpay_order_id
    payment_id = "pay_456"
    data = f"{order_id}|{payment_id}"
    import hmac, hashlib
    signature = hmac.new(settings.razorpay_key_secret.encode(), data.encode(), hashlib.sha256).hexdigest()

    response = client.post(
        "/payment/verify",
        data={
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature,
        },
        allow_redirects=False,
    )
    assert response.status_code == status.HTTP_302_FOUND
    assert "/app?message=Subscription active!" in response.headers["location"]
    # Verify payment status updated
    db.refresh(payment)
    assert payment.status == "paid"
    # Verify user plan upgraded
    db.refresh(test_user)
    assert test_user.plan == "starter"
    assert test_user.is_pro is False

def test_downgrade_plan(monkeypatch, client, db: Session, test_user):
    # Upgrade user first
    test_user.plan = "pro"
    test_user.is_pro = True
    db.commit()
    response = client.post("/downgrade", allow_redirects=False)
    assert response.status_code == status.HTTP_302_FOUND
    assert "/app?message=Plan downgraded to Community successfully" in response.headers["location"]
    db.refresh(test_user)
    assert test_user.plan == "free"
    assert test_user.is_pro is False
