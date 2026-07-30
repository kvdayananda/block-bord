from datetime import datetime, timedelta, timezone

import pytest
from backend.app.models import User
from backend.app.models.report import EmailVerificationToken

def test_register_success(client):
    response = client.post(
        "/register",
        data={"username": "testuser", "email": "test@example.com", "password": "Password123!@#"},
        follow_redirects=False
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/app"

def test_login_success(client, db):
    # Setup: create a user
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
    user = User(username="loginuser", email="login@example.com", password=pwd_context.hash("secret123"))
    db.add(user)
    db.commit()

    response = client.post(
        "/login",
        data={"username": "loginuser", "password": "secret123"},
        follow_redirects=False
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/app"

def test_login_fail(client):
    response = client.post(
        "/login",
        data={"username": "nonexistent", "password": "wrongpassword"},
        follow_redirects=False
    )
    assert response.status_code == 200 # Should return login page with error
    assert b"Invalid credentials" in response.content


def test_register_creates_verification_token(client, db, monkeypatch):
    sent = {}

    def fake_send_verification_email(email, verification_link):
        sent["email"] = email
        sent["link"] = verification_link

    monkeypatch.setattr("backend.app.routers.auth.send_verification_email", fake_send_verification_email)

    response = client.post(
        "/register",
        data={"username": "verifyuser", "email": "verify@example.com", "password": "Password123!@#"},
        follow_redirects=False
    )

    assert response.status_code == 302
    user = db.query(User).filter(User.username == "verifyuser").one()
    token = db.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == user.id).order_by(EmailVerificationToken.created_at.desc()).first()
    assert token is not None
    assert sent["email"] == "verify@example.com"
    assert sent["link"].endswith(f"/verify-email/{token.token}")


def test_verify_email_token_marks_user_verified(client, db):
    user = User(username="verifyme", email="verifyme@example.com", password="hashed")
    db.add(user)
    db.commit()
    db.refresh(user)

    token = EmailVerificationToken(
        token="abc123",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(token)
    db.commit()

    response = client.get("/verify-email/abc123", follow_redirects=False)

    assert response.status_code == 302
    db.refresh(user)
    assert user.is_email_verified is True
    db.refresh(token)
    assert token.used is True
