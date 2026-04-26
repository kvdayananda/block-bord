import pytest
from backend.app.models import User

def test_register_success(client):
    response = client.post(
        "/register",
        data={"username": "testuser", "email": "test@example.com", "password": "password123"},
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
