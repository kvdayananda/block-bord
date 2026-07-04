import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.models import User
from backend.app.database.connection import SessionLocal

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture(autouse=True)
def mock_ai_service(monkeypatch):
    from backend.app.routers.ai_tools import service
    
    async def mock_detect_scam(input_text):
        return {"verdict": "Scam", "reason": "Simulated scam detection response", "raw": {}}
        
    async def mock_chat_assistant(query):
        return {"answer": "Simulated assistant response", "raw": {}}
        
    async def mock_explain_risk(payload):
        return {"explanation": "Simulated risk explanation", "raw": {}}
        
    monkeypatch.setattr(service, "detect_scam", mock_detect_scam)
    monkeypatch.setattr(service, "chat_assistant", mock_chat_assistant)
    monkeypatch.setattr(service, "explain_risk", mock_explain_risk)

@pytest.fixture
def normal_user_session(client):
    # Create or retrieve a test user from database
    db = SessionLocal()
    user = db.query(User).filter(User.username == "test_normal").first()
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
    hashed_pwd = pwd_context.hash("password123")
    
    if not user:
        user = User(
            username="test_normal",
            email="test_normal@gmail.com",
            password=hashed_pwd,
            is_pro=False,
            plan="free"
        )
        db.add(user)
    else:
        user.password = hashed_pwd
    db.commit()
    db.refresh(user)
    
    # Simulate login by submitting POST to /login to set session cookies
    client.post(
        "/login",
        data={"username": "test_normal", "password": "password123"},
        follow_redirects=False
    )
    db.close()
    yield user

@pytest.fixture
def pro_user_session(client):
    db = SessionLocal()
    user = db.query(User).filter(User.username == "test_pro").first()
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
    hashed_pwd = pwd_context.hash("password123")
    
    if not user:
        user = User(
            username="test_pro",
            email="test_pro@gmail.com",
            password=hashed_pwd,
            is_pro=True,
            plan="pro"
        )
        db.add(user)
    else:
        user.password = hashed_pwd
        user.plan = "pro"
        user.is_pro = True
    db.commit()
    db.refresh(user)
        
    client.post(
        "/login",
        data={"username": "test_pro", "password": "password123"},
        follow_redirects=False
    )
    db.close()
    yield user

def test_security_suite_page(client, normal_user_session):
    response = client.get("/security")
    assert response.status_code == 200
    assert b"Security Suite" in response.content

def test_ai_hub_page(client, normal_user_session):
    response = client.get("/ai")
    assert response.status_code == 200
    assert b"AI Threat Hub" in response.content

def test_url_scan_api(client, normal_user_session):
    response = client.post("/security/api/scan-url", data={"url": "https://phishing-test-site.com"})
    assert response.status_code == 200
    data = response.json()
    assert "url" in data
    assert "malicious" in data
    assert "risk_score" in data

def test_domain_whois_api(client, normal_user_session):
    response = client.post("/security/api/lookup-domain", data={"domain": "google.com"})
    assert response.status_code == 200
    data = response.json()
    assert "domain" in data
    assert "registered" in data

def test_ip_reputation_api(client, normal_user_session):
    response = client.post("/security/api/check-ip", data={"ip": "8.8.8.8"})
    assert response.status_code == 200
    data = response.json()
    assert "ip" in data
    assert "abuse_score" in data

def test_email_breach_api(client, normal_user_session):
    response = client.post("/security/api/check-email", data={"email": "leak-test@gmail.com"})
    assert response.status_code == 200
    data = response.json()
    assert "email" in data
    assert "breached" in data

def test_password_strength_api(client, normal_user_session):
    response = client.post("/security/api/check-password", data={"password": "Password123!"})
    assert response.status_code == 200
    data = response.json()
    assert "breached" in data
    assert "strength" in data

def test_gated_ssl_analyzer_free_user(client, normal_user_session):
    # Free user should get 403 Forbidden
    response = client.post("/security/api/analyze-ssl", data={"hostname": "github.com"})
    assert response.status_code == 403

def test_gated_ssl_analyzer_pro_user(client, pro_user_session):
    # Pro user should succeed
    response = client.post("/security/api/analyze-ssl", data={"hostname": "github.com"})
    assert response.status_code == 200
    data = response.json()
    assert "hostname" in data
    assert "valid" in data

def test_gated_dns_lookup_free_user(client, normal_user_session):
    response = client.post("/security/api/dns-lookup", data={"hostname": "microsoft.com"})
    assert response.status_code == 403

def test_gated_dns_lookup_pro_user(client, pro_user_session):
    response = client.post("/security/api/dns-lookup", data={"hostname": "microsoft.com"})
    assert response.status_code == 200
    data = response.json()
    assert "hostname" in data
    assert "records" in data

def test_scam_detector_ai_api(client, normal_user_session):
    # Mock behavior checks or actual API if keys configured
    response = client.post("/ai/api/scam", json={"input_text": "Verify your bank details at http://fake-link.com"})
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert "reason" in data

def test_assistant_ai_api(client, normal_user_session):
    response = client.post("/ai/api/assistant", json={"message": "What is phishing?"})
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data

def test_risk_explainer_ai_free_user(client, normal_user_session):
    response = client.post("/ai/api/risk", json={"payload": {"risk_score": 85}})
    assert response.status_code == 403

def test_risk_explainer_ai_pro_user(client, pro_user_session):
    response = client.post("/ai/api/risk", json={"payload": {"risk_score": 85}})
    assert response.status_code == 200
    data = response.json()
    assert "explanation" in data
