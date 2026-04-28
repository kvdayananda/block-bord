import pytest
from backend.app.models import User, ScanHistory

@pytest.fixture
def admin_user(db):
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
    admin = User(
        username="adminuser", 
        email="admin@example.com", 
        password=pwd_context.hash("adminpass"),
        is_admin=True,
        is_active=True
    )
    db.add(admin)
    db.commit()
    return admin

@pytest.fixture
def admin_client(client, admin_user):
    # Log in as admin to get session cookie
    response = client.post(
        "/login",
        data={"username": "adminuser", "password": "adminpass"},
        follow_redirects=False
    )
    return client

def test_admin_dashboard_access(admin_client):
    response = admin_client.get("/admin")
    assert response.status_code == 200
    assert b"Admin" in response.content

def test_admin_stats_api(admin_client, db, admin_user):
    scan = ScanHistory(user_id=admin_user.id, content="http://scam.com", risk_level="High", risk_score=90)
    db.add(scan)
    db.commit()
    
    response = admin_client.get("/admin/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total_scans"] >= 1
    assert data["high_risk_24h"] >= 1

def test_blacklist_add(admin_client, db):
    response = admin_client.post(
        "/admin/blacklist",
        data={"domain": "scammer.com", "reason": "Test reason"},
        headers={"X-BlockBord-Source": "extension"},
        follow_redirects=False
    )
    assert response.status_code == 303
    
    from backend.app.models import BlacklistDomain
    entry = db.query(BlacklistDomain).filter(BlacklistDomain.domain == "scammer.com").first()
    assert entry is not None
