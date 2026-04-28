import pytest
from backend.app.models import User, ScanHistory
import json

@pytest.fixture
def test_user(db):
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
    user = User(
        username="scanuser", 
        email="scan@example.com", 
        password=pwd_context.hash("scanpass"),
        is_active=True
    )
    db.add(user)
    db.commit()
    return user

@pytest.fixture
def auth_client(client, test_user):
    client.post(
        "/login",
        data={"username": "scanuser", "password": "scanpass"},
        follow_redirects=False
    )
    return client

def test_scan_endpoint_unauthorized(client):
    response = client.post("/scan", json={"content": "http://google.com"}, headers={"X-BlockBord-Source": "extension"})
    assert response.status_code == 401

def test_scan_endpoint_authorized(auth_client, db, test_user):
    from unittest.mock import patch, AsyncMock
    
    with patch('backend.app.routers.scan.calculate_risk', new_callable=AsyncMock) as mock_calc:
        mock_calc.return_value = {
            "risk_score": 10.0,
            "risk_level": "OK",
            "reasons": ["Safe"],
            "category": "General"
        }

        response = auth_client.post(
            "/scan", 
            json={"content": "http://google.com"},
            headers={"X-BlockBord-Source": "extension"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["risk_level"] == "OK"
        assert "scan_id" in data
        
        scan = db.query(ScanHistory).filter(ScanHistory.id == data["scan_id"]).first()
        assert scan is not None
        assert scan.user_id == test_user.id
        assert scan.risk_level == "OK"

def test_scan_detail_page(auth_client, db, test_user):
    scan = ScanHistory(user_id=test_user.id, content="test", risk_level="OK", risk_score=0)
    db.add(scan)
    db.commit()
    
    response = auth_client.get(f"/scan/{scan.id}")
    assert response.status_code == 200
    assert b"Insights" in response.content
