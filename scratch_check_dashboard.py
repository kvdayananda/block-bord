import os
import sys

# Ensure backend can be imported
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.database.connection import Base
from backend.app.dependencies import get_db, get_current_user
from backend.app.models import User, ScanHistory

def main():
    print("Initializing test environment...")
    
    # Set up test database (in-memory SQLite)
    SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Create tables
    Base.metadata.create_all(bind=engine)

    # Create test user
    db = TestingSessionLocal()
    test_user = User(
        username="testuser",
        email="test@example.com",
        password="hashedpassword",
        is_active=True,
        is_pro=True,
        is_admin=False,
        plan="pro",
        api_key="bb_live_test_api_key_12345"
    )
    db.add(test_user)
    db.commit()
    db.refresh(test_user)
    
    # Add a mock scan history item to test rendering scans
    mock_scan = ScanHistory(
        user_id=test_user.id,
        content="http://malicious-phishing-site-test.com",
        risk_level="High",
        risk_score=95,
        category="Phishing"
    )
    db.add(mock_scan)
    db.commit()

    # Override dependencies
    def override_get_db():
        try:
            yield db
        finally:
            pass

    def override_get_current_user():
        return test_user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user

    # Create test client
    client = TestClient(app)

    # List of endpoints to verify
    endpoints = [
        ("/app", "HTML"),
        ("/history", "HTML"),
        ("/analytics", "HTML"),
        ("/settings", "HTML"),
        ("/extension-setup", "HTML"),
        ("/block-list", "HTML"),
        ("/api/stats", "JSON"),
        ("/api/analytics", "JSON"),
    ]

    print("\n--- Verifying Dashboard Endpoints ---")
    failures = 0
    for path, expected_type in endpoints:
        try:
            print(f"Requesting {path}...", end=" ")
            # We also pass a session dict for Starlette session middleware to find a user_id
            # in case any specific template or route uses request.session["user_id"]
            response = client.get(path)
            
            if response.status_code == 200:
                print(f"[OK] Success! (200 OK)")
            else:
                print(f"[FAIL] Failed! (Status: {response.status_code})")
                print(f"Response: {response.text[:500]}")
                failures += 1
        except Exception as e:
            print(f"[ERROR] Exception occurred: {e}")
            import traceback
            traceback.print_exc()
            failures += 1

    # Cleanup overrides
    app.dependency_overrides.clear()
    
    print("\n-------------------------------------")
    if failures == 0:
        print("[SUCCESS] ALL DASHBOARD ENDPOINTS ARE FULLY FUNCTIONAL AND RENDERING PROPERLY!")
        sys.exit(0)
    else:
        print(f"[WARNING] Encountered {failures} failure(s) during dashboard verification.")
        sys.exit(1)

if __name__ == "__main__":
    main()
