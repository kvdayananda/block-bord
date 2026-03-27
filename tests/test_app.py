import pytest
from fastapi.testclient import TestClient

from app import app


client = TestClient(app)


def test_status_page_available():
    response = client.get("/status")
    assert response.status_code == 200
    assert "status" in response.text.lower() or "block bord" in response.text.lower()


def test_landing_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "block bord" in response.text.lower()
