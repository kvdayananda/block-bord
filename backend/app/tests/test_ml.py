# test_ml endpoint

import pytest
from fastapi import status

def test_predict_success(monkeypatch, client):
    """ML predict endpoint should return probability and label."""
    # Mock the ml_engine.predict method
    class DummyEngine:
        def predict(self, url: str, raw: str = "") -> float:
            return 0.85  # high probability -> phishing
    monkeypatch.setattr("backend.app.services.ml_engine.ml_engine", DummyEngine())

    response = client.get("/ml/predict", params={"url": "http://example.com"})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["url"] == "http://example.com"
    assert data["probability"] == 0.85
    assert data["label"] == "phishing"
