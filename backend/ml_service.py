"""
Block Bord AI — Standalone Python ML Microservice
Serves XGBoost phishing prediction endpoints on port 8001.
"""
import os
import secrets
import sys
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.services.ml_engine import ml_engine

app = FastAPI(title="Block Bord ML Microservice", version="1.0.0")
ML_API_SECRET = os.getenv("ML_API_SECRET", "")

class PredictRequest(BaseModel):
    url: Optional[str] = None
    content: Optional[str] = None

@app.get("/")
def index():
    return {
        "service": "Block Bord AI - Python XGBoost ML Microservice",
        "status": "online",
        "ml_model_loaded": ml_engine.is_available,
        "endpoints": {
            "health": "/health",
            "predict_post": "/predict (POST)",
            "predict_get": "/predict?url=... (GET)",
            "docs": "/docs"
        }
    }

@app.get("/health")
def health():
    return {"status": "healthy", "ml_available": ml_engine.is_available}

@app.post("/predict")
def predict(req: PredictRequest, x_ml_secret: Optional[str] = Header(None)):
    verify_ml_secret(x_ml_secret)
    target = req.url or req.content or ""
    try:
        prob = ml_engine.predict(target)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="ML model is unavailable") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    risk_level = "high" if prob >= 0.7 else ("medium" if prob >= 0.35 else "safe")

    return {
        "url": target,
        "probability": prob,
        "risk_level": risk_level,
        "features": {"ml_available": ml_engine.is_available},
        "model_version": "xgboost_v1"
    }

@app.get("/predict")
def predict_get(url: str, x_ml_secret: Optional[str] = Header(None)):
    verify_ml_secret(x_ml_secret)
    try:
        prob = ml_engine.predict(url)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="ML model is unavailable") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    risk_level = "high" if prob >= 0.7 else ("medium" if prob >= 0.35 else "safe")
    return {
        "url": url,
        "probability": prob,
        "risk_level": risk_level,
        "model_version": "xgboost_v1"
    }


def verify_ml_secret(supplied_secret: Optional[str]) -> None:
    if not ML_API_SECRET:
        raise HTTPException(status_code=503, detail="ML API authentication is not configured")
    if not supplied_secret or not secrets.compare_digest(supplied_secret, ML_API_SECRET):
        raise HTTPException(status_code=401, detail="Invalid ML API secret")
