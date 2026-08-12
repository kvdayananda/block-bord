"""
Block Bord AI — Standalone Python ML Microservice
Serves XGBoost phishing prediction endpoints on port 8001.
"""
import sys
import os
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.services.ml_engine import ml_engine

app = FastAPI(title="Block Bord ML Microservice", version="1.0.0")

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
    target = req.url or req.content or ""
    prob = ml_engine.predict(target)
    risk_level = "high" if prob >= 0.7 else ("medium" if prob >= 0.35 else "safe")

    return {
        "url": target,
        "probability": prob,
        "risk_level": risk_level,
        "features": {"ml_available": ml_engine.is_available},
        "model_version": "xgboost_v1"
    }

@app.get("/predict")
def predict_get(url: str):
    prob = ml_engine.predict(url)
    risk_level = "high" if prob >= 0.7 else ("medium" if prob >= 0.35 else "safe")
    return {
        "url": url,
        "probability": prob,
        "risk_level": risk_level,
        "model_version": "xgboost_v1"
    }
