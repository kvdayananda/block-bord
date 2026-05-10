"""
Block Bord AI — Centralized Configuration
Type-safe environment variable loading using Pydantic Settings.
All settings are read from .env via python-dotenv.
"""
import os
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Core ──
    env: str = "development"
    session_secret: str = "dev_only_change_me"
    backend_url: str = "http://127.0.0.1:8000"
    cors_origin_regex: str = r"https?://(localhost|127\.0\.0\.1)(:\d+)?"

    # ── Database ──
    # Default to SQLite for local dev, but REQUIRES PostgreSQL (e.g. Neon) for production.
    database_url: str = "sqlite:///./blockbord.db"

    # ── Razorpay ──
    razorpay_key_id: str = ""
    razorpay_key_secret: str = ""
    razorpay_webhook_secret: str = ""
    payment_test_mode: bool = True

    # ── External APIs ──
    google_safe_browsing_key: str = ""
    gemini_api_key: str = ""
    hibp_api_key: str = ""

    # ── ML Paths ──
    phiusiil_dataset_path: str = "./ml_data/PhiUSIIL_Phishing_URL_Dataset.csv"
    xgboost_model_path: str = "./backend/ml/models/xgboost_phishing_v1.joblib"

    # ── SMTP ──
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = ""

    # ── Error Monitoring ──
    sentry_dsn: str = ""

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


# Singleton — import this everywhere
settings = Settings()
