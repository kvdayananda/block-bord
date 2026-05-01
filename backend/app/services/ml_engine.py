"""
Block Bord AI — ML Engine Service
Handles real-time phishing prediction using the trained XGBoost model.
"""
import os
import joblib
import numpy as np
import pandas as pd
import logging
from backend.app.config import settings
from backend.ml.feature_engineering import extract_url_features

logger = logging.getLogger("blockbord.ml_engine")


class MLEngine:
    def __init__(self):
        self.model         = None
        self.feature_names = None
        self.load_model()

    def load_model(self):
        """Loads the XGBoost model from disk."""
        path = settings.xgboost_model_path
        if not os.path.exists(path):
            logger.warning(
                f"ML Model not found at '{path}'. "
                "ML predictions will be disabled — only heuristics will run."
            )
            return
        try:
            self.model = joblib.load(path)
            # XGBoost stores feature names on the booster
            booster = getattr(self.model, "get_booster", lambda: None)()
            if booster and booster.feature_names:
                self.feature_names = booster.feature_names
            elif hasattr(self.model, "feature_names_in_"):
                self.feature_names = list(self.model.feature_names_in_)
            n = len(self.feature_names) if self.feature_names else "?"
            logger.info(f"XGBoost ML model loaded from '{path}' ({n} features).")
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")

    def predict(self, url: str, page_content: str = "") -> float:
        """
        Predicts the phishing probability of a URL.
        Returns a float 0.0 (safe) → 1.0 (phishing).
        Falls back to 0.0 if the model is unavailable.
        """
        if self.model is None:
            return 0.0

        try:
            features = extract_url_features(url, page_content)
            df = pd.DataFrame([features])

            # ── Align feature columns to training order ────────────────────
            if self.feature_names:
                for col in self.feature_names:
                    if col not in df.columns:
                        df[col] = 0  # fill unseen features with 0
                extra = [c for c in df.columns if c not in self.feature_names]
                if extra:
                    df = df.drop(columns=extra)
                df = df[self.feature_names]   # enforce training order

            # XGBoost predict_proba → [P(safe), P(phishing)]
            prob = float(self.model.predict_proba(df)[0][1])
            logger.debug(f"ML prediction for '{url}': {prob:.4f}")
            return prob

        except Exception as e:
            logger.error(f"Prediction error for '{url}': {e}")
            return 0.0

    @property
    def is_available(self) -> bool:
        return self.model is not None


# Singleton — import this everywhere
ml_engine = MLEngine()
