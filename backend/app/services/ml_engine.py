"""
Block Bord AI — ML Engine Service
Handles real-time phishing prediction using the trained XGBoost model.
"""
import os
import joblib
import pandas as pd
import logging
from backend.app.config import settings
from backend.ml.feature_engineering import extract_url_features

logger = logging.getLogger("blockbord.ml_engine")

class MLEngine:
    def __init__(self):
        self.model = None
        self.feature_names = None
        self.load_model()

    def load_model(self):
        """Loads the XGBoost model from disk."""
        if not os.path.exists(settings.xgboost_model_path):
            logger.warning(f"ML Model not found at {settings.xgboost_model_path}. ML predictions will be disabled.")
            return

        try:
            self.model = joblib.load(settings.xgboost_model_path)
            # If using XGBoost's Joblib, we can get feature names
            if hasattr(self.model, "feature_names_in_"):
                self.feature_names = self.model.feature_names_in_
            logger.info("XGBoost ML model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")

    def predict(self, url: str) -> float:
        """
        Predicts the phishing probability of a URL.
        Returns a float between 0.0 and 1.0.
        """
        if self.model is None:
            return 0.0

        try:
            features = extract_url_features(url)
            
            # Convert to DataFrame
            df = pd.DataFrame([features])
            
            # Ensure feature alignment with training
            if self.feature_names is not None:
                # Add missing columns as 0
                for col in self.feature_names:
                    if col not in df.columns:
                        df[col] = 0
                # Reorder and subset to match training features
                df = df[self.feature_names]

            # Predict probability
            # XGBoost predict_proba returns [safe_prob, phishing_prob]
            prob = self.model.predict_proba(df)[0][1]
            return float(prob)
        except Exception as e:
            logger.error(f"Prediction error for {url}: {e}")
            return 0.0

# Singleton instance
ml_engine = MLEngine()
