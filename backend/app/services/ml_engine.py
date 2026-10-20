import logging
import os
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from backend.ml.feature_engineering import extract_url_features

logger = logging.getLogger(__name__)
DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "ml" / "models" / "xgboost_phishing_v1.joblib"

class MLEngine:
    def __init__(self) -> None:
        self.model: Any = None
        model_path = Path(os.getenv("ML_MODEL_PATH", str(DEFAULT_MODEL_PATH)))
        if model_path.is_file():
            try:
                self.model = joblib.load(model_path)
                logger.info("Loaded XGBoost model from %s", model_path)
            except Exception:
                logger.exception("Could not load phishing model from %s", model_path)
        else:
            logger.warning("Phishing model is not installed at %s", model_path)

    @property
    def is_available(self) -> bool:
        return self.model is not None

    def predict(self, url: str, content: str = "") -> float:
        if self.model is None:
            raise RuntimeError("Phishing model is unavailable.")
        if not url:
            raise ValueError("A URL is required for phishing prediction.")

        features = extract_url_features(url, content)
        expected_features = self.model.get_booster().feature_names
        if expected_features:
            features = {name: features.get(name, 0) for name in expected_features}

        probabilities = self.model.predict_proba(pd.DataFrame([features]))[0]
        classes = list(self.model.classes_)
        try:
            phishing_index = classes.index(1)
        except ValueError as exc:
            raise RuntimeError("Phishing model does not expose a positive class.") from exc

        return float(probabilities[phishing_index])

ml_engine = MLEngine()
