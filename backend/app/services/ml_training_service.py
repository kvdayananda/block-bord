"""
Block Bord AI — ML Training Service
Handles incremental/session-based model retraining from user feedback.
"""
import os
import joblib
import pandas as pd
import logging
from datetime import datetime
from backend.app.config import settings
from backend.ml.feature_engineering import extract_url_features

logger = logging.getLogger("blockbord.ml_training")

def train_model_from_samples(samples: list):
    """
    Receives a list of (label, content) tuples.
    Extracts features and updates the model or saves for batch retraining.
    """
    if not samples:
        return False, "No samples provided for retraining."
    
    try:
        # 1. Log samples for future deep training
        log_path = os.path.join("ml_data", "user_feedback_harvest.csv")
        os.makedirs("ml_data", exist_ok=True)
        
        new_data = []
        for label, content in samples:
            # If content is a URL, extract features
            # (In this platform, feedback usually relates to URLs)
            features = extract_url_features(content)
            features['label'] = 1 if label.lower() == "spam" else 0
            features['timestamp'] = datetime.now().isoformat()
            new_data.append(features)
        
        df_new = pd.DataFrame(new_data)
        
        # Append to feedback log
        header = not os.path.exists(log_path)
        df_new.to_csv(log_path, mode='a', index=False, header=header)
        
        logger.info(f"Harvested {len(samples)} feedback samples for ML improvement.")
        
        # 2. Simulate incremental improvement 
        # (In a real high-scale system, this would trigger an asynchronous Airflow/Celery job)
        return True, f"Successfully processed {len(samples)} samples. Insights integrated into future model updates."
        
    except Exception as e:
        logger.error(f"Retraining error: {e}")
        return False, str(e)
