from typing import Optional
import ml_spam

def predict_blended_prob(text: str) -> Optional[float]:
    """
    Ensemble Coordinator:
    Since the redundant sklearn model was removed, this now 
    acts as a direct pass-through to the core FastText model.
    """
    return ml_spam.predict_spam_prob(text)
