"""Machine Learning API routes"""

from fastapi import APIRouter, Query, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from backend.app.services.ml_engine import ml_engine
import subprocess, os, sys

router = APIRouter(prefix="/ml", tags=["Machine Learning"])

class PredictResponse(BaseModel):
    url: str
    probability: float
    label: str

@router.get("/predict", response_model=PredictResponse)
async def predict(url: str = Query(..., description="URL to evaluate")):
    """Return phishing probability using the loaded XGBoost model.

    If the model is unavailable, probability will be 0.0 and label "safe".
    """
    prob = ml_engine.predict(url)
    label = "phishing" if prob > 0.5 else "safe"
    return PredictResponse(url=url, probability=prob, label=label)

@router.post("/retrain")
async def retrain(background_tasks: BackgroundTasks):
    """Trigger asynchronous model retraining.

    The training script located at ``backend/ml/train_model.py`` will be executed
    in a background task. The endpoint returns immediately with a status message.
    """
    def _run_training():
        # Use the same Python interpreter that runs the server
        python_exe = sys.executable
        script_path = os.path.join(os.path.dirname(__file__), "..", "..", "ml", "train_model.py")
        subprocess.run([python_exe, "-m", "backend.ml.train_model"], check=False)

    background_tasks.add_task(_run_training)
    return JSONResponse(content={"detail": "Model retraining started in background."})
