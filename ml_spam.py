import re
from pathlib import Path
from typing import List, Tuple, Optional

MODEL_DIR = Path("models")
MODEL_PATH = MODEL_DIR / "spam_model.bin"
TRAIN_TXT = MODEL_DIR / "spam_train.txt"

def _normalize(text: str) -> str:
    s = (text or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s

def _has_fasttext() -> bool:
    try:
        import fasttext  # noqa: F401
        return True
    except Exception:
        return False

def load_model():
    if not MODEL_PATH.exists():
        return None
    try:
        import fasttext
        return fasttext.load_model(str(MODEL_PATH))
    except Exception:
        return None

def predict_spam_prob(text: str) -> Optional[float]:
    """
    Returns spam probability (0..1) if model exists; else None.
    """
    model = load_model()
    if model is None:
        return None
    try:
        labels, probs = model.predict(_normalize(text), k=2)
        out = dict(zip(labels, probs))
        return float(out.get("__label__spam", 0.0))
    except Exception:
        return None

def train_model_from_samples(samples: List[Tuple[str, str]]) -> Tuple[bool, str]:
    """
    samples: list of (label, content), label in {'spam','ham'}
    Trains and saves model. Needs >= 20 samples.
    """
    if not _has_fasttext():
        return False, "fastText not installed. Install 'fasttext-wheel'."
    if len(samples) < 20:
        return False, "Need at least 20 feedback samples to train."

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    with open(TRAIN_TXT, "w", encoding="utf-8") as f:
        for label, content in samples:
            lab = "spam" if (label or "").lower() == "spam" else "ham"
            txt = _normalize(content)
            if not txt:
                continue
            f.write(f"__label__{lab} {txt}\n")

    import fasttext
    model = fasttext.train_supervised(
        input=str(TRAIN_TXT),
        lr=0.6,
        epoch=25,
        wordNgrams=2,
        dim=100,
        loss="softmax",
        minn=2,
        maxn=4
    )
    model.save_model(str(MODEL_PATH))
    return True, "Model retrained successfully."
