"""
Block Bord AI — ML Model Training Script
Trains an XGBoost classifier on the PhiUSIIL Phishing URL Dataset.

Usage:
    # Place PhiUSIIL_Phishing_URL_Dataset.csv in ml_data/ then run:
    python -m backend.ml.train_model
"""
import os
import sys
import joblib
import logging
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report, confusion_matrix
)

# ── Setup Logging ──────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_model")

# ── Configuration ──────────────────────────────────────────────────────────────
# Adjust paths relative to project root
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
# Support both the original filename and the prefixed variant
_CSV_CANDIDATES = [
    os.path.join(PROJECT_ROOT, "ml_data", "PhiUSIIL_Phishing_URL_Dataset.csv"),
    os.path.join(PROJECT_ROOT, "ml_data", "ml_dataPhiUSIIL_Phishing_URL_Dataset.csv"),
]
CSV_PATH  = next((p for p in _CSV_CANDIDATES if os.path.exists(p)), _CSV_CANDIDATES[0])
MODEL_DIR = os.path.join(PROJECT_ROOT, "backend", "ml", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "xgboost_phishing_v1.joblib")

# PhiUSIIL dataset has 54+ features. We list the known numeric ones here.
# If the CSV has more, they are used automatically.
PHIUSIIL_NUMERIC_FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP", "URLSimilarityIndex",
    "CharContinuationRate", "TLDLegitimateProb", "URLCharProb",
    "TLDLength", "NoOfSubDomain", "HasObfuscation",
    "NoOfObfuscatedChar", "ObfuscationRatio", "NoOfLettersInURL",
    "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL",
    "IsHTTPS", "LineOfCode", "LargestLineLength", "HasTitle",
    "DomainTitleMatchScore", "URLTitleMatchScore", "HasFavicon",
    "Robots", "IsResponsive", "NoOfURLRedirect", "NoOfSelfRedirect",
    "HasDescription", "NoOfPopup", "NoOfiFrame", "HasExternalFormSubmit",
    "HasSocialNet", "HasSubmitButton", "HasHiddenFields",
    "HasPasswordField", "Bank", "Pay", "Crypto", "HasCopyrightInfo",
    "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef",
    "NoOfEmptyRef", "NoOfExternalRef",
    # Lexical extras
    "NoOfDotsInURL", "HasHTTPS", "EntropyOfURL", "IsDomainIP",
]
LABEL_COL = "label"  # normalized in load_data()

# ── XGBoost hyperparameters ─────────────────────────────────────────────────
XGBOOST_PARAMS = dict(
    n_estimators=300,
    max_depth=7,
    learning_rate=0.08,
    subsample=0.85,
    colsample_bytree=0.85,
    min_child_weight=3,
    gamma=0.1,
    reg_alpha=0.05,
    reg_lambda=1.5,
    random_state=42,
    n_jobs=-1,
    eval_metric="logloss",
    early_stopping_rounds=20,
)


# ── Dataset Loader ─────────────────────────────────────────────────────────────
def load_data() -> tuple[pd.DataFrame, pd.Series]:
    """Loads the PhiUSIIL CSV and returns (X, y)."""
    if not os.path.exists(CSV_PATH):
        logger.error(
            f"Dataset not found at: {CSV_PATH}\n"
            "  → Download from: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset\n"
            "  → Save the CSV to ml_data/PhiUSIIL_Phishing_URL_Dataset.csv\n"
            "  → Then re-run this script."
        )
        sys.exit(1)

    logger.info(f"Loading dataset from {CSV_PATH} …")
    df = pd.read_csv(CSV_PATH, low_memory=False)
    logger.info(f"Loaded {len(df):,} rows × {df.shape[1]} columns")

    # ── Validate size – warn if it looks like synthetic/truncated data ─────
    if len(df) < 5_000:
        logger.warning(
            f"Dataset has only {len(df)} rows — this looks like the SYNTHETIC FALLBACK, "
            "not the real PhiUSIIL dataset (235,000 rows). "
            "Accuracy will be LOW. Please download the real dataset."
        )

    # ── Normalize label column ─────────────────────────────────────────────
    for candidate in ["Label", "label", "CLASS_LABEL", "phishing"]:
        if candidate in df.columns:
            df = df.rename(columns={candidate: LABEL_COL})
            break

    if LABEL_COL not in df.columns:
        raise ValueError(f"Cannot find label column. Columns: {list(df.columns)}")

    # ── Encode label → 0/1 ────────────────────────────────────────────────
    y = df[LABEL_COL]
    if y.dtype == object:
        le = LabelEncoder()
        y = pd.Series(le.fit_transform(y), name=LABEL_COL)
        logger.info(f"Label classes: {le.classes_}")

    # ── Select numeric feature columns ─────────────────────────────────────
    drop_cols = {LABEL_COL, "FILENAME", "URL", "url", "Domain", "domain"}
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])

    # Keep only numeric columns (handles string URL column etc.)
    X = X.select_dtypes(include=[np.number]).fillna(0)
    logger.info(f"Feature matrix: {X.shape[1]} features, {len(X):,} samples")
    logger.info(f"Label distribution: {dict(y.value_counts().sort_index())}")

    return X, y


# ── Training ───────────────────────────────────────────────────────────────────
def train(X: pd.DataFrame, y: pd.Series) -> XGBClassifier:
    """Trains and evaluates an XGBoost model. Returns the fitted model."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    logger.info(f"Train: {len(X_train):,} rows | Test: {len(X_test):,} rows")

    model = XGBClassifier(**XGBOOST_PARAMS)
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=50
    )

    # ── Evaluation ──────────────────────────────────────────────────────────
    y_pred      = model.predict(X_test)
    y_prob      = model.predict_proba(X_test)[:, 1]

    acc       = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall    = recall_score(y_test, y_pred, zero_division=0)
    f1        = f1_score(y_test, y_pred, zero_division=0)
    auc       = roc_auc_score(y_test, y_prob)

    logger.info("\n" + "=" * 55)
    logger.info("  BLOCK BORD AI — XGBOOST MODEL EVALUATION REPORT")
    logger.info("=" * 55)
    logger.info(f"  Accuracy  : {acc:.4f}  ({acc*100:.2f}%)")
    logger.info(f"  Precision : {precision:.4f}")
    logger.info(f"  Recall    : {recall:.4f}")
    logger.info(f"  F1 Score  : {f1:.4f}")
    logger.info(f"  AUC-ROC   : {auc:.4f}")
    logger.info("=" * 55)
    logger.info("\nClassification Report:\n" + classification_report(y_test, y_pred,
        target_names=["Safe (0)", "Phishing (1)"]))

    cm = confusion_matrix(y_test, y_pred)
    logger.info(f"Confusion Matrix:\n{cm}")

    # ── Feature importance (top 15) ─────────────────────────────────────────
    fi = pd.Series(model.feature_importances_, index=X.columns)
    top15 = fi.nlargest(15)
    logger.info("\nTop-15 Feature Importances:")
    for feat, score in top15.items():
        logger.info(f"  {feat:<35} {score:.4f}")

    return model


# ── Save Model ─────────────────────────────────────────────────────────────────
def save_model(model: XGBClassifier) -> None:
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    size_kb = os.path.getsize(MODEL_PATH) / 1024
    logger.info(f"\nModel saved → {MODEL_PATH}  ({size_kb:.1f} KB)")


# ── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    X, y = load_data()
    model = train(X, y)
    save_model(model)
    logger.info("Training complete. Model is ready for production.")
