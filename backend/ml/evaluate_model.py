"""
Block Bord AI — ML Model Evaluation Script
Loads the saved XGBoost model and generates a full accuracy report.

Usage:
    python -m backend.ml.evaluate_model
"""
import os
import sys
import joblib
import logging
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # headless backend
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report,
    confusion_matrix, roc_curve, ConfusionMatrixDisplay
)
from sklearn.model_selection import train_test_split

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluate_model")

# ── Paths ──────────────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODEL_PATH   = os.path.join(PROJECT_ROOT, "backend", "ml", "models", "xgboost_phishing_v1.joblib")
CSV_PATH     = os.path.join(PROJECT_ROOT, "ml_data", "PhiUSIIL_Phishing_URL_Dataset.csv")
REPORT_DIR   = os.path.join(PROJECT_ROOT, "backend", "ml", "reports")
LABEL_COL    = "label"


def load_model():
    if not os.path.exists(MODEL_PATH):
        logger.error(f"Model not found at {MODEL_PATH}. Run train_model.py first.")
        sys.exit(1)
    model = joblib.load(MODEL_PATH)
    logger.info(f"Model loaded from {MODEL_PATH}")
    return model


def load_data():
    if not os.path.exists(CSV_PATH):
        logger.error(f"Dataset not found at {CSV_PATH}.")
        sys.exit(1)
    df = pd.read_csv(CSV_PATH, low_memory=False)
    logger.info(f"Dataset: {len(df):,} rows × {df.shape[1]} columns")

    # Normalize label
    for col in ["Label", "label", "CLASS_LABEL", "phishing"]:
        if col in df.columns:
            df = df.rename(columns={col: LABEL_COL})
            break

    if LABEL_COL not in df.columns:
        raise ValueError("Label column not found.")

    y = df[LABEL_COL]
    if y.dtype == object:
        from sklearn.preprocessing import LabelEncoder
        y = pd.Series(LabelEncoder().fit_transform(y), name=LABEL_COL)

    drop_cols = {LABEL_COL, "FILENAME", "URL", "url", "Domain", "domain"}
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    X = X.select_dtypes(include=[np.number]).fillna(0)
    return X, y


def evaluate():
    model = load_model()
    X, y  = load_data()

    # Reproduce the same test split used during training
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # ── Align features to what the model was trained on ──────────────────────
    expected_features = model.get_booster().feature_names
    if expected_features:
        missing = [f for f in expected_features if f not in X_test.columns]
        extra   = [f for f in X_test.columns if f not in expected_features]
        if missing:
            logger.warning(f"Missing features (will be filled with 0): {missing}")
            for f in missing:
                X_test[f] = 0
        if extra:
            X_test = X_test.drop(columns=extra)
        X_test = X_test[expected_features]

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc       = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall    = recall_score(y_test, y_pred, zero_division=0)
    f1        = f1_score(y_test, y_pred, zero_division=0)
    auc       = roc_auc_score(y_test, y_prob)

    # ── Print full report ─────────────────────────────────────────────────────
    sep = "=" * 60
    print(f"\n{sep}")
    print("  BLOCK BORD AI — MODEL EVALUATION REPORT")
    print(sep)
    print(f"  Test samples  : {len(X_test):,}")
    print(f"  Features used : {X_test.shape[1]}")
    print(sep)
    print(f"  Accuracy      : {acc:.4f}  ({acc*100:.2f}%)")
    print(f"  Precision     : {precision:.4f}  ({precision*100:.2f}%)")
    print(f"  Recall        : {recall:.4f}  ({recall*100:.2f}%)")
    print(f"  F1 Score      : {f1:.4f}  ({f1*100:.2f}%)")
    print(f"  AUC-ROC       : {auc:.4f}")
    print(sep)
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"]))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"Confusion Matrix:")
    print(f"  True Negative  (Safe correctly identified)    : {tn:,}")
    print(f"  False Positive (Safe flagged as Phishing)     : {fp:,}")
    print(f"  False Negative (Phishing missed)              : {fn:,}")
    print(f"  True Positive  (Phishing correctly caught)    : {tp:,}")
    print(f"  False Positive Rate : {fp / (fp + tn):.4f}  (lower is better)")
    print(f"  False Negative Rate : {fn / (fn + tp):.4f}  (lower is better)")
    print(sep)

    # ── Feature importance ─────────────────────────────────────────────────
    fi = pd.Series(model.feature_importances_, index=X_test.columns)
    top20 = fi.nlargest(20)
    print("\nTop-20 Feature Importances:")
    for feat, score in top20.items():
        bar = "█" * int(score * 200)
        print(f"  {feat:<40} {score:.4f}  {bar}")

    # ── Generate plots ──────────────────────────────────────────────────────
    os.makedirs(REPORT_DIR, exist_ok=True)

    # ROC Curve
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    plt.figure(figsize=(7, 5))
    plt.plot(fpr, tpr, color="#5a67d8", lw=2, label=f"AUC = {auc:.4f}")
    plt.plot([0, 1], [0, 1], "k--", lw=1)
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Block Bord AI — ROC Curve (XGBoost)")
    plt.legend(loc="lower right")
    plt.tight_layout()
    roc_path = os.path.join(REPORT_DIR, "roc_curve.png")
    plt.savefig(roc_path, dpi=150)
    plt.close()
    logger.info(f"ROC curve saved → {roc_path}")

    # Confusion Matrix Plot
    fig, ax = plt.subplots(figsize=(5, 4))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Safe", "Phishing"])
    disp.plot(ax=ax, colorbar=False, cmap="Blues")
    ax.set_title("Block Bord AI — Confusion Matrix")
    plt.tight_layout()
    cm_path = os.path.join(REPORT_DIR, "confusion_matrix.png")
    plt.savefig(cm_path, dpi=150)
    plt.close()
    logger.info(f"Confusion matrix saved → {cm_path}")

    # Feature Importance Plot
    plt.figure(figsize=(8, 6))
    top20.sort_values().plot(kind="barh", color="#48bb78")
    plt.xlabel("Importance Score")
    plt.title("Block Bord AI — Top-20 Feature Importances")
    plt.tight_layout()
    fi_path = os.path.join(REPORT_DIR, "feature_importance.png")
    plt.savefig(fi_path, dpi=150)
    plt.close()
    logger.info(f"Feature importance plot saved → {fi_path}")

    print(f"\nPlots saved to: {REPORT_DIR}/")
    print(sep)

    return {
        "accuracy": acc, "precision": precision,
        "recall": recall, "f1": f1, "auc": auc,
    }


if __name__ == "__main__":
    results = evaluate()
    if results["accuracy"] >= 0.95:
        print("\n✅ Model meets the 95%+ accuracy target for production!")
    else:
        print(f"\n⚠️  Model accuracy ({results['accuracy']*100:.2f}%) is below the 95% target.")
        print("   → Download the real PhiUSIIL dataset (235K rows) and retrain.")
