import os
import sys
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
import xgboost as xgb

# Ensure parent directory in path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from config import DATA_DIR, MODELS_DIR, LABEL_NAMES
from ml.feature_extraction import transform_flow_logs, FEATURE_COLUMNS, assert_zero_ip_leakage

def train_and_evaluate():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = DATA_DIR / "synthetic_vpc_flows.csv"
    if not csv_path.exists():
        print(f"Data file not found at {csv_path}. Run build_dataset.py first.")
        from data.build_dataset import build_and_save_data
        build_and_save_data()

    print(f"Loading dataset from: {csv_path}")
    raw_df = pd.read_csv(csv_path)
    
    # Transform raw flows with zero IP leakage
    X, _ = transform_flow_logs(raw_df)
    assert_zero_ip_leakage(X)
    y = raw_df["label"].values

    # Train/Test Split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"Dataset split: Train={len(X_train)} samples, Test={len(X_test)} samples")
    print(f"Features ({len(FEATURE_COLUMNS)}): {FEATURE_COLUMNS}")

    # Compute class weights for imbalanced threat distribution
    classes, counts = np.unique(y_train, return_counts=True)
    total_samples = len(y_train)
    class_weights = {c: total_samples / (len(classes) * cnt) for c, cnt in zip(classes, counts)}
    sample_weights = np.array([class_weights[label] for label in y_train])

    # Preprocessor: Scaler fitted on training data
    scaler = StandardScaler()
    scaler.fit(X_train)

    # 1. Random Forest Classifier
    print("\n" + "="*50)
    print("Training Random Forest Classifier (Multi-Class)...")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    rf_preds = rf.predict(X_test)
    print("Random Forest Evaluation Report:")
    print(classification_report(y_test, rf_preds, target_names=LABEL_NAMES, digits=4))

    # 2. XGBoost Classifier (Primary NIDS Model)
    print("\n" + "="*50)
    print("Training XGBoost NIDS Classifier (Class-Weighted)...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        objective="multi:softprob",
        num_class=4,
        random_state=42,
        n_jobs=-1,
        eval_metric="mlogloss"
    )
    xgb_model.fit(X_train, y_train, sample_weight=sample_weights)

    xgb_preds = xgb_model.predict(X_test)
    xgb_probs = xgb_model.predict_proba(X_test)

    print("XGBoost Evaluation Report:")
    print(classification_report(y_test, xgb_preds, target_names=LABEL_NAMES, digits=4))

    cm = confusion_matrix(y_test, xgb_preds)
    print("Confusion Matrix:")
    print(cm)

    # Calculate overall metrics
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, xgb_preds, average="weighted")
    print(f"\nXGBoost Weighted Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")

    # Precompute representative background sample for TreeSHAP
    # Using 100 stratified representative rows ensures sub-second SHAP value calculation
    background_df = X_train.sample(n=min(100, len(X_train)), random_state=42)

    # Save models and artifacts
    xgb_path = MODELS_DIR / "xgboost_nids.pkl"
    rf_path = MODELS_DIR / "rf_nids.pkl"
    preprocessor_path = MODELS_DIR / "preprocessor.pkl"
    shap_bg_path = MODELS_DIR / "shap_background.pkl"

    joblib.dump(xgb_model, xgb_path)
    joblib.dump(rf, rf_path)
    joblib.dump({
        "scaler": scaler,
        "feature_columns": FEATURE_COLUMNS,
        "label_names": LABEL_NAMES
    }, preprocessor_path)
    joblib.dump(background_df, shap_bg_path)

    print(f"\nSaved XGBoost model to: {xgb_path}")
    print(f"Saved Preprocessor to: {preprocessor_path}")
    print(f"Saved SHAP background summary to: {shap_bg_path}")

    return {
        "xgb_model": xgb_model,
        "f1_score": f1,
        "precision": precision,
        "recall": recall
    }

if __name__ == "__main__":
    train_and_evaluate()
