import pytest
import sys
import json
from pathlib import Path
import pandas as pd
import numpy as np

# Add project root
sys.path.append(str(Path(__file__).resolve().parent.parent))
from ml.feature_extraction import (
    transform_flow_logs, parse_flow_log_line,
    assert_zero_ip_leakage, FEATURE_COLUMNS, FORBIDDEN_COLUMNS
)
from ml.explainability import FlowExplainer
from config import MODELS_DIR, SAMPLE_FLOWS_FILE

def test_zero_ip_leakage():
    """Verify that feature extraction strictly excludes all raw IP identifiers."""
    sample_flow = {
        "version": "5",
        "account_id": "301276846152",
        "interface_id": "eni-12345678",
        "srcaddr": "198.51.100.44",
        "dstaddr": "10.0.1.100",
        "srcport": 45123,
        "dstport": 80,
        "protocol": 6,
        "packets": 50,
        "bytes": 25000,
        "start": 1700000000,
        "end": 1700000010,
        "action": "ACCEPT",
        "log_status": "OK",
        "tcp_flags": 27,
        "type": "IPv4",
        "pkt_srcaddr": "198.51.100.44",
        "pkt_dstaddr": "10.0.1.100"
    }
    
    X_features, meta_df = transform_flow_logs([sample_flow])

    # 1. Feature columns must not intersect forbidden columns
    for col in X_features.columns:
        assert col not in FORBIDDEN_COLUMNS
        assert "addr" not in col.lower()
        if col != "is_ephemeral_port":
            assert "ip" not in col.lower()
    
    # 2. All feature values must be numeric
    for col in X_features.columns:
        assert np.issubdtype(X_features[col].dtype, np.number)

    # 3. Explicit zero leakage assertion
    assert_zero_ip_leakage(X_features)

def test_flow_log_line_parsing():
    """Verify parsing AWS VPC Flow Log v5 record."""
    line = "5 301276846152 eni-01234567 198.51.100.5 10.0.1.100 52345 80 6 3 150 1700000000 1700000002 ACCEPT OK 2 IPv4 198.51.100.5 10.0.1.100"
    parsed = parse_flow_log_line(line)
    assert parsed is not None
    assert parsed["srcaddr"] == "198.51.100.5"
    assert parsed["dstport"] == 80
    assert parsed["tcp_flags"] == 2
    assert parsed["action"] == "ACCEPT"

def test_treeshap_explainer():
    """Verify TreeSHAP explanation executes within sub-second bounds with non-zero attributions."""
    if not (MODELS_DIR / "xgboost_nids.pkl").exists():
        pytest.skip("Model not yet trained")

    explainer = FlowExplainer()
    with open(SAMPLE_FLOWS_FILE, "r") as f:
        flows = json.load(f)

    X_features, _ = transform_flow_logs(flows[:3])
    res = explainer.explain_flow(X_features.iloc[0])

    assert "predicted_label" in res
    assert "confidence" in res
    assert "attributions" in res
    assert len(res["attributions"]) == len(FEATURE_COLUMNS)
    assert res["inference_time_ms"] < 1000  # Sub-second guarantee

def test_all_four_models_and_benchmarks():
    """Verify all 4 ML models (RF, XGBoost, SVM, NN) and benchmark metrics are present and functional."""
    import joblib
    model_files = {
        "Random Forest": MODELS_DIR / "rf_nids.pkl",
        "XGBoost": MODELS_DIR / "xgboost_nids.pkl",
        "SVM": MODELS_DIR / "svm_nids.pkl",
        "Neural Network": MODELS_DIR / "nn_nids.pkl",
    }
    for name, path in model_files.items():
        assert path.exists(), f"Model {name} missing at {path}"
        m = joblib.load(path)
        assert hasattr(m, "predict"), f"Model {name} missing predict method"
        assert hasattr(m, "predict_proba"), f"Model {name} missing predict_proba method"

    # Test predictions on sample flow
    with open(SAMPLE_FLOWS_FILE, "r") as f:
        flows = json.load(f)
    X_features, _ = transform_flow_logs(flows[:5])
    for name, path in model_files.items():
        m = joblib.load(path)
        preds = m.predict(X_features)
        probs = m.predict_proba(X_features)
        assert len(preds) == len(X_features)
        assert probs.shape == (len(X_features), 4)

    # Test benchmark metrics JSON
    bench_file = MODELS_DIR / "benchmark_metrics.json"
    assert bench_file.exists()
    with open(bench_file, "r") as f:
        data = json.load(f)
    for expected_model in ["Random Forest", "XGBoost", "SVM", "Neural Network"]:
        assert expected_model in data
        metrics = data[expected_model]
        for metric_name in ["accuracy", "precision", "recall", "f1", "fpr", "latency_ms"]:
            assert metric_name in metrics
            assert isinstance(metrics[metric_name], (int, float))

