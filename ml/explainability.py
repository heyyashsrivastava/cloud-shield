import sys
import time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import shap
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config import MODELS_DIR, MITRE_ATTACK_MAP, LABEL_NAMES
from ml.feature_extraction import FEATURE_COLUMNS

class FlowExplainer:
    """
    Sub-second TreeSHAP explainer for Cloud Shield NIDS alerts.
    Uses pre-computed background data and TreeSHAP algorithm.
    """
    def __init__(self, model_path=None, bg_path=None):
        if model_path is None:
            model_path = MODELS_DIR / "xgboost_nids.pkl"
        if bg_path is None:
            bg_path = MODELS_DIR / "shap_background.pkl"

        self.model = joblib.load(model_path)
        self.background_df = joblib.load(bg_path) if Path(bg_path).exists() else None
        
        # Initialize TreeExplainer
        # For XGBoost multi:softprob, TreeExplainer without model_output='probability'
        # produces margin values, or with probability gives probability contributions.
        self.explainer = shap.TreeExplainer(self.model)

    def explain_flow(self, flow_features: pd.DataFrame, predicted_class: int = None) -> dict:
        """
        Explain a single flow's classification within milliseconds.
        Returns top positive and negative contributing features with exact SHAP impact.
        """
        start_time = time.time()
        
        # Ensure single row DataFrame
        if isinstance(flow_features, pd.Series):
            flow_features = flow_features.to_frame().T
        
        # Align columns
        df_eval = flow_features[FEATURE_COLUMNS]

        # Model prediction if not provided
        probs = self.model.predict_proba(df_eval)[0]
        if predicted_class is None:
            predicted_class = int(np.argmax(probs))

        # Compute SHAP values
        shap_values = self.explainer.shap_values(df_eval)
        
        # Handle multi-class output shape
        # In newer SHAP, shap_values is an array of shape (n_samples, n_features, n_classes)
        # or a list of arrays of shape (n_samples, n_features)
        if isinstance(shap_values, list):
            class_shap = shap_values[predicted_class][0]
        elif len(shap_values.shape) == 3:
            class_shap = shap_values[0, :, predicted_class]
        else:
            class_shap = shap_values[0]

        feature_values = df_eval.iloc[0].values
        
        # Build explanation items
        attributions = []
        for feat_name, feat_val, s_val in zip(FEATURE_COLUMNS, feature_values, class_shap):
            attributions.append({
                "feature": feat_name,
                "value": float(feat_val),
                "shap_value": float(s_val),
                "impact": "INCREASES_RISK" if s_val > 0 else "DECREASES_RISK",
                "abs_importance": abs(float(s_val))
            })

        # Sort by absolute SHAP importance descending
        attributions.sort(key=lambda x: x["abs_importance"], reverse=True)

        elapsed_ms = (time.time() - start_time) * 1000

        # Top features description for SOC analyst summary
        top_drivers = [a for a in attributions if a["shap_value"] > 0][:5]
        summary_sentences = []
        for d in top_drivers:
            summary_sentences.append(f"{d['feature']} = {d['value']:.2f} (SHAP contribution: +{d['shap_value']:.3f})")

        return {
            "predicted_class": predicted_class,
            "predicted_label": LABEL_NAMES[predicted_class],
            "confidence": float(probs[predicted_class]),
            "probabilities": {name: float(probs[i]) for i, name in enumerate(LABEL_NAMES)},
            "mitre_info": MITRE_ATTACK_MAP.get(predicted_class, {}),
            "attributions": attributions,
            "top_drivers": top_drivers,
            "analyst_summary": "; ".join(summary_sentences) if summary_sentences else "Standard baseline flow profile",
            "inference_time_ms": round(elapsed_ms, 2)
        }

    def generate_waterfall_figure(self, flow_features: pd.DataFrame, predicted_class: int = None, max_display: int = 10, explanation: dict = None):
        """Generate a matplotlib figure showing top feature attributions."""
        if explanation is None:
            explanation = self.explain_flow(flow_features, predicted_class)
        top_attrs = list(explanation["attributions"][:max_display])
        top_attrs.reverse()  # For horizontal bar chart

        features = [f"{a['feature']} ({a['value']:.1f})" for a in top_attrs]
        shap_vals = [a["shap_value"] for a in top_attrs]
        colors = ["#ef4444" if val > 0 else "#3b82f6" for val in shap_vals]

        fig, ax = plt.subplots(figsize=(8, 4.5), facecolor="#0f172a")
        ax.set_facecolor("#0f172a")
        bars = ax.barh(features, shap_vals, color=colors, height=0.6)
        
        ax.axvline(0, color="#64748b", linestyle="--", linewidth=1)
        ax.tick_params(colors="#e2e8f0", labelsize=9)
        for spine in ax.spines.values():
            spine.set_color("#334155")
            
        ax.set_title(
            f"SHAP Feature Attribution: {explanation['predicted_label']} "
            f"({explanation['confidence']*100:.1f}% Confidence | {explanation['inference_time_ms']}ms)",
            color="#f8fafc",
            fontsize=11,
            pad=12,
            fontweight="bold"
        )
        ax.set_xlabel("SHAP Impact on Threat Probability", color="#94a3b8", fontsize=9)
        plt.tight_layout()
        return fig
