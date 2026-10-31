import os
import sys
import json
import time
import gzip
import io
from pathlib import Path
import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import joblib

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent))
from config import (
    BASE_DIR, DATA_DIR, MODELS_DIR, STATE_FILE, AUDIT_LOG_FILE,
    SAMPLE_FLOWS_FILE, LOCAL_FLOW_LOG_FILE, IMMUTABLE_ALLOWLIST, MITRE_ATTACK_MAP,
    LABEL_NAMES, get_aws_identity, get_aws_session, get_bucket_name
)
from ml.feature_extraction import (
    transform_flow_logs, parse_flow_log_line,
    assert_zero_ip_leakage, FEATURE_COLUMNS
)
from ml.explainability import FlowExplainer
from soar.remediation import (
    quarantine_ip, restore_ip, get_quarantined_ips,
    verify_audit_ledger, is_ip_allowlisted, SecurityViolationError
)

# Streamlit Page Config
st.set_page_config(
    page_title="Cloud Shield | Enterprise Cloud-Native NIDS & SOAR",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber SOC Dark CSS
st.markdown("""
<style>
    .main { background-color: #0b1120; color: #e2e8f0; }
    .stMetric {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .status-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.75rem;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
    .badge-high { background: rgba(139, 92, 246, 0.2); color: #a78bfa; border: 1px solid #8b5cf6; }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
    .badge-benign { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    .card-box {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    /* Persistent Cyber Top Nav Tabs */
    div.main div[data-testid="stRadio"] > div[role="radiogroup"] {
        display: flex;
        gap: 12px;
        background-color: #0b1329;
        padding: 8px;
        border-radius: 12px;
        border: 1px solid #1e293b;
        margin-bottom: 24px;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.4);
    }
    div.main div[data-testid="stRadio"] > div[role="radiogroup"] > label {
        background: #111827;
        padding: 10px 24px;
        border-radius: 8px;
        border: 1px solid #1f2937;
        cursor: pointer;
        font-weight: 600;
        font-size: 0.95rem;
        color: #94a3b8;
        transition: all 0.25s ease-in-out;
        user-select: none;
    }
    div.main div[data-testid="stRadio"] > div[role="radiogroup"] > label > div:first-child {
        display: none !important;
    }
    div.main div[data-testid="stRadio"] > div[role="radiogroup"] > label:hover {
        background: #1e293b;
        color: #f8fafc;
        border-color: #3b82f6;
    }
    div.main div[data-testid="stRadio"] > div[role="radiogroup"] > label[data-checked="true"],
    div.main div[data-testid="stRadio"] > div[role="radiogroup"] > label:has(input:checked) {
        background: linear-gradient(135deg, #1d4ed8 0%, #2563eb 100%) !important;
        border-color: #60a5fa !important;
        color: #ffffff !important;
        box-shadow: 0 4px 14px rgba(37, 99, 235, 0.45);
    }
    div.main div[data-testid="stRadio"] > div[role="radiogroup"] > label:has(input:checked) p {
        color: #ffffff !important;
        font-weight: 700;
    }
    }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_models_and_explainer():
    """Cache XGBoost model, preprocessor, and TreeSHAP explainer."""
    xgb_path = MODELS_DIR / "xgboost_nids.pkl"
    if not xgb_path.exists():
        from ml.train_models import train_and_evaluate
        train_and_evaluate()
    model = joblib.load(xgb_path)
    explainer = FlowExplainer(model_path=xgb_path)
    return model, explainer

model, explainer = load_models_and_explainer()

# --- SIDEBAR: AWS Fleet & Control Controls ---
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=64)
    st.title("Cloud Shield NIDS")
    st.caption("Enterprise Cloud-Native Intrusion Detection & SOAR")
    
    st.divider()
    st.subheader("🌐 AWS Environment")
    identity = get_aws_identity()
    
    if identity.get("connected"):
        st.success(f"Connected: AWS Account `{identity['account_id']}`")
        st.markdown(f"**Region:** `{identity['region']}`")
    else:
        st.warning("AWS Credentials: Offline/Mock Mode")

    # Infra State Check
    infra_active = False
    infra_state = {}
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                infra_state = json.load(f)
            infra_active = True
            st.info(f"Active VPC: `{infra_state.get('vpc_id', 'N/A')}`\nTarget EC2: `{infra_state.get('public_ip', 'PENDING')}`")
        except Exception:
            pass

    st.divider()
    st.subheader("🎯 Target Web Server")
    pub_ip = infra_state.get("public_ip")
    if pub_ip and pub_ip != "PENDING":
        st.success(f"🟢 **Live Target:** [http://{pub_ip}](http://{pub_ip})")
        st.caption("Victim server: Apex Global Financial Portal on AWS EC2 (Port 80)")
    else:
        st.info("Target: http://localhost:5000")

    st.divider()
    st.subheader("📡 Telemetry Source")
    query_source = st.query_params.get("source", "s3").lower()
    default_source_idx = 1 if query_source == "demo" else 0

    def on_source_changed():
        chosen_source = st.session_state.get("telemetry_ingest_mode", "")
        st.query_params["source"] = "s3" if "S3" in chosen_source else "demo"

    ingest_mode = st.radio(
        "Ingestion Mode:",
        ["☁️ Live AWS S3 Polling", "🎮 Instant Demo Replay"],
        index=default_source_idx,
        key="telemetry_ingest_mode",
        on_change=on_source_changed
    )

    st.divider()
    st.subheader("⚡ Simulate Cyber Attacks")
    st.caption("Fire attack bursts against the target to test real-time detection.")

    if st.button("💥 Run Full Attack Suite", use_container_width=True):
        with st.spinner("Generating DoS, PortScan, and Brute Force flows..."):
            from scripts.simulate_traffic import run_all_simulations
            try:
                run_all_simulations()
                st.success("Attacks dispatched!")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Simulation failed: {e}")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("🌊 DoS SYN Flood", use_container_width=True):
            from scripts.simulate_traffic import simulate_syn_flood
            try:
                simulate_syn_flood(num_packets=50)
                st.success("DoS burst sent!")
                time.sleep(0.5)
                st.rerun()
            except Exception as e:
                st.error(str(e))

        if st.button("🔍 Port Scan", use_container_width=True):
            from scripts.simulate_traffic import simulate_port_scan
            try:
                simulate_port_scan()
                st.success("Port scan sent!")
                time.sleep(0.5)
                st.rerun()
            except Exception as e:
                st.error(str(e))

    with col_btn2:
        if st.button("🔑 Brute Force", use_container_width=True):
            from scripts.simulate_traffic import simulate_brute_force
            try:
                simulate_brute_force(count=15)
                st.success("Brute force sent!")
                time.sleep(0.5)
                st.rerun()
            except Exception as e:
                st.error(str(e))

        if st.button("✅ Normal Web Traffic", use_container_width=True):
            from scripts.simulate_traffic import simulate_normal_traffic
            try:
                simulate_normal_traffic(count=15)
                st.success("Benign flows sent!")
                time.sleep(0.5)
                st.rerun()
            except Exception as e:
                st.error(str(e))

    st.divider()
    if st.button("🗑️ 1-Click AWS Teardown", type="secondary", use_container_width=True):
        with st.spinner("Tearing down all AWS resources cleanly..."):
            from scripts.cleanup_aws_infra import cleanup_infrastructure
            try:
                cleanup_infrastructure()
                st.success("All AWS resources destroyed cleanly!")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Teardown failed: {e}")

# Function to load flow telemetry
def load_telemetry():
    if ingest_mode == "🎮 Instant Demo Replay":
        if SAMPLE_FLOWS_FILE.exists():
            with open(SAMPLE_FLOWS_FILE, "r") as f:
                flows = json.load(f)
            return flows
        return []
    else:
        # S3 Live Ingestion
        bucket_name = infra_state.get("s3_bucket") or get_bucket_name()
        region = identity["region"]
        session = get_aws_session()
        s3 = session.client("s3", region_name=region)
        flows = []
        try:
            objs = s3.list_objects_v2(Bucket=bucket_name, Prefix="vpc-flow-logs/", MaxKeys=30)
            for item in objs.get("Contents", []):
                if item["Key"].endswith(".gz"):
                    resp = s3.get_object(Bucket=bucket_name, Key=item["Key"])
                    with gzip.GzipFile(fileobj=io.BytesIO(resp["Body"].read())) as gz:
                        lines = gz.read().decode("utf-8").splitlines()
                        for line in lines:
                            rec = parse_flow_log_line(line)
                            if rec:
                                flows.append(rec)
        except Exception as e:
            st.warning(f"S3 Polling notice: {e}. Falling back to demo telemetry.")
            if SAMPLE_FLOWS_FILE.exists():
                with open(SAMPLE_FLOWS_FILE, "r") as f:
                    flows = json.load(f)
        return flows

raw_flows = load_telemetry()

# Ingest and classify
if raw_flows:
    X_features, meta_df = transform_flow_logs(raw_flows)
    preds = model.predict(X_features)
    probs = model.predict_proba(X_features)
    
    meta_df["predicted_class"] = preds
    meta_df["predicted_label"] = [LABEL_NAMES[p] for p in preds]
    meta_df["confidence"] = [probs[i][preds[i]] for i in range(len(preds))]
    meta_df["mitre_technique"] = [MITRE_ATTACK_MAP[p]["technique_id"] for p in preds]
    meta_df["severity"] = [MITRE_ATTACK_MAP[p]["severity"] for p in preds]
else:
    meta_df = pd.DataFrame()
    X_features = pd.DataFrame()

# Persistent Navigation Tabs
TAB_OPTIONS = [
    "🛡️ Real-Time SOC Monitor",
    "🧠 Explainable AI (TreeSHAP)",
    "⚡ SOAR Active Remediation"
]
TAB_KEY_MAP = {"monitor": 0, "explainability": 1, "soar": 2}
INDEX_TO_KEY = ["monitor", "explainability", "soar"]

# Read and validate query param
query_tab = st.query_params.get("tab", "monitor").lower()
target_tab_idx = TAB_KEY_MAP.get(query_tab, 0)

# Synchronize session state with query param
if "top_nav_radio" not in st.session_state:
    st.session_state["top_nav_radio"] = TAB_OPTIONS[target_tab_idx]
elif st.session_state.get("_prev_query_tab") != query_tab:
    st.session_state["top_nav_radio"] = TAB_OPTIONS[target_tab_idx]

st.session_state["_prev_query_tab"] = query_tab

def on_tab_nav_changed():
    chosen_label = st.session_state.get("top_nav_radio", TAB_OPTIONS[0])
    new_idx = TAB_OPTIONS.index(chosen_label) if chosen_label in TAB_OPTIONS else 0
    st.query_params["tab"] = INDEX_TO_KEY[new_idx]
    st.session_state["_prev_query_tab"] = INDEX_TO_KEY[new_idx]

active_tab = st.radio(
    "Navigation View",
    options=TAB_OPTIONS,
    horizontal=True,
    key="top_nav_radio",
    on_change=on_tab_nav_changed,
    label_visibility="collapsed"
)

current_idx = TAB_OPTIONS.index(active_tab) if active_tab in TAB_OPTIONS else 0
st.query_params["tab"] = INDEX_TO_KEY[current_idx]

# ==============================================================================
# TAB 1: SOC MONITOR
# ==============================================================================
if active_tab == "🛡️ Real-Time SOC Monitor":
    st.header("Real-Time Intrusion Detection & Telemetry Feed")
    
    # KPI Row
    c1, c2, c3, c4 = st.columns(4)
    total_flows = len(meta_df)
    threat_flows = len(meta_df[meta_df["predicted_class"] != 0]) if total_flows > 0 else 0
    threat_pct = (threat_flows / total_flows * 100) if total_flows > 0 else 0
    quarantined_ips = get_quarantined_ips()

    c1.metric("Flows Ingested", f"{total_flows:,}")
    c2.metric("Threats Flagged", f"{threat_flows:,}", delta=f"{threat_pct:.1f}% risk ratio", delta_color="inverse")
    c3.metric("MITRE ATT&CK Detections", len(meta_df["mitre_technique"].unique()) if total_flows > 0 else 0)
    c4.metric("Active Quarantined IPs", len(quarantined_ips))

    st.divider()

    # Attack Class Breakdown & MITRE Matrix
    col_a, col_b = st.columns([1, 2])
    with col_a:
        st.subheader("Classification Profile")
        if total_flows > 0:
            class_counts = meta_df["predicted_label"].value_counts()
            st.bar_chart(class_counts)
        else:
            st.info("No flow logs loaded.")

    with col_b:
        st.subheader("MITRE ATT&CK Mapping Framework")
        m1, m2, m3 = st.columns(3)
        with m1:
            st.markdown("""
            **T1046: Network Scan**  
            *Discovery Tactic*  
            Probing closed/open TCP ports with single SYN flags.
            """)
            scan_count = len(meta_df[meta_df["predicted_label"] == "PortScan"]) if total_flows > 0 else 0
            st.caption(f"Detections: **{scan_count}**")
        with m2:
            st.markdown("""
            **T1498.001: SYN Flood**  
            *Impact Tactic*  
            High packet velocity TCP SYN floods to exhaust server sockets.
            """)
            dos_count = len(meta_df[meta_df["predicted_label"] == "DoS_SYN"]) if total_flows > 0 else 0
            st.caption(f"Detections: **{dos_count}**")
        with m3:
            st.markdown("""
            **T1110.001: Brute Force**  
            *Credential Access Tactic*  
            Rapid repeated auth payloads to ports 80/22/3389.
            """)
            bf_count = len(meta_df[meta_df["predicted_label"] == "BruteForce"]) if total_flows > 0 else 0
            st.caption(f"Detections: **{bf_count}**")

    st.divider()
    st.subheader("Live Telemetry & Alert Stream")
    if total_flows > 0:
        display_df = meta_df[["srcaddr", "dstaddr", "srcport", "dstport", "action", "predicted_label", "mitre_technique", "severity", "confidence"]].copy()
        display_df["confidence"] = display_df["confidence"].apply(lambda x: f"{x*100:.1f}%")
        st.dataframe(display_df, use_container_width=True, height=350)
    else:
        st.warning("No telemetry records found. Dispatch simulation or deploy infra.")

# ==============================================================================
# TAB 2: EXPLAINABILITY (TreeSHAP)
# ==============================================================================
elif active_tab == "🧠 Explainable AI (TreeSHAP)":
    st.header("🧠 Sub-Second Explainable AI (TreeSHAP)")
    st.markdown("Attribution of model decisions at flow level with pre-computed background summary.")

    if total_flows > 0:
        threat_indices = meta_df[meta_df["predicted_class"] != 0].index.tolist()
        if not threat_indices:
            threat_indices = list(range(min(5, total_flows)))

        selected_idx = st.selectbox(
            "Select Flow to Explain:",
            options=threat_indices,
            format_func=lambda i: f"Flow #{i} | {meta_df.iloc[i]['srcaddr']} -> {meta_df.iloc[i]['dstaddr']}:{meta_df.iloc[i]['dstport']} [{meta_df.iloc[i]['predicted_label']} ({meta_df.iloc[i]['confidence']*100:.1f}%)]"
        )

        flow_feat = X_features.iloc[selected_idx]
        pred_c = int(meta_df.iloc[selected_idx]["predicted_class"])
        explanation = explainer.explain_flow(flow_feat, predicted_class=pred_c)

        col_x1, col_x2 = st.columns([1, 1])
        with col_x1:
            st.subheader("SHAP Feature Attribution Waterfall")
            fig = explainer.generate_waterfall_figure(flow_feat, predicted_class=pred_c, explanation=explanation)
            st.pyplot(fig)
            st.caption(f"⚡ TreeSHAP attribution completed in `{explanation['inference_time_ms']} ms`.")

        with col_x2:
            st.subheader("SOC Analyst Synthesis")
            st.markdown(f"**Classification:** `{explanation['predicted_label']}` ({explanation['confidence']*100:.2f}% Confidence)")
            st.markdown(f"**MITRE ATT&CK:** `{explanation['mitre_info'].get('technique_id')}` - *{explanation['mitre_info'].get('technique_name')}*")
            st.markdown(f"**Severity:** `{explanation['mitre_info'].get('severity')}`")
            st.info(f"**Key Behavioral Drivers:**\n{explanation['analyst_summary']}")

            # Feature table
            attr_df = pd.DataFrame(explanation["attributions"][:8])
            st.dataframe(attr_df[["feature", "value", "shap_value", "impact"]], use_container_width=True)
    else:
        st.info("No flows available to inspect.")

# ==============================================================================
# TAB 3: SOAR & ACTIVE RESPONSE
# ==============================================================================
elif active_tab == "⚡ SOAR Active Remediation":
    st.header("⚡ SOAR Remediation Console & Safety Controls")
    
    # Allowlist Banner
    st.success(f"🔒 **Immutable Allowlist Active:** {', '.join(sorted(list(IMMUTABLE_ALLOWLIST)))} (CAN NEVER BE QUARANTINED)")

    col_s1, col_s2 = st.columns(2)
    with col_s1:
        st.subheader("Active Quarantine Action")
        with st.form("quarantine_form"):
            target_ip_input = st.text_input("Target Attacker IP to Quarantine:", placeholder="e.g. 198.51.100.23")
            quarantine_reason = st.text_input("Reason:", value="Automated NIDS high-confidence threat detection")
            quarantine_mitre = st.selectbox("MITRE Technique:", ["T1498.001 (DoS)", "T1046 (Port Scan)", "T1110.001 (Brute Force)", "Manual"])
            submit_q = st.form_submit_button("🚨 Quarantine Attacker IP")

            if submit_q and target_ip_input:
                try:
                    res = quarantine_ip(target_ip_input, reason=quarantine_reason, mitre_technique=quarantine_mitre)
                    st.success(f"Successfully quarantined IP {target_ip_input}! AWS rule created.")
                    st.query_params["tab"] = "soar"
                    st.session_state["top_nav_radio"] = TAB_OPTIONS[2]
                    st.rerun()
                except SecurityViolationError as e:
                    st.error(str(e))
                except Exception as e:
                    st.error(f"Quarantine failed: {e}")

    with col_s2:
        st.subheader("Restore / Reversal Action")
        active_q = list(get_quarantined_ips())
        with st.form("restore_form"):
            restore_target = st.selectbox("Select IP to Restore:", options=active_q if active_q else ["No IPs Quarantined"])
            restore_reason = st.text_input("Restore Justification:", value="False-positive clearance / Analyst review")
            submit_r = st.form_submit_button("🔓 Restore Access")

            if submit_r and restore_target and restore_target != "No IPs Quarantined":
                try:
                    res = restore_ip(restore_target, reason=restore_reason)
                    st.success(f"Restored IP {restore_target} to normal access.")
                    st.query_params["tab"] = "soar"
                    st.session_state["top_nav_radio"] = TAB_OPTIONS[2]
                    st.rerun()
                except Exception as e:
                    st.error(f"Restore failed: {e}")

    st.divider()
    st.subheader("📜 Non-Repudiation Audit Ledger (data/soar_audit.jsonl)")
    ledger_entries = verify_audit_ledger()
    if ledger_entries:
        ledger_df = pd.DataFrame(ledger_entries)
        st.dataframe(ledger_df[["timestamp", "action", "ip", "status", "operator", "mitre_technique", "tamper_evident_valid", "signature"]], use_container_width=True)
    else:
        st.info("No audit ledger events recorded yet.")
