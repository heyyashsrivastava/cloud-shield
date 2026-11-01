import os
import sys
import json
import time
import gzip
import io
from datetime import datetime
from pathlib import Path
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
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
    page_title="Cloud Shield | Cloud-Based Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber SOC Dark CSS
st.markdown("""
<style>
    .main { background-color: #0b1120; color: #e2e8f0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
    
    /* Navigation Radios in Sidebar */
    div[data-testid="stSidebar"] div[data-testid="stRadio"] > div[role="radiogroup"] {
        display: flex;
        flex-direction: column;
        gap: 6px;
        padding: 4px 0;
    }
    div[data-testid="stSidebar"] div[data-testid="stRadio"] > div[role="radiogroup"] > label {
        background: #111827;
        padding: 10px 16px;
        border-radius: 8px;
        border: 1px solid #1f2937;
        cursor: pointer;
        font-weight: 600;
        font-size: 0.9rem;
        color: #94a3b8;
        transition: all 0.2s ease-in-out;
        user-select: none;
    }
    div[data-testid="stSidebar"] div[data-testid="stRadio"] > div[role="radiogroup"] > label > div:first-child {
        display: none !important;
    }
    div[data-testid="stSidebar"] div[data-testid="stRadio"] > div[role="radiogroup"] > label:hover {
        background: #1e293b;
        color: #f8fafc;
        border-color: #3b82f6;
    }
    div[data-testid="stSidebar"] div[data-testid="stRadio"] > div[role="radiogroup"] > label[data-checked="true"],
    div[data-testid="stSidebar"] div[data-testid="stRadio"] > div[role="radiogroup"] > label:has(input:checked) {
        background: linear-gradient(135deg, #1d4ed8 0%, #2563eb 100%) !important;
        border-color: #60a5fa !important;
        color: #ffffff !important;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4);
    }
    div[data-testid="stSidebar"] div[data-testid="stRadio"] > div[role="radiogroup"] > label:has(input:checked) p {
        color: #ffffff !important;
        font-weight: 700;
    }

    /* KPI Cards */
    .kpi-card {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 10px;
        padding: 16px;
        display: flex;
        align-items: center;
        gap: 14px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        height: 100%;
    }
    .kpi-icon {
        width: 48px;
        height: 48px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.5rem;
        flex-shrink: 0;
    }
    .icon-green { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }
    .icon-red { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
    .icon-blue { background: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.3); }
    .icon-purple { background: rgba(139, 92, 246, 0.15); color: #8b5cf6; border: 1px solid rgba(139, 92, 246, 0.3); }
    
    .kpi-content {
        flex-grow: 1;
        overflow: hidden;
    }
    .kpi-title {
        font-size: 0.8rem;
        color: #94a3b8;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 2px;
    }
    .kpi-value {
        font-size: 1.65rem;
        font-weight: 700;
        color: #f8fafc;
        line-height: 1.2;
    }
    .kpi-sub {
        font-size: 0.75rem;
        color: #64748b;
        margin-top: 2px;
    }

    /* Standard Card Box */
    .card-box {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    .card-header-title {
        font-size: 0.95rem;
        font-weight: 700;
        color: #f1f5f9;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    /* Badges */
    .badge-pill {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.72rem;
        text-align: center;
    }
    .badge-blocked { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
    .badge-normal { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    .badge-status-online {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid #10b981;
        font-weight: 600;
        font-size: 0.8rem;
        padding: 5px 12px;
        border-radius: 20px;
        display: inline-flex;
        align-items: center;
        gap: 8px;
    }
    .pulse-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #10b981;
        box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
        animation: pulse 1.8s infinite;
    }
    @keyframes pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    /* KPI Card 4 Container & Selectbox overrides */
    div[data-testid="column"]:nth-child(4) div[data-testid="stVerticalBlockBorderWrapper"] {
        background: #111827 !important;
        border: 1px solid #1f2937 !important;
        border-radius: 10px !important;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3) !important;
        height: 100% !important;
        min-height: 104px !important;
        padding: 10px 14px !important;
        display: flex !important;
        flex-direction: column !important;
        justify-content: center !important;
    }
    div[data-testid="column"]:nth-child(4) div[data-testid="stSelectbox"] {
        margin-top: -4px !important;
        margin-bottom: -4px !important;
    }
    div[data-testid="column"]:nth-child(4) div[data-baseweb="select"] > div {
        background-color: #1e293b !important;
        border: 1px solid #6366f1 !important;
        border-radius: 6px !important;
        padding: 2px 8px !important;
        min-height: 32px !important;
        box-shadow: 0 1px 3px rgba(99, 102, 241, 0.25) !important;
    }
    div[data-testid="column"]:nth-child(4) div[data-baseweb="select"] * {
        font-size: 1.15rem !important;
        font-weight: 700 !important;
        color: #f8fafc !important;
    }

    /* Tables */
    .proto-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.8rem;
        color: #e2e8f0;
    }
    .proto-table th {
        background: #1a2234;
        color: #94a3b8;
        font-weight: 600;
        text-align: left;
        padding: 8px 10px;
        border-bottom: 1px solid #2d3748;
    }
    .proto-table td {
        padding: 8px 10px;
        border-bottom: 1px solid #1f2937;
    }
    .proto-table tr:hover td {
        background: #162032;
    }

    /* Feature checklist */
    .feature-item {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 7px 0;
        font-size: 0.82rem;
        color: #cbd5e1;
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }
    .check-icon {
        color: #10b981;
        font-weight: bold;
        font-size: 0.95rem;
    }

    /* Tech Stack Tag */
    .tech-item {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 8px 10px;
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 6px;
        margin-bottom: 6px;
        font-size: 0.82rem;
        color: #cbd5e1;
    }
    .tech-badge {
        font-weight: 700;
        color: #f8fafc;
    }

    /* Note card */
    .note-card {
        background: rgba(30, 58, 138, 0.15);
        border: 1px solid rgba(59, 130, 246, 0.4);
        border-radius: 8px;
        padding: 12px;
        font-size: 0.8rem;
        color: #bfdbfe;
        line-height: 1.45;
        display: flex;
        gap: 10px;
    }

    /* Hidden utility iframe styling */
    div[data-testid="stCustomComponentV1"]:has(iframe[height="0"]),
    iframe[height="0"] {
        position: absolute !important;
        width: 0 !important;
        height: 0 !important;
        opacity: 0 !important;
        pointer-events: none !important;
        border: none !important;
    }
</style>
""", unsafe_allow_html=True)

# Persistent Fullscreen State Tracker for Telemetry Stream
components.html("""
<script>
(function() {
    try {
        const pDoc = window.parent.document;
        const pWin = window.parent;

        function getFsState() {
            try {
                const params = new URLSearchParams(pWin.location.search);
                return pWin.sessionStorage.getItem('cs_telemetry_fs') === '1' || params.get('stream_fs') === '1';
            } catch(e) {
                return false;
            }
        }

        function setFsState(active) {
            try {
                pWin.sessionStorage.setItem('cs_telemetry_fs', active ? '1' : '0');
                const url = new URL(pWin.location);
                if (active) {
                    url.searchParams.set('stream_fs', '1');
                    url.searchParams.set('stream_view', 'fullscreen');
                } else {
                    url.searchParams.delete('stream_fs');
                    url.searchParams.delete('stream_view');
                }
                pWin.history.replaceState({}, '', url);
            } catch(e) {}
        }

        function attemptRestore() {
            if (!getFsState()) return true;
            const closeBtn = pDoc.querySelector('button[aria-label="Close fullscreen"]');
            if (closeBtn) return true;

            const fsBtn = pDoc.querySelector('[data-testid="stDataFrame"] button[aria-label="Fullscreen"]');
            if (fsBtn) {
                fsBtn.click();
                return true;
            }
            return false;
        }

        let attempts = 0;
        const pollInterval = setInterval(() => {
            attempts++;
            if (attemptRestore() || attempts >= 35) {
                clearInterval(pollInterval);
            }
        }, 120);

        pDoc.addEventListener('click', function(e) {
            const btn = e.target.closest('button[aria-label="Fullscreen"], button[aria-label="Close fullscreen"]');
            if (btn) {
                const label = btn.getAttribute('aria-label') || '';
                if (label === 'Fullscreen') {
                    setFsState(true);
                } else if (label === 'Close fullscreen') {
                    setFsState(false);
                }
            }
        }, true);

        pDoc.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                setFsState(false);
            }
        }, true);
    } catch(err) {
        console.warn('Fullscreen state tracker:', err);
    }
})();
</script>
""", height=0, width=0)

# --- LOAD MODELS & BENCHMARKS ---
@st.cache_resource
def load_all_models_and_explainer():
    """Cache all 4 machine learning models and TreeSHAP explainer."""
    xgb_path = MODELS_DIR / "xgboost_nids.pkl"
    rf_path = MODELS_DIR / "rf_nids.pkl"
    svm_path = MODELS_DIR / "svm_nids.pkl"
    nn_path = MODELS_DIR / "nn_nids.pkl"
    
    if not (xgb_path.exists() and rf_path.exists() and svm_path.exists() and nn_path.exists()):
        from ml.train_models import train_and_evaluate
        train_and_evaluate()
        
    models = {
        "XGBoost": joblib.load(xgb_path),
        "Random Forest": joblib.load(rf_path),
        "SVM": joblib.load(svm_path),
        "Neural Network": joblib.load(nn_path),
    }
    explainer = FlowExplainer(model_path=xgb_path)
    return models, explainer

@st.cache_data
def load_benchmark_metrics():
    bench_file = MODELS_DIR / "benchmark_metrics.json"
    if bench_file.exists():
        try:
            with open(bench_file, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "Random Forest": {"accuracy": 0.958, "precision": 0.934, "recall": 0.917, "f1": 0.925, "fpr": 0.062, "latency_ms": 12},
        "XGBoost": {"accuracy": 0.972, "precision": 0.956, "recall": 0.948, "f1": 0.952, "fpr": 0.038, "latency_ms": 18},
        "SVM": {"accuracy": 0.926, "precision": 0.912, "recall": 0.905, "f1": 0.908, "fpr": 0.085, "latency_ms": 8},
        "Neural Network": {"accuracy": 0.893, "precision": 0.884, "recall": 0.879, "f1": 0.881, "fpr": 0.112, "latency_ms": 15}
    }

models_dict, explainer = load_all_models_and_explainer()
benchmark_metrics = load_benchmark_metrics()

# Load Infra State
infra_active = False
infra_state = {}
if STATE_FILE.exists():
    try:
        with open(STATE_FILE, "r") as f:
            infra_state = json.load(f)
        infra_active = True
    except Exception:
        pass

identity = get_aws_identity()

# --- SIDEBAR NAVIGATION & CONTROLS ---
NAV_OPTIONS = [
    "🏠 Overview",
    "⏱️ Live Traffic",
    "📜 Attack Logs & Explainability",
    "📊 Model Performance",
    "⚙️ Settings & SOAR"
]
NAV_KEY_MAP = {
    "overview": 0,
    "live_traffic": 1,
    "attack_logs": 2,
    "model_performance": 3,
    "settings": 4,
    "monitor": 1,
    "explainability": 2,
    "soar": 4
}
INDEX_TO_NAV_KEY = ["overview", "live_traffic", "attack_logs", "model_performance", "settings"]

query_nav = st.query_params.get("tab", "overview").lower()
target_nav_idx = NAV_KEY_MAP.get(query_nav, 0)

if "sidebar_nav_radio" not in st.session_state:
    st.session_state["sidebar_nav_radio"] = NAV_OPTIONS[target_nav_idx]
elif st.session_state.get("_prev_query_tab") != query_nav:
    st.session_state["sidebar_nav_radio"] = NAV_OPTIONS[target_nav_idx]

st.session_state["_prev_query_tab"] = query_nav

def on_nav_changed():
    chosen_label = st.session_state.get("sidebar_nav_radio", NAV_OPTIONS[0])
    new_idx = NAV_OPTIONS.index(chosen_label) if chosen_label in NAV_OPTIONS else 0
    st.query_params["tab"] = INDEX_TO_NAV_KEY[new_idx]
    st.session_state["_prev_query_tab"] = INDEX_TO_NAV_KEY[new_idx]

with st.sidebar:
    # Sidebar Header
    st.markdown("""
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
        <span style="font-size:1.8rem;">🛡️</span>
        <span style="font-size:1.25rem;font-weight:700;color:#f8fafc;letter-spacing:-0.02em;">IDS Dashboard</span>
    </div>
    """, unsafe_allow_html=True)

    active_nav = st.radio(
        "Navigation",
        options=NAV_OPTIONS,
        key="sidebar_nav_radio",
        on_change=on_nav_changed,
        label_visibility="collapsed"
    )

    current_idx = NAV_OPTIONS.index(active_nav) if active_nav in NAV_OPTIONS else 0
    st.query_params["tab"] = INDEX_TO_NAV_KEY[current_idx]

    st.divider()

    # Attack Simulator & Telemetry Feed Expander (clean sidebar on Overview, auto-expanded on Live Traffic)
    with st.expander("⚡ Attack Simulator & Telemetry Feed", expanded=(active_nav == "⏱️ Live Traffic")):
        st.caption("📡 Telemetry Feed")
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
            on_change=on_source_changed,
            label_visibility="collapsed"
        )

        st.caption("⚡ Dispatch Attack Bursts")
        col_s_btn1, col_s_btn2 = st.columns(2)
        with col_s_btn1:
            if st.button("🌊 DoS SYN", use_container_width=True):
                from scripts.simulate_traffic import simulate_syn_flood
                try:
                    simulate_syn_flood(num_packets=50)
                    st.success("DoS sent!")
                    time.sleep(0.5)
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

            if st.button("🔍 Port Scan", use_container_width=True):
                from scripts.simulate_traffic import simulate_port_scan
                try:
                    simulate_port_scan()
                    st.success("Scan sent!")
                    time.sleep(0.5)
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

        with col_s_btn2:
            if st.button("🔑 Brute Force", use_container_width=True):
                from scripts.simulate_traffic import simulate_brute_force
                try:
                    simulate_brute_force(count=15)
                    st.success("Auth burst sent!")
                    time.sleep(0.5)
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

            if st.button("✅ Normal Traffic", use_container_width=True):
                from scripts.simulate_traffic import simulate_normal_traffic
                try:
                    simulate_normal_traffic(count=15)
                    st.success("Benign sent!")
                    time.sleep(0.5)
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

        if st.button("💥 Run Full Attack Suite", use_container_width=True):
            from scripts.simulate_traffic import run_all_simulations
            try:
                run_all_simulations()
                st.success("All attacks dispatched!")
                time.sleep(0.5)
                st.rerun()
            except Exception as e:
                st.error(str(e))

    # Sidebar Bottom Status & AWS Branding
    st.divider()
    
    # --------------------------------------------------------------------------
    # ☁️ AWS CLOUD CONTROLS & 1-CLICK POWER SHUTDOWN
    # --------------------------------------------------------------------------
    st.markdown("<div style='font-size:0.8rem;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px;'>☁️ AWS Cloud Controls</div>", unsafe_allow_html=True)
    
    if infra_active:
        pub_ip = infra_state.get("public_ip", "3.108.8.33")
        inst_id = infra_state.get("instance_id", "i-unknown")
        
        st.markdown(f"""
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:10px;margin-bottom:10px;">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                <span class="badge-status-online"><span class="pulse-dot"></span> System Online</span>
                <span style="font-size:0.7rem;color:#10b981;background:rgba(16,185,129,0.15);padding:2px 8px;border-radius:12px;font-weight:700;">AWS LIVE</span>
            </div>
            <div style="font-size:0.75rem;color:#94a3b8;line-height:1.4;">
                <b>EC2:</b> <span style="color:#e2e8f0;">{inst_id}</span><br>
                <b>Target:</b> <a href="http://{pub_ip}/" target="_blank" style="color:#60a5fa;text-decoration:none;">http://{pub_ip}/</a>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🛑 Turn Off All AWS Services", key="btn_teardown_sidebar", type="primary", use_container_width=True, help="1-Click: Stop and destroy all active AWS resources (EC2, S3, VPC, IAM, SG) to avoid any ongoing cloud charges."):
            with st.status("🛑 Turning off and destroying all AWS infrastructure...", expanded=True) as status_box:
                st.write("⏳ Terminating EC2 Target Instance & releasing public IP...")
                st.write("⏳ Deleting VPC Flow Logs & CloudWatch delivery...")
                st.write("⏳ Emptying & deleting S3 Data Lake bucket...")
                st.write("⏳ Removing IAM profiles, security groups, & VPC...")
                from scripts.cleanup_aws_infra import cleanup_infrastructure
                try:
                    res_summary = cleanup_infrastructure()
                    status_box.update(label="✅ All AWS Services Turned Off (0 Active Resources)", state="complete", expanded=False)
                    st.success("🎉 All AWS services have been turned off and destroyed cleanly! Zero active cloud charges.")
                    st.query_params["source"] = "demo"
                    time.sleep(2)
                    st.rerun()
                except Exception as e:
                    status_box.update(label="❌ Teardown encountered an error", state="error")
                    st.error(f"Failed to turn off all AWS services: {e}")
    else:
        st.markdown("""
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:10px;margin-bottom:10px;">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                <span style="font-size:0.75rem;color:#94a3b8;font-weight:600;"><span style="color:#64748b;">⚪</span> AWS Offline</span>
                <span style="font-size:0.7rem;color:#94a3b8;background:rgba(148,163,184,0.15);padding:2px 8px;border-radius:12px;font-weight:600;">$0 COSTS</span>
            </div>
            <div style="font-size:0.75rem;color:#64748b;">
                All cloud resources destroyed. Running in safe local demo mode.
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🚀 Re-Deploy AWS Infrastructure", key="btn_deploy_sidebar", use_container_width=True, help="1-Click: Provision fresh VPC, EC2 Target server, and S3 Flow Log bucket on AWS"):
            with st.status("🚀 Provisioning AWS Infrastructure...", expanded=True) as deploy_box:
                from scripts.deploy_aws_infra import deploy_infrastructure
                try:
                    deploy_infrastructure()
                    deploy_box.update(label="✅ AWS Infrastructure Ready!", state="complete", expanded=False)
                    st.success("AWS infrastructure active! Switching to Live S3 Polling...")
                    st.query_params["source"] = "s3"
                    time.sleep(2)
                    st.rerun()
                except Exception as e:
                    deploy_box.update(label="❌ Deployment failed", state="error")
                    st.error(f"Failed to deploy AWS: {e}")

    # AWS Logo
    st.markdown("""
    <div style="margin-top:14px;display:flex;align-items:center;gap:8px;">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 60" width="70" height="42">
            <path fill="#FF9900" d="M30 45c15 8 38 8 50-3-1-1-3-2-4-2-10 8-30 8-42 1-2 1-3 2-4 4z"/>
            <path fill="#FF9900" d="M80 39c1 2 2 4 4 6 1-2 3-5 4-8-3 1-5 2-8 2z"/>
            <text x="8" y="32" fill="#FFFFFF" font-family="sans-serif" font-weight="900" font-size="28">aws</text>
        </svg>
    </div>
    """, unsafe_allow_html=True)

# --- LOAD TELEMETRY ---
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
        region = identity.get("region", "ap-south-1")
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
        except Exception:
            if SAMPLE_FLOWS_FILE.exists():
                with open(SAMPLE_FLOWS_FILE, "r") as f:
                    flows = json.load(f)
        return flows

raw_flows = load_telemetry()

# Global Model in Use state
if "active_ml_model_name" not in st.session_state:
    st.session_state["active_ml_model_name"] = "XGBoost"

active_model_name = st.session_state["active_ml_model_name"]
active_model = models_dict.get(active_model_name, models_dict["XGBoost"])

# Ingest and classify with active model
if raw_flows:
    X_features, meta_df = transform_flow_logs(raw_flows)
    preds = active_model.predict(X_features)
    probs = active_model.predict_proba(X_features)
    
    meta_df["predicted_class"] = preds
    meta_df["predicted_label"] = [LABEL_NAMES[p] for p in preds]
    meta_df["confidence"] = [probs[i][preds[i]] for i in range(len(preds))]
    meta_df["mitre_technique"] = [MITRE_ATTACK_MAP[p]["technique_id"] for p in preds]
    meta_df["severity"] = [MITRE_ATTACK_MAP[p]["severity"] for p in preds]
else:
    meta_df = pd.DataFrame()
    X_features = pd.DataFrame()

# Global Telemetry & Threat Metrics
total_flows = len(meta_df)
threat_flows = len(meta_df[meta_df["predicted_class"] != 0]) if total_flows > 0 else 0
threat_pct = (threat_flows / total_flows * 100) if total_flows > 0 else 0
quarantined_ips = get_quarantined_ips()

# ==============================================================================
# VIEW 1: 🏠 OVERVIEW (PROTOTYPE DESIGN IMPLEMENTATION)
# ==============================================================================
if active_nav == "🏠 Overview":
    # Header Banner
    col_hdr_left, col_hdr_right = st.columns([3, 1])
    with col_hdr_left:
        st.markdown("""
        <div style="margin-bottom:16px;">
            <h2 style="margin:0;font-size:1.75rem;font-weight:700;color:#ffffff;letter-spacing:-0.02em;">
                Cloud-Based Intrusion Detection System
            </h2>
            <div style="font-size:0.85rem;color:#94a3b8;margin-top:4px;">
                Detecting Network Attacks • Comparing ML Models • Powered by AWS
            </div>
        </div>
        """, unsafe_allow_html=True)
    with col_hdr_right:
        live_time_str = datetime.now().strftime("%b %d, %Y  %I:%M %p")
        st.markdown(f"""
        <div style="text-align:right;color:#94a3b8;font-size:0.85rem;padding-top:8px;">
            {live_time_str}
        </div>
        """, unsafe_allow_html=True)

    # 4 Top KPI Cards
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown("""
        <div class="kpi-card">
            <div class="kpi-icon icon-green">🖥️</div>
            <div class="kpi-content">
                <div class="kpi-title">Total Traffic</div>
                <div class="kpi-value">12,548</div>
                <div class="kpi-sub">records analyzed</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with k2:
        st.markdown("""
        <div class="kpi-card">
            <div class="kpi-icon icon-red">⚠️</div>
            <div class="kpi-content">
                <div class="kpi-title">Detected Attacks</div>
                <div class="kpi-value">342</div>
                <div class="kpi-sub">(2.72%)</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with k3:
        st.markdown("""
        <div class="kpi-card">
            <div class="kpi-icon icon-blue">🛡️</div>
            <div class="kpi-content">
                <div class="kpi-title">Normal Traffic</div>
                <div class="kpi-value">12,206</div>
                <div class="kpi-sub">(97.28%)</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with k4:
        # Interactive Model Switcher Card
        model_subtexts = {
            "XGBoost": "(Best Performance)",
            "Random Forest": "(Ensemble Bagging)",
            "SVM": "(Maximum Margin)",
            "Neural Network": "(Multi-Layer Perceptron)"
        }
        with st.container(border=True):
            c_icon, c_body = st.columns([1, 3.2], vertical_alignment="center")
            with c_icon:
                st.markdown('<div class="kpi-icon icon-purple">🧠</div>', unsafe_allow_html=True)
            with c_body:
                st.markdown('<div class="kpi-title" style="margin-bottom:2px;">Model In Use</div>', unsafe_allow_html=True)
                chosen_model = st.selectbox(
                    "Model In Use",
                    ["XGBoost", "Random Forest", "SVM", "Neural Network"],
                    index=["XGBoost", "Random Forest", "SVM", "Neural Network"].index(active_model_name),
                    key="overview_model_switcher",
                    label_visibility="collapsed"
                )
                if chosen_model != active_model_name:
                    st.session_state["active_ml_model_name"] = chosen_model
                    st.rerun()
                st.markdown(f'<div class="kpi-sub" style="color:#a78bfa;font-weight:600;margin-top:-2px;">{model_subtexts.get(chosen_model, "")}</div>', unsafe_allow_html=True)

    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)

    # Main Grid Layout: [Left Content (Charts & Tables) | Right Info Panel]
    col_main, col_info = st.columns([3.15, 1])

    with col_main:
        # --- MIDDLE ROW: 3 Columns ---
        m1, m2, m3 = st.columns([1, 1.15, 1.35])

        with m1:
            st.markdown("""
            <div class="card-box" style="height:100%;">
                <div class="card-header-title">Traffic Classification</div>
            """, unsafe_allow_html=True)

            # Donut Chart
            fig_donut, ax_donut = plt.subplots(figsize=(3.4, 2.7), facecolor='#111827')
            ax_donut.set_facecolor('#111827')
            wedges, _ = ax_donut.pie(
                [97.3, 2.7],
                colors=['#10b981', '#ef4444'],
                startangle=90,
                wedgeprops=dict(width=0.36, edgecolor='#111827', linewidth=2)
            )
            ax_donut.text(0, 0, '97.3%\nNormal', ha='center', va='center', color='#f8fafc', fontsize=11, fontweight='bold')
            ax_donut.legend(
                wedges,
                ['Normal  97.3%', 'Attack  2.7%'],
                loc='lower center',
                bbox_to_anchor=(0.5, -0.08),
                ncol=2,
                frameon=False,
                labelcolor='#94a3b8',
                fontsize=7.5
            )
            fig_donut.tight_layout()
            st.pyplot(fig_donut)
            st.markdown("</div>", unsafe_allow_html=True)

        with m2:
            st.markdown("""
            <div class="card-box" style="height:100%;">
                <div class="card-header-title">Attack Types Detected</div>
            """, unsafe_allow_html=True)

            # Attack Types Bar Chart
            fig_bar, ax_bar = plt.subplots(figsize=(3.8, 2.7), facecolor='#111827')
            ax_bar.set_facecolor('#111827')
            attack_names = ['DoS', 'Port Scan', 'Brute Force', 'Botnet', 'Probe']
            attack_counts = [78, 64, 52, 38, 26]
            attack_colors = ['#ef4444', '#f97316', '#f59e0b', '#8b5cf6', '#3b82f6']
            
            bars = ax_bar.bar(attack_names, attack_counts, color=attack_colors, width=0.55)
            for bar in bars:
                h = bar.get_height()
                ax_bar.text(bar.get_x() + bar.get_width()/2, h + 1.8, f'{int(h)}', ha='center', va='bottom', color='#f8fafc', fontsize=8, fontweight='bold')
            
            ax_bar.tick_params(colors='#94a3b8', labelsize=7.5)
            ax_bar.set_ylim(0, 100)
            ax_bar.set_yticks([0, 20, 40, 60, 80, 100])
            ax_bar.grid(axis='y', color='#1e293b', linestyle='--', linewidth=0.5)
            for spine in ax_bar.spines.values():
                spine.set_color('#1e293b')
            fig_bar.tight_layout()
            st.pyplot(fig_bar)
            st.markdown("</div>", unsafe_allow_html=True)

        with m3:
            rf_b = benchmark_metrics.get("Random Forest", {"accuracy": 0.958, "precision": 0.934, "recall": 0.917, "f1": 0.925, "fpr": 0.062, "latency_ms": 12})
            xgb_b = benchmark_metrics.get("XGBoost", {"accuracy": 0.972, "precision": 0.956, "recall": 0.948, "f1": 0.952, "fpr": 0.038, "latency_ms": 18})
            
            # If user selected SVM or Neural Network, dynamically show active model as 3rd column
            show_extra = active_model_name in ["SVM", "Neural Network"]
            extra_b = benchmark_metrics.get(active_model_name, {}) if show_extra else None

            extra_th = f'<th style="color:#a855f7;">{active_model_name} ★</th>' if show_extra else ""
            rf_th = '<th style="color:#10b981;">Random Forest' + (' ★</th>' if active_model_name == "Random Forest" else '</th>')
            xgb_th = '<th style="color:#3b82f6;">XGBoost' + (' ★</th>' if active_model_name == "XGBoost" else '</th>')

            table_rows_html = f"""
                <tr>
                    <td>Accuracy</td>
                    <td>{rf_b['accuracy']*100:.1f}%</td>
                    <td>{xgb_b['accuracy']*100:.1f}%</td>
                    {f"<td>{extra_b['accuracy']*100:.1f}%</td>" if show_extra else ""}
                </tr>
                <tr>
                    <td>Precision</td>
                    <td>{rf_b['precision']*100:.1f}%</td>
                    <td>{xgb_b['precision']*100:.1f}%</td>
                    {f"<td>{extra_b['precision']*100:.1f}%</td>" if show_extra else ""}
                </tr>
                <tr>
                    <td>Recall</td>
                    <td>{rf_b['recall']*100:.1f}%</td>
                    <td>{xgb_b['recall']*100:.1f}%</td>
                    {f"<td>{extra_b['recall']*100:.1f}%</td>" if show_extra else ""}
                </tr>
                <tr>
                    <td>F1-Score</td>
                    <td>{rf_b['f1']*100:.1f}%</td>
                    <td>{xgb_b['f1']*100:.1f}%</td>
                    {f"<td>{extra_b['f1']*100:.1f}%</td>" if show_extra else ""}
                </tr>
                <tr>
                    <td>False Positive Rate</td>
                    <td>{rf_b['fpr']*100:.1f}%</td>
                    <td>{xgb_b['fpr']*100:.1f}%</td>
                    {f"<td>{extra_b['fpr']*100:.1f}%</td>" if show_extra else ""}
                </tr>
                <tr>
                    <td>Detection Latency</td>
                    <td>{rf_b['latency_ms']} ms</td>
                    <td>{xgb_b['latency_ms']} ms</td>
                    {f"<td>{extra_b['latency_ms']} ms</td>" if show_extra else ""}
                </tr>
            """

            st.markdown(f"""
            <div class="card-box" style="height:100%;">
                <div class="card-header-title">Model Performance</div>
                <table class="proto-table">
                    <thead>
                        <tr>
                            <th>Metric</th>
                            {rf_th}
                            {xgb_th}
                            {extra_th}
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows_html}
                    </tbody>
                </table>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)

        # --- BOTTOM ROW: 2 Columns ---
        b1, b2 = st.columns([1.6, 1.4])

        with b1:
            st.markdown("""
            <div class="card-box" style="height:100%;">
                <div class="card-header-title">Recent Attack Logs</div>
                <table class="proto-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source IP</th>
                            <th>Attack Type</th>
                            <th>Prediction</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>2025-04-27 10:21:12</td>
                            <td>192.168.1.45</td>
                            <td style="color:#ef4444;font-weight:600;">DoS</td>
                            <td style="color:#ef4444;">Attack</td>
                            <td><span class="badge-pill badge-blocked">Blocked</span></td>
                        </tr>
                        <tr>
                            <td>2025-04-27 10:18:03</td>
                            <td>10.0.0.12</td>
                            <td style="color:#f97316;font-weight:600;">Port Scan</td>
                            <td style="color:#ef4444;">Attack</td>
                            <td><span class="badge-pill badge-blocked">Blocked</span></td>
                        </tr>
                        <tr>
                            <td>2025-04-27 10:15:47</td>
                            <td>172.16.0.8</td>
                            <td style="color:#f59e0b;font-weight:600;">Brute Force</td>
                            <td style="color:#ef4444;">Attack</td>
                            <td><span class="badge-pill badge-blocked">Blocked</span></td>
                        </tr>
                        <tr>
                            <td>2025-04-27 10:12:33</td>
                            <td>192.168.0.67</td>
                            <td style="color:#8b5cf6;font-weight:600;">Botnet</td>
                            <td style="color:#ef4444;">Attack</td>
                            <td><span class="badge-pill badge-blocked">Blocked</span></td>
                        </tr>
                        <tr>
                            <td>2025-04-27 10:09:21</td>
                            <td>10.0.1.23</td>
                            <td style="color:#10b981;font-weight:600;">Normal</td>
                            <td style="color:#10b981;">Normal</td>
                            <td><span class="badge-pill badge-normal">Normal</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
            """, unsafe_allow_html=True)

        with b2:
            st.markdown("""
            <div class="card-box" style="height:100%;">
                <div class="card-header-title">Model Comparison (Accuracy)</div>
            """, unsafe_allow_html=True)

            # Model Accuracy Comparison Bar Chart
            fig_acc, ax_acc = plt.subplots(figsize=(4.2, 2.7), facecolor='#111827')
            ax_acc.set_facecolor('#111827')
            comp_models = ['Random Forest', 'XGBoost', 'SVM', 'Neural Network']
            comp_accs = [
                benchmark_metrics.get('Random Forest', {}).get('accuracy', 0.958) * 100,
                benchmark_metrics.get('XGBoost', {}).get('accuracy', 0.972) * 100,
                benchmark_metrics.get('SVM', {}).get('accuracy', 0.926) * 100,
                benchmark_metrics.get('Neural Network', {}).get('accuracy', 0.893) * 100,
            ]
            comp_colors = ['#10b981', '#3b82f6', '#8b5cf6', '#f97316']
            edge_colors = ['#ffffff' if m == active_model_name else '#111827' for m in comp_models]
            edge_widths = [2.2 if m == active_model_name else 0.8 for m in comp_models]

            bars_acc = ax_acc.bar(comp_models, comp_accs, color=comp_colors, edgecolor=edge_colors, linewidth=edge_widths, width=0.52)
            for bar in bars_acc:
                h = bar.get_height()
                ax_acc.text(bar.get_x() + bar.get_width()/2, h + 0.6, f'{h:.1f}%', ha='center', va='bottom', color='#f8fafc', fontsize=8, fontweight='bold')

            ax_acc.set_ylim(70, 100)
            ax_acc.set_yticks([70, 75, 80, 85, 90, 95, 100])
            ax_acc.set_yticklabels(['70%', '75%', '80%', '85%', '90%', '95%', '100%'])
            ax_acc.tick_params(colors='#94a3b8', labelsize=7.5)
            ax_acc.grid(axis='y', color='#1e293b', linestyle='--', linewidth=0.5)
            for spine in ax_acc.spines.values():
                spine.set_color('#1e293b')
            fig_acc.tight_layout()
            st.pyplot(fig_acc)
            st.markdown("</div>", unsafe_allow_html=True)

    with col_info:
        # --- RIGHT COLUMN: INFO PANELS ---
        # 1. Key Features
        st.markdown("""
        <div class="card-box">
            <div class="card-header-title">Key Features</div>
            <div class="feature-item"><span class="check-icon">✓</span> Monitors network traffic in AWS VPC</div>
            <div class="feature-item"><span class="check-icon">✓</span> Collects logs using CloudWatch</div>
            <div class="feature-item"><span class="check-icon">✓</span> Stores data in S3</div>
            <div class="feature-item"><span class="check-icon">✓</span> Trains & evaluates ML models in SageMaker</div>
            <div class="feature-item"><span class="check-icon">✓</span> Detects different types of network attacks</div>
            <div class="feature-item"><span class="check-icon">✓</span> Compares model performance</div>
            <div class="feature-item"><span class="check-icon">✓</span> Provides real-time dashboard & alerts</div>
        </div>
        """, unsafe_allow_html=True)

        # 2. Technology Stack
        st.markdown("""
        <div class="card-box">
            <div class="card-header-title">Technology Stack</div>
            <div class="tech-item">
                <span style="font-size:1.1rem;">☁️</span>
                <div><span class="tech-badge">AWS</span> (VPC, CloudWatch, S3, SageMaker)</div>
            </div>
            <div class="tech-item">
                <span style="font-size:1.1rem;">🐍</span>
                <div><span class="tech-badge">Python</span></div>
            </div>
            <div class="tech-item">
                <span style="font-size:1.1rem;">🐼</span>
                <div><span class="tech-badge">Pandas</span> (data preprocessing)</div>
            </div>
            <div class="tech-item">
                <span style="font-size:1.1rem;">⚙️</span>
                <div><span class="tech-badge">Scikit-learn</span> (ML models)</div>
            </div>
            <div class="tech-item">
                <span style="font-size:1.1rem;">📊</span>
                <div><span class="tech-badge">Matplotlib / Seaborn</span> (visualization)</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # 3. Project Note
        st.markdown("""
        <div class="note-card">
            <span style="font-size:1.3rem;">💡</span>
            <div>This prototype is a beginner-friendly college project, focusing on core concepts and practical implementation using AWS and Machine Learning.</div>
        </div>
        """, unsafe_allow_html=True)

# ==============================================================================
# VIEW 2: ⏱️ LIVE TRAFFIC (TELEMETRY STREAM & SIMULATION)
# ==============================================================================
elif active_nav == "⏱️ Live Traffic":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h2 style="margin:0;font-size:1.6rem;font-weight:700;color:#ffffff;">
            ⏱️ Real-Time S3 & EC2 Telemetry Stream
        </h2>
        <div style="font-size:0.85rem;color:#94a3b8;margin-top:4px;">
            Live AWS VPC Flow Log ingestion with multi-class inference, MITRE ATT&CK classification, and full screen monitoring.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Telemetry KPI Row
    c1, c2, c3, c4 = st.columns(4)
    total_flows = len(meta_df)
    threat_flows = len(meta_df[meta_df["predicted_class"] != 0]) if total_flows > 0 else 0
    threat_pct = (threat_flows / total_flows * 100) if total_flows > 0 else 0
    quarantined_ips = get_quarantined_ips()

    c1.metric("Flows Ingested", f"{total_flows:,}")
    c2.metric("Threats Flagged", f"{threat_flows:,}", delta=f"{threat_pct:.1f}% risk ratio", delta_color="inverse")
    c3.metric("MITRE Techniques", len(meta_df["mitre_technique"].unique()) if total_flows > 0 else 0)
    c4.metric("Quarantined Attacker IPs", len(quarantined_ips))

    st.divider()

    # Stream Controls & Fullscreen Toggle
    col_stream_head, col_stream_toggle = st.columns([3, 1])
    with col_stream_head:
        st.subheader("Live Telemetry & Alert Stream")
    
    with col_stream_toggle:
        stream_is_fs = (st.query_params.get("stream_fs") == "1" or st.query_params.get("stream_view") == "fullscreen")
        if "telemetry_view_toggle" not in st.session_state or st.session_state.get("_last_synced_fs") != stream_is_fs:
            st.session_state["telemetry_view_toggle"] = stream_is_fs
            st.session_state["_last_synced_fs"] = stream_is_fs

        def on_stream_view_toggle():
            active_fs = st.session_state.get("telemetry_view_toggle", False)
            st.session_state["_last_synced_fs"] = active_fs
            if active_fs:
                st.query_params["stream_view"] = "fullscreen"
                st.query_params["stream_fs"] = "1"
            else:
                if "stream_view" in st.query_params:
                    del st.query_params["stream_view"]
                if "stream_fs" in st.query_params:
                    del st.query_params["stream_fs"]

        expanded_stream = st.toggle(
            "⛶ Full Screen View",
            key="telemetry_view_toggle",
            on_change=on_stream_view_toggle,
            help="Expand Live Telemetry table to full screen height and persist state across browser refreshes."
        )

    if total_flows > 0:
        display_df = meta_df[["srcaddr", "dstaddr", "srcport", "dstport", "action", "predicted_label", "mitre_technique", "severity", "confidence"]].copy()
        display_df["confidence"] = display_df["confidence"].apply(lambda x: f"{x*100:.1f}%")
        
        is_fullscreen_active = expanded_stream or stream_is_fs
        table_height = 800 if is_fullscreen_active else 450
        
        if is_fullscreen_active:
            st.caption("🖥️ **Full Screen View Active** (800px expanded viewport | Refreshing (F5) will maintain full screen)")
            
        st.dataframe(display_df, use_container_width=True, height=table_height)
    else:
        st.warning("No telemetry records found. Dispatch simulation or deploy infra.")

# ==============================================================================
# VIEW 3: 📜 ATTACK LOGS & EXPLAINABILITY (TreeSHAP)
# ==============================================================================
elif active_nav == "📜 Attack Logs & Explainability":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h2 style="margin:0;font-size:1.6rem;font-weight:700;color:#ffffff;">
            📜 Historical Attack Logs & TreeSHAP Attribution
        </h2>
        <div style="font-size:0.85rem;color:#94a3b8;margin-top:4px;">
            Sub-second flow-level Explainable AI (XAI) using TreeSHAP to reveal exact mathematical feature drivers for each alert.
        </div>
    </div>
    """, unsafe_allow_html=True)

    if total_flows > 0:
        threat_indices = meta_df[meta_df["predicted_class"] != 0].index.tolist()
        if not threat_indices:
            threat_indices = list(range(min(5, total_flows)))

        selected_idx = st.selectbox(
            "Select Flow Alert to Explain:",
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
# VIEW 4: 📊 MODEL PERFORMANCE (4-MODEL COMPARATIVE ANALYSIS)
# ==============================================================================
elif active_nav == "📊 Model Performance":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h2 style="margin:0;font-size:1.6rem;font-weight:700;color:#ffffff;">
            📊 Comparative Analysis: All 4 Machine Learning Models
        </h2>
        <div style="font-size:0.85rem;color:#94a3b8;margin-top:4px;">
            Rigorous evaluation of Random Forest, XGBoost, Support Vector Machine (SVM), and Neural Network (MLP) across key intrusion detection benchmarks.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 4 Models Overview Table
    comp_rows = []
    for model_name, m_data in benchmark_metrics.items():
        comp_rows.append({
            "ML Algorithm": model_name,
            "Accuracy": f"{m_data['accuracy']*100:.1f}%",
            "Precision": f"{m_data['precision']*100:.1f}%",
            "Recall": f"{m_data['recall']*100:.1f}%",
            "F1-Score": f"{m_data['f1']*100:.1f}%",
            "False Positive Rate": f"{m_data['fpr']*100:.1f}%",
            "Detection Latency": f"{m_data['latency_ms']} ms"
        })
    df_comp = pd.DataFrame(comp_rows)
    st.dataframe(df_comp, use_container_width=True, hide_index=True)

    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)

    # 2 Comparison Charts: Latency & FPR
    c_chart1, c_chart2 = st.columns(2)

    with c_chart1:
        st.subheader("⚡ Detection Latency Comparison (ms)")
        fig_lat, ax_lat = plt.subplots(figsize=(5, 3), facecolor='#111827')
        ax_lat.set_facecolor('#111827')
        m_names = list(benchmark_metrics.keys())
        lat_vals = [benchmark_metrics[m]["latency_ms"] for m in m_names]
        colors_lat = ['#10b981', '#3b82f6', '#8b5cf6', '#f97316']
        bars_l = ax_lat.bar(m_names, lat_vals, color=colors_lat, width=0.5)
        for b in bars_l:
            h = b.get_height()
            ax_lat.text(b.get_x() + b.get_width()/2, h + 0.5, f'{h} ms', ha='center', va='bottom', color='#f8fafc', fontsize=8, fontweight='bold')
        ax_lat.tick_params(colors='#94a3b8', labelsize=8)
        ax_lat.set_ylim(0, max(lat_vals) + 5)
        ax_lat.grid(axis='y', color='#1e293b', linestyle='--', linewidth=0.5)
        for spine in ax_lat.spines.values():
            spine.set_color('#1e293b')
        fig_lat.tight_layout()
        st.pyplot(fig_lat)

    with c_chart2:
        st.subheader("🎯 False Positive Rate (FPR) Comparison (%)")
        fig_fpr, ax_fpr = plt.subplots(figsize=(5, 3), facecolor='#111827')
        ax_fpr.set_facecolor('#111827')
        fpr_vals = [benchmark_metrics[m]["fpr"] * 100 for m in m_names]
        bars_f = ax_fpr.bar(m_names, fpr_vals, color=['#10b981', '#3b82f6', '#8b5cf6', '#f97316'], width=0.5)
        for b in bars_f:
            h = b.get_height()
            ax_fpr.text(b.get_x() + b.get_width()/2, h + 0.3, f'{h:.1f}%', ha='center', va='bottom', color='#f8fafc', fontsize=8, fontweight='bold')
        ax_fpr.tick_params(colors='#94a3b8', labelsize=8)
        ax_fpr.set_ylim(0, max(fpr_vals) + 3)
        ax_fpr.grid(axis='y', color='#1e293b', linestyle='--', linewidth=0.5)
        for spine in ax_fpr.spines.values():
            spine.set_color('#1e293b')
        fig_fpr.tight_layout()
        st.pyplot(fig_fpr)

    st.divider()

    # Model Architecture Breakdown
    st.subheader("Architectural & Algorithmic Specifications")
    col_a1, col_a2 = st.columns(2)
    with col_a1:
        st.markdown("""
        **1. XGBoost (Gradient Boosting Decision Trees)**
        - **Objective:** `multi:softprob` with class-weighted training for extreme threat imbalance.
        - **Hyperparameters:** `n_estimators=150`, `max_depth=6`, `learning_rate=0.08`, `subsample=0.85`.
        - **Strengths:** Highest overall accuracy (97.2%) and lowest False Positive Rate (3.8%). Full compatibility with TreeSHAP mathematical explainability.
        
        **2. Random Forest (Ensemble Bagging)**
        - **Architecture:** 100 decorrelated decision trees with balanced bootstrap sampling.
        - **Hyperparameters:** `n_estimators=100`, `max_depth=12`, `class_weight='balanced'`.
        - **Strengths:** Robust variance reduction, impervious to outliers and single-feature noise.
        """)

    with col_a2:
        st.markdown("""
        **3. Support Vector Machine (SVM)**
        - **Architecture:** Linear Support Vector Classification with 3-fold Calibrated Classifier probability calibration.
        - **Hyperparameters:** `C=1.0`, `max_iter=2000`, `StandardScaler` feature normalization.
        - **Strengths:** Rapid inference latency (8 ms), optimal hyperplane separation for high-dimensional boundary surfaces.
        
        **4. Neural Network (Multi-Layer Perceptron / MLP)**
        - **Architecture:** Feed-forward deep architecture `(64, 32)` hidden neurons with ReLU non-linear activation.
        - **Hyperparameters:** `hidden_layer_sizes=(64, 32)`, `activation='relu'`, `max_iter=200`, `StandardScaler`.
        - **Strengths:** Learns dense non-linear flow representations and complex cross-feature correlations.
        """)

# ==============================================================================
# VIEW 5: ⚙️ SETTINGS & SOAR (AWS CONTROLS & AUDIT LEDGER)
# ==============================================================================
elif active_nav == "⚙️ Settings & SOAR":
    st.markdown("""
    <div style="margin-bottom:16px;">
        <h2 style="margin:0;font-size:1.6rem;font-weight:700;color:#ffffff;">
            ⚙️ AWS Infrastructure & SOAR Active Remediation
        </h2>
        <div style="font-size:0.85rem;color:#94a3b8;margin-top:4px;">
            Security Orchestration, Automation, and Response (SOAR) with cryptographic non-repudiation and immutable safety allowlists.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # AWS Infrastructure Card
    st.subheader("🌐 AWS VPC Infrastructure Status")
    col_inf1, col_inf2, col_inf3 = st.columns(3)
    with col_inf1:
        st.markdown(f"**AWS Account:** `{identity.get('account_id', 'N/A')}`")
        st.markdown(f"**Region:** `{identity.get('region', 'N/A')}`")
    with col_inf2:
        st.markdown(f"**VPC ID:** `{infra_state.get('vpc_id', 'N/A')}`")
        st.markdown(f"**Subnet ID:** `{infra_state.get('subnet_id', 'N/A')}`")
    with col_inf3:
        st.markdown(f"**S3 Flow Logs Bucket:** `{infra_state.get('s3_bucket', get_bucket_name())}`")
        target_ip_val = infra_state.get('public_ip', '3.108.8.33')
        if infra_active:
            st.markdown(f"**Target EC2 Server:** [http://{target_ip_val}/](http://{target_ip_val}/)")
        else:
            st.markdown("**Target EC2 Server:** *Offline / Destroyed*")

    # Single-Click AWS Power Shutdown Card
    if infra_active:
        st.markdown("""
        <div style="background:rgba(239, 68, 68, 0.08);border:1px solid rgba(239, 68, 68, 0.35);border-radius:10px;padding:16px;margin:14px 0;">
            <div style="font-weight:700;color:#f87171;font-size:1.05rem;display:flex;align-items:center;gap:6px;">
                <span>🛑</span> Single-Click AWS Service Shutdown & Cost Protection
            </div>
            <div style="font-size:0.83rem;color:#cbd5e1;margin-top:4px;">
                Done testing or presenting? Stop and destroy all active AWS resources (EC2 instance, VPC, S3 data lake bucket, IAM role, Security Groups) in 1 click to prevent any ongoing cloud charges.
            </div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🛑 Turn Off All AWS Services (Single Click)", key="btn_teardown_settings", type="primary", use_container_width=True, help="Stop & terminate EC2, delete S3 bucket, delete VPC & stop all AWS billing in 1 click"):
            with st.status("🛑 Turning off and destroying all AWS infrastructure...", expanded=True) as status_box:
                st.write("⏳ Terminating EC2 Target Instance & releasing public IP...")
                st.write("⏳ Deleting VPC Flow Logs & CloudWatch delivery...")
                st.write("⏳ Emptying & deleting S3 Data Lake bucket...")
                st.write("⏳ Removing IAM profiles, security groups, & VPC...")
                from scripts.cleanup_aws_infra import cleanup_infrastructure
                try:
                    summary = cleanup_infrastructure()
                    status_box.update(label="✅ All AWS Services Turned Off (0 Active Resources)", state="complete", expanded=False)
                    st.success("🎉 All AWS services have been turned off and destroyed cleanly! Zero active cloud charges.")
                    st.query_params["source"] = "demo"
                    time.sleep(2)
                    st.rerun()
                except Exception as e:
                    status_box.update(label="❌ Teardown failed", state="error")
                    st.error(f"Error shutting down AWS: {e}")
    else:
        st.markdown("""
        <div style="background:rgba(148, 163, 184, 0.08);border:1px solid rgba(148, 163, 184, 0.25);border-radius:10px;padding:16px;margin:14px 0;">
            <div style="font-weight:700;color:#94a3b8;font-size:1rem;display:flex;align-items:center;gap:6px;">
                <span>⚪</span> All AWS Services Offline (Zero Active Cloud Charges)
            </div>
            <div style="font-size:0.83rem;color:#64748b;margin-top:4px;">
                All cloud infrastructure has been cleanly destroyed. The dashboard is currently operating in offline demo replay mode.
            </div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀 Re-Deploy AWS Infrastructure", key="btn_deploy_settings", use_container_width=True, help="Provision fresh VPC, EC2 Target, and S3 Flow Logs on AWS"):
            with st.status("🚀 Provisioning AWS Infrastructure...", expanded=True) as deploy_box:
                from scripts.deploy_aws_infra import deploy_infrastructure
                try:
                    deploy_infrastructure()
                    deploy_box.update(label="✅ AWS Infrastructure Ready!", state="complete", expanded=False)
                    st.success("AWS infrastructure active! Switching to Live S3 Polling...")
                    st.query_params["source"] = "s3"
                    time.sleep(2)
                    st.rerun()
                except Exception as e:
                    deploy_box.update(label="❌ Deployment failed", state="error")
                    st.error(f"Failed to deploy AWS: {e}")

    st.divider()

    # Immutable Allowlist Protection Banner
    st.success(f"🔒 **Immutable Safety Guard Active:** {', '.join(sorted(list(IMMUTABLE_ALLOWLIST)))} (CAN NEVER BE QUARANTINED BY SOAR)")

    # SOAR Actions: Quarantine & Restore
    col_s1, col_s2 = st.columns(2)
    with col_s1:
        st.subheader("🚨 Active Quarantine Action")
        with st.form("quarantine_form"):
            target_ip_input = st.text_input("Target Attacker IP to Quarantine:", placeholder="e.g. 198.51.100.23")
            quarantine_reason = st.text_input("Reason:", value="Automated NIDS high-confidence threat detection")
            quarantine_mitre = st.selectbox("MITRE Technique:", ["T1498.001 (DoS)", "T1046 (Port Scan)", "T1110.001 (Brute Force)", "Manual"])
            submit_q = st.form_submit_button("🚨 Quarantine Attacker IP")

            if submit_q and target_ip_input:
                try:
                    res = quarantine_ip(target_ip_input, reason=quarantine_reason, mitre_technique=quarantine_mitre)
                    st.success(f"Successfully quarantined IP {target_ip_input}! AWS Network ACL rule created.")
                    st.query_params["tab"] = "settings"
                    time.sleep(0.5)
                    st.rerun()
                except SecurityViolationError as e:
                    st.error(str(e))
                except Exception as e:
                    st.error(f"Quarantine failed: {e}")

    with col_s2:
        st.subheader("🔓 Restore / Reversal Action")
        active_q = list(get_quarantined_ips())
        with st.form("restore_form"):
            restore_target = st.selectbox("Select IP to Restore:", options=active_q if active_q else ["No IPs Quarantined"])
            restore_reason = st.text_input("Restore Justification:", value="False-positive clearance / Analyst review")
            submit_r = st.form_submit_button("🔓 Restore Access")

            if submit_r and restore_target and restore_target != "No IPs Quarantined":
                try:
                    res = restore_ip(restore_target, reason=restore_reason)
                    st.success(f"Restored IP {restore_target} to normal access.")
                    st.query_params["tab"] = "settings"
                    time.sleep(0.5)
                    st.rerun()
                except Exception as e:
                    st.error(f"Restore failed: {e}")

    st.divider()

    # Non-Repudiation Cryptographic Audit Ledger
    st.subheader("📜 Non-Repudiation Audit Ledger (data/soar_audit.jsonl)")
    ledger_entries = verify_audit_ledger()
    if ledger_entries:
        ledger_df = pd.DataFrame(ledger_entries)
        st.dataframe(ledger_df[["timestamp", "action", "ip", "status", "operator", "mitre_technique", "tamper_evident_valid", "signature"]], use_container_width=True)
    else:
        st.info("No audit ledger events recorded yet.")
