# 🛡️ Cloud Shield: Enterprise Cloud-Native Intrusion Detection & Response System

Cloud Shield is a production-grade, cloud-native Network Intrusion Detection System (NIDS) and Security Orchestration, Automation, and Response (SOAR) platform built for Amazon Web Services (AWS). It ingests high-resolution VPC Flow Logs, performs sub-second threat classification using calibrated multi-class XGBoost models with **Zero IP Leakage**, generates sub-second **TreeSHAP** feature attributions, and executes reversible active defense with an **Immutable Allowlist**.

---

## 🌟 Key Architectural Pillars

1. **Live AWS Telemetry & Infrastructure as Code:**
   - **Enhanced VPC Flow Logs v5:** Captures full transport layer semantics (TCP flags bitmask, flow directions, packet-to-byte velocities).
   - **S3 Telemetry Data Lake:** AES-256 server-side encryption with a 1-day auto-expiry lifecycle rule to minimize FinOps costs.
   - **Target Honeypot Tier:** EC2 instance running Apache HTTPD with port 22 strictly closed (managed securely via AWS Systems Manager SSM) and port 80 open for web traffic.
   - **1-Command Provisioning & Teardown:** Automated deployment via `scripts/deploy_aws_infra.py` and clean teardown via `scripts/cleanup_aws_infra.py`.

2. **Machine Learning with Zero IP Leakage:**
   - Eliminates raw IP identifiers (`srcaddr`, `dstaddr`, `pkt-srcaddr`, `pkt-dstaddr`) from feature vectors to prevent memorization and overfitting.
   - Behavioral feature extraction: packet velocity, byte-to-packet ratios, TCP flag bitmasks (SYN, ACK, FIN, RST, PSH, URG), well-known port indicators, and connection duration.
   - High-performance multi-class **XGBoost** and **Random Forest** models with class-weighted loss calibration.

3. **Sub-Second Explainable AI (TreeSHAP):**
   - Instant (<15ms) model decision attribution using TreeSHAP with pre-computed background summaries.
   - Visual waterfall feature contributions and automated natural language SOC analyst summaries.

4. **SOAR Active Response & Safety Controls:**
   - **Immutable Allowlist:** Protection for AWS IMDS (`169.254.169.254`), default VPC gateway (`10.0.0.1`), localhost (`127.0.0.1`), and local administrator IP.
   - **Reversible Remediation:** Network ACL deny rule injection and instant one-click restoration.
   - **Non-Repudiation Audit Ledger:** Append-only ledger in `data/soar_audit.jsonl` secured with SHA-256 cryptographic signatures.

5. **SOC Analyst Dashboard (`app.py`):**
   - Cyber-themed Streamlit application with dual ingestion modes (Live S3 Polling & Instant Demo Replay).
   - Live MITRE ATT&CK framework mapping (T1046, T1498.001, T1110.001).
   - FinOps cost calculator benchmarking Cloud Shield against AWS GuardDuty (up to 85% cost reduction).

---

## 📂 Directory Layout

```
cloud-shield/
├── config.py                 # Dynamic AWS identity, paths, allowlists & MITRE maps
├── app.py                    # Streamlit SOC Analyst Dashboard & Management Console
├── requirements.txt          # Python dependencies
├── README.md                 # System documentation & architectural reference
├── data/
│   ├── build_dataset.py      # Synthetic VPC flow log generator with zero IP leakage
│   ├── sample_flows.json     # Pre-loaded scenarios for instant SOC demo replay
│   ├── synthetic_vpc_flows.csv # Training dataset
│   └── soar_audit.jsonl      # Non-repudiation cryptographic audit ledger
├── ml/
│   ├── feature_extraction.py # Zero-IP behavioral feature extraction pipeline
│   ├── train_models.py       # Multi-class XGBoost & Random Forest training
│   └── explainability.py     # Sub-second TreeSHAP waterfall explainer
├── soar/
│   └── remediation.py        # Active quarantine/restore with immutable safety guards
├── scripts/
│   ├── deploy_aws_infra.py   # Provisions VPC, EC2, S3 & Custom Flow Logs
│   ├── simulate_traffic.py   # Simulates DoS SYN flood, PortScan, and Normal flows
│   └── cleanup_aws_infra.py  # 1-command teardown of all AWS resources
├── models/
│   ├── xgboost_nids.pkl      # Trained XGBoost NIDS model
│   ├── rf_nids.pkl           # Trained Random Forest model
│   ├── preprocessor.pkl      # Scaler and column definitions
│   └── shap_background.pkl   # TreeSHAP background data summary
└── tests/
    ├── test_aws.py           # AWS STS connectivity and naming compliance tests
    ├── test_ml.py            # Zero IP Leakage and ML inference tests
    └── test_soar.py          # Allowlist safety guards and cryptographic audit tests
```

---

## 🚀 Quick Start Guide

### 1. Launch the SOC Dashboard
```bash
streamlit run app.py
```

### 2. Run the Automated Test Suite
```bash
python -m pytest tests/ -v
```

### 3. Deploy Live AWS Infrastructure (Optional)
```bash
python scripts/deploy_aws_infra.py
```

### 4. Dispatch Traffic Simulation
```bash
python scripts/simulate_traffic.py
```

### 5. Tear Down AWS Resources
```bash
python scripts/cleanup_aws_infra.py
```
