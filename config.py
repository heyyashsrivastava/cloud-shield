import os
import boto3
import requests
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
SCRIPTS_DIR = BASE_DIR / "scripts"
STATE_FILE = BASE_DIR / "infra_state.json"
AUDIT_LOG_FILE = DATA_DIR / "soar_audit.jsonl"
SAMPLE_FLOWS_FILE = DATA_DIR / "sample_flows.json"
LOCAL_FLOW_LOG_FILE = DATA_DIR / "local_target_flows.log"

# AWS Configuration Defaults
PROJECT_TAG = "CloudShield"
VPC_CIDR = "10.0.0.0/16"
SUBNET_CIDR = "10.0.1.0/24"
DEFAULT_REGION = "ap-south-1"

# Flow Log Format (AWS VPC Flow Logs v5 format with transport & tcp-flags)
FLOW_LOG_FIELDS = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log-status", "tcp-flags", "type",
    "pkt-srcaddr", "pkt-dstaddr"
]
FLOW_LOG_FORMAT = " ".join([f"${{{f}}}" for f in FLOW_LOG_FIELDS])

# Immutable Allowlist: These IPs can NEVER be quarantined by SOAR
IMMUTABLE_ALLOWLIST = {
    "10.0.0.1",          # AWS VPC default router / gateway
    "169.254.169.254",    # AWS EC2 Instance Metadata Service (IMDS)
    "127.0.0.1",          # Localhost
    "0.0.0.0",            # Default route
    "255.255.255.255"     # Broadcast
}

def get_local_admin_ip():
    """Detect the operator's public IP to add to immutable allowlist."""
    try:
        resp = requests.get("https://api.ipify.org?format=json", timeout=3)
        if resp.status_code == 200:
            return resp.json().get("ip", "127.0.0.1")
    except Exception:
        pass
    return "127.0.0.1"

# Extend allowlist with current admin IP
try:
    _admin_ip = get_local_admin_ip()
    if _admin_ip:
        IMMUTABLE_ALLOWLIST.add(_admin_ip)
except Exception:
    pass

def get_aws_session():
    """Return a boto3 Session using the active default AWS CLI credentials."""
    return boto3.Session()

def get_aws_identity():
    """Dynamically detect account ID and region from STS caller identity."""
    session = get_aws_session()
    region = session.region_name or os.environ.get("AWS_DEFAULT_REGION") or DEFAULT_REGION
    try:
        sts = session.client("sts", region_name=region)
        caller = sts.get_caller_identity()
        return {
            "account_id": caller["Account"],
            "arn": caller["Arn"],
            "user_id": caller["UserId"],
            "region": region,
            "connected": True
        }
    except Exception as e:
        return {
            "account_id": "DUMMY_ACCOUNT",
            "arn": "arn:aws:iam::123456789012:user/dummy",
            "user_id": "DUMMY_USER",
            "region": region,
            "connected": False,
            "error": str(e)
        }

def get_bucket_name(account_id: str = None, region: str = None):
    """Generate globally unique S3 bucket name for flow logs."""
    if not account_id or not region:
        identity = get_aws_identity()
        account_id = identity["account_id"]
        region = identity["region"]
    return f"cloud-shield-flow-logs-{account_id}-{region}".lower()

# MITRE ATT&CK Classification Mapping
MITRE_ATTACK_MAP = {
    0: {
        "label": "BENIGN",
        "technique_id": "N/A",
        "technique_name": "Normal Traffic",
        "tactic": "Legitimate Network Flow",
        "severity": "LOW",
        "color": "#10b981"
    },
    1: {
        "label": "PortScan",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "severity": "MEDIUM",
        "color": "#f59e0b"
    },
    2: {
        "label": "DoS_SYN",
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "tactic": "Impact",
        "severity": "CRITICAL",
        "color": "#ef4444"
    },
    3: {
        "label": "BruteForce",
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "severity": "HIGH",
        "color": "#8b5cf6"
    }
}

LABEL_NAMES = ["BENIGN", "PortScan", "DoS_SYN", "BruteForce"]
LABEL_TO_ID = {name: idx for idx, name in enumerate(LABEL_NAMES)}
