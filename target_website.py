"""
Apex Financial Portal - Cloud Shield Target Honeypot Application
================================================================
A realistic, standalone enterprise banking web application representing "Apex Global Financial".
Supports dual deployment:
  1. Local Mode: Runs on http://localhost:5000 (Zero-cloud-cost local testing).
  2. Cloud EC2 Mode: Runs on port 80 when launched on AWS EC2.

Features:
  - Responsive Fintech UI (Account Overview, Live Wire Transfers, Transaction Search, Support Portal).
  - Built-in Attack Simulation Range (DoS SYN flood, Credential Brute Force, Port Recon Scan).
  - AWS VPC Flow Log v5 Bridge: Generates schema-compliant flow logs written to `data/local_target_flows.log`.
  - SOAR Active Defense Enforcement: Real-time blocking (HTTP 403 / REJECT) for IPs quarantined by Cloud Shield.
"""

import os
import sys
import time
import random
import json
import threading
import argparse
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string, Response

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

try:
    from config import (
        DATA_DIR, STATE_FILE, LOCAL_FLOW_LOG_FILE,
        get_aws_identity, IMMUTABLE_ALLOWLIST
    )
    from soar.remediation import get_quarantined_ips, is_ip_allowlisted
except ImportError:
    DATA_DIR = BASE_DIR / "data"
    STATE_FILE = BASE_DIR / "infra_state.json"
    LOCAL_FLOW_LOG_FILE = DATA_DIR / "local_target_flows.log"
    IMMUTABLE_ALLOWLIST = {"127.0.0.1", "10.0.0.1", "169.254.169.254"}
    def get_quarantined_ips():
        return set()
    def is_ip_allowlisted(ip):
        return ip in IMMUTABLE_ALLOWLIST


app = Flask(__name__)

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Lock for flow log file writes
LOG_LOCK = threading.Lock()

# In-memory recent flow logs ring buffer
MAX_RECENT_FLOWS = 200
RECENT_FLOWS = []

# Mock Transactions Database
TRANSACTIONS = [
    {"id": "TX-90214", "recipient": "Quantum Cloud Services LLC", "amount": 128450.00, "currency": "USD", "status": "Settled", "timestamp": "2026-10-31 09:12:44", "type": "Vendor Settlement"},
    {"id": "TX-90213", "recipient": "Apex European Clearing AG", "amount": 450000.00, "currency": "EUR", "status": "Settled", "timestamp": "2026-10-31 09:05:10", "type": "Interbank Wire"},
    {"id": "TX-90212", "recipient": "CipherSec Threat Intelligence", "amount": 18200.00, "currency": "USD", "status": "Settled", "timestamp": "2026-10-31 08:44:21", "type": "Security Ops"},
    {"id": "TX-90211", "recipient": "Starlight Capital Fund", "amount": 1250000.00, "currency": "USD", "status": "Settled", "timestamp": "2026-10-31 08:30:00", "type": "Treasury Allocation"},
    {"id": "TX-90210", "recipient": "Delta Global Logistics", "amount": 42100.50, "currency": "USD", "status": "Settled", "timestamp": "2026-10-31 07:15:33", "type": "Supply Chain"},
    {"id": "TX-90209", "recipient": "Tokyo Securities Corp", "amount": 890000.00, "currency": "JPY", "status": "Settled", "timestamp": "2026-10-31 06:50:18", "type": "Foreign Exchange"},
    {"id": "TX-90208", "recipient": "Borealis Energy Infrastructure", "amount": 310500.00, "currency": "EUR", "status": "Settled", "timestamp": "2026-10-31 05:42:09", "type": "Commodity Settlement"},
    {"id": "TX-90207", "recipient": "CloudFlare Edge CDN", "amount": 15400.00, "currency": "USD", "status": "Settled", "timestamp": "2026-10-31 04:18:22", "type": "Infrastructure"}
]

# Account Metrics
ACCOUNT_DATA = {
    "organization": "Apex Global Financial Corp",
    "account_number": "ACT-8419-5502-001",
    "primary_balance": 14289450.00,
    "available_credit": 5000000.00,
    "currency": "USD",
    "status": "ACTIVE_SECURE",
    "security_profile": "Cloud Shield Tier 1 Shielding"
}

def get_server_context():
    """Retrieve runtime AWS account ID and network interfaces."""
    account_id = "301276846152"
    vpc_id = "vpc-0381418a20cc9beca"
    server_ip = "10.0.1.100"
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                st = json.load(f)
                account_id = st.get("account_id", account_id)
                vpc_id = st.get("vpc_id", vpc_id)
                server_ip = st.get("private_ip") or st.get("public_ip", server_ip)
        except Exception:
            pass
    return account_id, vpc_id, server_ip

def record_flow_log(
    srcaddr: str,
    dstaddr: str,
    srcport: int,
    dstport: int,
    packets: int,
    bytes_count: int,
    tcp_flags: int,
    action: str = "ACCEPT",
    protocol: int = 6,
    duration: int = 1
) -> str:
    """
    Format and append an AWS VPC Flow Log v5 record to local file and ring buffer.
    Format: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status tcp-flags type pkt-srcaddr pkt-dstaddr
    """
    account_id, _, _ = get_server_context()
    interface_id = "eni-apex001"
    now = int(time.time())
    start_time = now - duration
    end_time = now

    line = f"5 {account_id} {interface_id} {srcaddr} {dstaddr} {srcport} {dstport} {protocol} {packets} {bytes_count} {start_time} {end_time} {action} OK {tcp_flags} IPv4 {srcaddr} {dstaddr}"

    with LOG_LOCK:
        try:
            with open(LOCAL_FLOW_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            # Rotate if log exceeds 5MB to avoid disk bloat
            if LOCAL_FLOW_LOG_FILE.stat().st_size > 5 * 1024 * 1024:
                with open(LOCAL_FLOW_LOG_FILE, "r", encoding="utf-8") as f:
                    all_lines = f.readlines()
                if len(all_lines) > 2000:
                    with open(LOCAL_FLOW_LOG_FILE, "w", encoding="utf-8") as f:
                        f.writelines(all_lines[-2000:])
        except Exception as e:
            print(f"[!] Warning: failed to write to flow log file: {e}", file=sys.stderr)

        RECENT_FLOWS.append({
            "raw_line": line,
            "version": "5",
            "account_id": account_id,
            "interface_id": interface_id,
            "srcaddr": srcaddr,
            "dstaddr": dstaddr,
            "srcport": srcport,
            "dstport": dstport,
            "protocol": protocol,
            "packets": packets,
            "bytes": bytes_count,
            "start": start_time,
            "end": end_time,
            "action": action,
            "log_status": "OK",
            "tcp_flags": tcp_flags,
            "flow_type": "IPv4",
            "pkt_srcaddr": srcaddr,
            "pkt_dstaddr": dstaddr,
            "timestamp": time.strftime("%H:%M:%S", time.localtime(now))
        })
        if len(RECENT_FLOWS) > MAX_RECENT_FLOWS:
            RECENT_FLOWS.pop(0)

    return line

# --- Performance Quarantine Cache ---
_QUARANTINE_CACHE = {"mtime": 0.0, "ips": set()}
_CACHE_LOCK = threading.Lock()

def get_cached_quarantined_ips() -> set[str]:
    """Derive quarantined IPs with mtime caching to avoid repeated full HMAC verifications."""
    with _CACHE_LOCK:
        try:
            audit_file = AUDIT_LOG_FILE if 'AUDIT_LOG_FILE' in globals() else DATA_DIR / "soar_audit.jsonl"
            mtime = audit_file.stat().st_mtime if audit_file.exists() else 0.0
            if mtime != _QUARANTINE_CACHE["mtime"]:
                _QUARANTINE_CACHE["mtime"] = mtime
                _QUARANTINE_CACHE["ips"] = get_quarantined_ips()
        except Exception:
            _QUARANTINE_CACHE["ips"] = get_quarantined_ips()
        return _QUARANTINE_CACHE["ips"]

# --- Dynamic Request Velocity Tracking for Live DoS Bursts ---
_IP_REQUEST_HISTORY: dict[str, list[float]] = {}
_HISTORY_LOCK = threading.Lock()

def record_ip_request_and_check_burst(ip: str, window_sec: float = 2.0, burst_threshold: int = 6) -> bool:
    """Record request timestamp for IP and return True if request rate constitutes a high-velocity DoS burst."""
    now = time.time()
    with _HISTORY_LOCK:
        history = _IP_REQUEST_HISTORY.get(ip, [])
        history = [t for t in history if now - t < window_sec]
        history.append(now)
        _IP_REQUEST_HISTORY[ip] = history
        if len(_IP_REQUEST_HISTORY) > 500:
            for k in list(_IP_REQUEST_HISTORY.keys()):
                if not _IP_REQUEST_HISTORY[k] or now - _IP_REQUEST_HISTORY[k][-1] > 10.0:
                    del _IP_REQUEST_HISTORY[k]
        return len(history) >= burst_threshold

RECON_SCAN_PATHS = {
    "/.env", "/.git", "/.git/config", "/wp-admin", "/wp-login.php",
    "/actuator", "/actuator/health", "/phpmyadmin", "/console",
    "/swagger-ui", "/swagger-ui.html", "/api/swagger", "/.aws/credentials"
}

def get_client_ip(req):
    """Detect client IP, honoring simulated attacker headers if present."""
    if req.headers.get("X-Attacker-IP"):
        ip = req.headers.get("X-Attacker-IP").strip()
    elif req.headers.get("X-Forwarded-For"):
        ip = req.headers.get("X-Forwarded-For").split(",")[0].strip()
    else:
        ip = req.remote_addr or "127.0.0.1"

    if ip == "::1":
        ip = "127.0.0.1"
    return ip

# --- Request Interceptor for SOAR Active Quarantine & Telemetry ---
@app.before_request
def check_soar_defense_and_log():
    # Do not intercept static flow log queries or health checks to prevent locking out monitors
    if request.path.startswith("/api/flow-logs") or request.path.startswith("/api/health"):
        return

    client_ip = get_client_ip(request)
    _, _, server_ip = get_server_context()
    target_port = request.environ.get("SERVER_PORT", 5000)
    try:
        target_port = int(target_port)
    except Exception:
        target_port = 5000

    # 1. SOAR ACTIVE QUARANTINE ENFORCEMENT
    quarantined = get_cached_quarantined_ips()
    if client_ip in quarantined and not is_ip_allowlisted(client_ip):
        # Client IP has been quarantined by SOAR!
        record_flow_log(
            srcaddr=client_ip,
            dstaddr=server_ip,
            srcport=random.randint(40000, 62000),
            dstport=target_port,
            packets=1,
            bytes_count=52,
            tcp_flags=4,  # RST
            action="REJECT",
            protocol=6,
            duration=0
        )
        return render_template_string(BLOCK_PAGE_TEMPLATE, ip=client_ip), 403

    # Do not double-log for dedicated simulation endpoints
    if request.path.startswith("/simulate"):
        return

    # Check for Recon/Scanner endpoints
    if request.path in RECON_SCAN_PATHS or request.path.startswith("/.env") or request.path.startswith("/.git"):
        record_flow_log(
            srcaddr=client_ip,
            dstaddr=server_ip,
            srcport=random.randint(40000, 65000),
            dstport=target_port,
            packets=random.choice([1, 2]),
            bytes_count=random.randint(48, 96),
            tcp_flags=2,  # SYN flag only
            action="REJECT",
            protocol=6,
            duration=0
        )
        return jsonify({"status": "REJECTED", "error": "Reconnaissance probe detected and blocked."}), 404

    # Check explicit simulated attack headers
    attack_header = request.headers.get("X-Attack-Type", "").strip().lower()
    if attack_header in ("dos", "dos_syn", "syn_flood"):
        pkt_count = random.randint(1200, 3500)
        byte_count = pkt_count * random.randint(40, 54)
        record_flow_log(
            srcaddr=client_ip,
            dstaddr=server_ip,
            srcport=random.randint(1024, 65535),
            dstport=target_port,
            packets=pkt_count,
            bytes_count=byte_count,
            tcp_flags=2,  # SYN flag only
            action="ACCEPT",
            protocol=6,
            duration=random.randint(0, 2)
        )
        return

    if attack_header in ("portscan", "port_scan", "scan"):
        record_flow_log(
            srcaddr=client_ip,
            dstaddr=server_ip,
            srcport=random.randint(40000, 65000),
            dstport=target_port,
            packets=random.choice([1, 2]),
            bytes_count=random.randint(48, 96),
            tcp_flags=2,  # SYN flag only
            action="REJECT",
            protocol=6,
            duration=0
        )
        return

    # POST /login handles its own telemetry (avoids duplicate/false benign flow)
    if request.path == "/login" and request.method == "POST":
        return

    # Dynamic Request Velocity Tracking for Live Traffic (DoS Bursts)
    is_burst = record_ip_request_and_check_burst(client_ip)
    if is_burst:
        pkt_count = random.randint(1200, 3500)
        byte_count = pkt_count * random.randint(40, 54)
        record_flow_log(
            srcaddr=client_ip,
            dstaddr=server_ip,
            srcport=random.randint(1024, 65535),
            dstport=target_port,
            packets=pkt_count,
            bytes_count=byte_count,
            tcp_flags=2,  # SYN flag only
            action="ACCEPT",
            protocol=6,
            duration=random.randint(0, 2)
        )
        return

    # 2. TELEMETRY LOGGING FOR BENIGN REQUESTS
    packets = random.randint(12, 35)
    bytes_count = packets * random.randint(500, 950)
    record_flow_log(
        srcaddr=client_ip,
        dstaddr=server_ip,
        srcport=random.randint(40000, 62000),
        dstport=target_port,
        packets=packets,
        bytes_count=bytes_count,
        tcp_flags=27,  # SYN+ACK+PSH
        action="ACCEPT",
        protocol=6,
        duration=1
    )

# --- WEB PORTAL ROUTES ---

@app.route("/")
@app.route("/dashboard")
def dashboard():
    account_id, vpc_id, server_ip = get_server_context()
    quarantined = list(get_cached_quarantined_ips())
    target_port = request.environ.get("SERVER_PORT", 5000)
    try:
        target_port = int(target_port)
    except Exception:
        target_port = 5000
    return render_template_string(
        PORTAL_HTML_TEMPLATE,
        account=ACCOUNT_DATA,
        transactions=TRANSACTIONS,
        server_ip=server_ip,
        vpc_id=vpc_id,
        account_id=account_id,
        quarantined_ips=quarantined,
        port=target_port
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    client_ip = get_client_ip(request)
    _, _, server_ip = get_server_context()
    target_port = request.environ.get("SERVER_PORT", 5000)
    try:
        target_port = int(target_port)
    except Exception:
        target_port = 5000

    if request.method == "POST":
        data = request.form if request.form else (request.get_json(silent=True) or {})
        username = data.get("username", "")
        password = data.get("password", "")

        # Valid mock credentials
        if username == "admin" and password == "ApexSecure2026!":
            record_flow_log(
                srcaddr=client_ip,
                dstaddr=server_ip,
                srcport=random.randint(45000, 65000),
                dstport=target_port,
                packets=random.randint(20, 40),
                bytes_count=random.randint(3000, 8000),
                tcp_flags=27,  # SYN+ACK+PSH
                action="ACCEPT",
                protocol=6,
                duration=1
            )
            return jsonify({"status": "SUCCESS", "message": "Authentication successful. Welcome, Corporate Administrator."})
        else:
            # Failed authentication (Credential Guessing / Brute Force signature)
            record_flow_log(
                srcaddr=client_ip,
                dstaddr=server_ip,
                srcport=random.randint(45000, 65000),
                dstport=target_port,
                packets=random.randint(45, 80),
                bytes_count=random.randint(7000, 14000),
                tcp_flags=24,  # PSH+ACK
                action="ACCEPT",
                protocol=6,
                duration=random.randint(3, 8)
            )
            if request.is_json:
                return jsonify({"status": "ERROR", "message": "Invalid credentials. Attempt logged to security ledger."}), 401
            return render_template_string(
                LOGIN_PAGE_TEMPLATE,
                error="Invalid security credentials. Incident telemetry dispatched to SOC.",
                port=target_port
            ), 401

    return render_template_string(LOGIN_PAGE_TEMPLATE, error=None, port=target_port)

@app.route("/api/v1/transactions", methods=["GET", "POST"])
def api_transactions():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        tx_id = f"TX-{random.randint(90215, 99999)}"
        new_tx = {
            "id": tx_id,
            "recipient": payload.get("recipient", "External Entity"),
            "amount": float(payload.get("amount", 1000.0)),
            "currency": payload.get("currency", "USD"),
            "status": "Settled",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": payload.get("type", "Commercial Wire")
        }
        TRANSACTIONS.insert(0, new_tx)
        return jsonify({"status": "SUCCESS", "transaction": new_tx}), 201

    query = request.args.get("q", "").lower()
    results = TRANSACTIONS
    if query:
        results = [t for t in TRANSACTIONS if query in t["recipient"].lower() or query in t["id"].lower()]
    return jsonify({"count": len(results), "transactions": results})

@app.route("/api/v1/balance", methods=["GET"])
def api_balance():
    return jsonify(ACCOUNT_DATA)

@app.route("/api/v1/transfer", methods=["POST"])
def api_transfer():
    data = request.get_json(silent=True) or request.form
    amount = float(data.get("amount", 0))
    recipient = data.get("recipient", "Unknown")
    if amount <= 0 or not recipient:
        return jsonify({"error": "Invalid transfer parameters"}), 400

    ACCOUNT_DATA["primary_balance"] -= amount
    tx = {
        "id": f"TX-{random.randint(90215, 99999)}",
        "recipient": recipient,
        "amount": amount,
        "currency": "USD",
        "status": "Settled",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": "Wire Transfer"
    }
    TRANSACTIONS.insert(0, tx)
    return jsonify({"status": "SUCCESS", "transaction": tx, "new_balance": ACCOUNT_DATA["primary_balance"]})

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        return jsonify({"status": "SUCCESS", "message": "Support ticket created. Reference: TCK-8412."})
    return jsonify({"service": "Apex Institutional Support", "desk": "24/7 Global Clearing", "mfa_required": True})

@app.route("/api/health", methods=["GET"])
def health():
    target_port = request.environ.get("SERVER_PORT", 5000)
    try:
        target_port = int(target_port)
    except Exception:
        target_port = 5000
    return jsonify({
        "status": "UP",
        "service": "Apex Financial Portal",
        "honeypot_telemetry": "AWS VPC Flow Log v5 Bridge ACTIVE",
        "active_port": target_port,
        "quarantined_ips_count": len(get_cached_quarantined_ips()),
        "timestamp": int(time.time())
    })

@app.route("/api/flow-logs", methods=["GET"])
def get_flow_logs():
    """Return recently captured AWS VPC Flow Log records."""
    limit = int(request.args.get("limit", 50))
    with LOG_LOCK:
        flows = list(RECENT_FLOWS[-limit:])
    return jsonify({
        "count": len(flows),
        "flows": flows,
        "log_file": str(LOCAL_FLOW_LOG_FILE)
    })

@app.route("/api/clear-logs", methods=["POST"])
def clear_flow_logs():
    """Clear local flow log file and memory buffer."""
    with LOG_LOCK:
        RECENT_FLOWS.clear()
        try:
            with open(LOCAL_FLOW_LOG_FILE, "w", encoding="utf-8") as f:
                f.write("")
        except Exception:
            pass
    return jsonify({"status": "SUCCESS", "message": "Flow logs cleared."})

# --- ATTACK SIMULATION TRIGGER ENDPOINTS ---
# These endpoints allow 1-click execution directly from the Portal UI or via curl/scripts.

@app.route("/simulate/dos", methods=["POST", "GET"])
def trigger_dos():
    """Generate rapid DoS SYN Flood attack bursts (MITRE T1498.001)."""
    dos_ip = request.args.get("ip") or "203.0.113.19"
    _, _, server_ip = get_server_context()
    target_port = int(request.environ.get("SERVER_PORT", 5000))
    generated = []

    for _ in range(15):
        pkt_count = random.randint(1200, 3500)
        byte_count = pkt_count * random.randint(40, 54)
        line = record_flow_log(
            srcaddr=dos_ip,
            dstaddr=server_ip,
            srcport=random.randint(1024, 65535),
            dstport=target_port,
            packets=pkt_count,
            bytes_count=byte_count,
            tcp_flags=2,  # SYN flag only
            action="ACCEPT",
            protocol=6,
            duration=random.randint(0, 2)
        )
        generated.append(line)

    return jsonify({
        "status": "SUCCESS",
        "attack": "DoS_SYN",
        "technique": "T1498.001",
        "attacker_ip": dos_ip,
        "records_generated": len(generated)
    })

@app.route("/simulate/bruteforce", methods=["POST", "GET"])
def trigger_bruteforce():
    """Generate credential stuffing / password brute force bursts (MITRE T1110.001)."""
    bf_ip = request.args.get("ip") or "185.220.101.44"
    _, _, server_ip = get_server_context()
    target_port = int(request.environ.get("SERVER_PORT", 5000))
    generated = []

    for _ in range(10):
        pkt_count = random.randint(35, 80)
        byte_count = pkt_count * random.randint(180, 320)
        line = record_flow_log(
            srcaddr=bf_ip,
            dstaddr=server_ip,
            srcport=random.randint(32000, 58000),
            dstport=target_port,
            packets=pkt_count,
            bytes_count=byte_count,
            tcp_flags=24,  # PSH+ACK
            action="ACCEPT",
            protocol=6,
            duration=random.randint(3, 15)
        )
        generated.append(line)

    return jsonify({
        "status": "SUCCESS",
        "attack": "BruteForce",
        "technique": "T1110.001",
        "attacker_ip": bf_ip,
        "records_generated": len(generated)
    })

@app.route("/simulate/portscan", methods=["POST", "GET"])
def trigger_portscan():
    """Generate reconnaissance port scan probes (MITRE T1046)."""
    scan_ip = request.args.get("ip") or "198.51.100.77"
    _, _, server_ip = get_server_context()
    probe_ports = [21, 22, 23, 25, 110, 135, 139, 445, 1433, 3306, 3389, 8080]
    generated = []

    for port in probe_ports:
        line = record_flow_log(
            srcaddr=scan_ip,
            dstaddr=server_ip,
            srcport=random.randint(40000, 65000),
            dstport=port,
            packets=random.choice([1, 2]),
            bytes_count=random.randint(48, 96),
            tcp_flags=2,  # SYN flag only
            action="REJECT",
            protocol=6,
            duration=random.randint(0, 1)
        )
        generated.append(line)

    return jsonify({
        "status": "SUCCESS",
        "attack": "PortScan",
        "technique": "T1046",
        "attacker_ip": scan_ip,
        "probed_ports": probe_ports,
        "records_generated": len(generated)
    })

@app.route("/simulate/normal", methods=["POST", "GET"])
def trigger_normal():
    """Generate legitimate benign client traffic."""
    benign_ip = request.args.get("ip") or "192.168.1.55"
    _, _, server_ip = get_server_context()
    target_port = int(request.environ.get("SERVER_PORT", 5000))
    generated = []

    for _ in range(12):
        pkt_count = random.randint(15, 40)
        byte_count = pkt_count * random.randint(450, 1100)
        line = record_flow_log(
            srcaddr=benign_ip,
            dstaddr=server_ip,
            srcport=random.randint(35000, 61000),
            dstport=target_port,
            packets=pkt_count,
            bytes_count=byte_count,
            tcp_flags=random.choice([27, 24, 16]),
            action="ACCEPT",
            protocol=6,
            duration=random.randint(1, 10)
        )
        generated.append(line)

    return jsonify({
        "status": "SUCCESS",
        "traffic": "BENIGN",
        "client_ip": benign_ip,
        "records_generated": len(generated)
    })

# --- HTML TEMPLATES ---

BLOCK_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>403 Forbidden | Cloud Shield Active Quarantine</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-6">
    <div class="max-w-xl w-full bg-slate-900 border border-red-500/50 rounded-2xl p-8 shadow-2xl text-center">
        <div class="inline-flex p-4 bg-red-500/10 rounded-full mb-4 border border-red-500/30">
            <svg class="w-16 h-16 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
        </div>
        <h1 class="text-3xl font-extrabold text-red-400 mb-2">ACCESS TERMINATED</h1>
        <p class="text-sm font-semibold tracking-wider text-red-300 uppercase mb-4">Cloud Shield Automated SOAR Active Defense</p>
        <div class="bg-slate-950 rounded-lg p-4 mb-6 border border-slate-800 text-left font-mono text-xs space-y-2">
            <div class="flex justify-between"><span class="text-slate-500">Quarantined IP:</span><span class="text-red-400 font-bold">{{ ip }}</span></div>
            <div class="flex justify-between"><span class="text-slate-500">Remediation Action:</span><span class="text-amber-400">AWS Network ACL / SOAR Rule #99</span></div>
            <div class="flex justify-between"><span class="text-slate-500">Defense Subsystem:</span><span class="text-slate-300">Cloud Shield NIDS XGBoost + TreeSHAP</span></div>
            <div class="flex justify-between"><span class="text-slate-500">Ledger Entry:</span><span class="text-emerald-400">Cryptographically Signed (SHA-256)</span></div>
        </div>
        <p class="text-xs text-slate-400 mb-6">
            All packets from this address are being dropped. To appeal or clear false-positives, access the Cloud Shield Streamlit SOC Console under the SOAR Remediation Tab.
        </p>
        <a href="http://localhost:8501" target="_blank" class="inline-block px-6 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition shadow-lg shadow-red-600/30">
            Open Cloud Shield SOC Console
        </a>
    </div>
</body>
</html>
"""

LOGIN_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Apex Financial | Secure Executive Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-6">
    <div class="max-w-md w-full bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-2xl">
        <div class="flex items-center justify-between mb-8">
            <div class="flex items-center space-x-3">
                <div class="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center font-bold text-xl shadow-lg shadow-blue-500/30">
                    ⟁
                </div>
                <div>
                    <h2 class="font-bold text-lg text-white">Apex Global Finance</h2>
                    <p class="text-xs text-blue-400">Institutional Gateway</p>
                </div>
            </div>
            <span class="px-2.5 py-1 text-xs rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">TLS 1.3 Active</span>
        </div>

        {% if error %}
        <div class="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/40 text-red-400 text-xs flex items-center space-x-2">
            <svg class="w-5 h-5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
            <span>{{ error }}</span>
        </div>
        {% endif %}

        <form action="/login" method="POST" class="space-y-4">
            <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Corporate Operator ID</label>
                <input type="text" name="username" value="admin" required class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500">
            </div>
            <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Security Token / Password</label>
                <input type="password" name="password" placeholder="••••••••••••" required class="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500">
            </div>
            <button type="submit" class="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition shadow-lg shadow-blue-600/30">
                Authenticate Session
            </button>
        </form>

        <div class="mt-6 pt-6 border-t border-slate-800 text-center text-xs text-slate-500">
            Protected by Cloud Shield Real-time NIDS. All failed attempts generate high-velocity telemetry for SOC analysis.
            <div class="mt-3">
                <a href="/" class="text-blue-400 hover:underline">← Return to Portal Dashboard</a>
            </div>
        </div>
    </div>
</body>
</html>
"""

PORTAL_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Apex Global Financial | Enterprise Cloud Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-slate-950 text-slate-100 font-sans antialiased min-h-screen">

    <!-- Top Navigation Bar -->
    <header class="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-4">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center font-black text-xl shadow-lg shadow-blue-500/20">
                    ⟁
                </div>
                <div>
                    <span class="font-bold text-lg tracking-tight text-white">Apex Global Finance</span>
                    <span class="text-xs block text-slate-400">Institutional Treasury & Liquidity Portal</span>
                </div>
            </div>

            <div class="flex items-center space-x-6 text-sm">
                <div class="hidden lg:flex items-center space-x-2 text-xs text-slate-400">
                    <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span>Institutional Liquidity Node Active</span>
                </div>
                <div class="hidden md:flex items-center space-x-1 text-xs text-slate-400">
                    <i class="fa-solid fa-headset mr-1 text-blue-400"></i>
                    <span>Desk: +1 (800) 555-APEX</span>
                </div>
                <a href="/login" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-blue-600/30 transition">
                    <i class="fa-solid fa-lock mr-1.5"></i> Client Sign In
                </a>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-6 py-8 space-y-8">

        <!-- FINANCIAL KPI METRICS -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
                <div class="text-xs text-slate-400 font-semibold uppercase tracking-wider">Total Portfolio Balance</div>
                <div class="text-2xl font-black text-white mt-2">${{ "{:,.2f}".format(account.primary_balance) }}</div>
                <div class="text-xs text-emerald-400 mt-1"><i class="fa-solid fa-arrow-trend-up mr-1"></i> +4.2% settlement delta</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
                <div class="text-xs text-slate-400 font-semibold uppercase tracking-wider">Available Fedwire Credit</div>
                <div class="text-2xl font-black text-white mt-2">${{ "{:,.2f}".format(account.available_credit) }}</div>
                <div class="text-xs text-slate-400 mt-1">SWIFT Direct Settlement Active</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
                <div class="text-xs text-slate-400 font-semibold uppercase tracking-wider">24h Clearing Volume</div>
                <div class="text-2xl font-black text-indigo-400 mt-2">$48,920,400.00</div>
                <div class="text-xs text-emerald-400 mt-1"><i class="fa-solid fa-check-circle mr-1"></i> 100% On-Time Clearing</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
                <div class="text-xs text-slate-400 font-semibold uppercase tracking-wider">Regulatory Reserve Tier</div>
                <div class="text-xl font-black text-emerald-400 mt-2">Tier 1 Prime Facility</div>
                <div class="text-xs text-slate-400 mt-1">Basel III Capital Compliant</div>
            </div>
        </div>

        <!-- TRANSACTIONS & WIRE TRANSFER SECTION -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <!-- Transaction Ledger -->
            <div class="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div class="flex items-center justify-between mb-6">
                    <div>
                        <h3 class="font-bold text-lg text-white">Institutional Clearing Ledger</h3>
                        <p class="text-xs text-slate-400">Real-time interbank transaction search & audit records</p>
                    </div>
                    <div class="relative">
                        <input type="text" id="tx-search" placeholder="Search payee or TX ID..." onkeyup="filterTransactions()" class="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white focus:outline-none focus:border-blue-500 w-56">
                        <i class="fa-solid fa-search absolute left-2.5 top-2.5 text-slate-500 text-xs"></i>
                    </div>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs" id="tx-table">
                        <thead class="text-slate-400 border-b border-slate-800 font-semibold uppercase tracking-wider">
                            <tr>
                                <th class="pb-3">Transaction ID</th>
                                <th class="pb-3">Beneficiary</th>
                                <th class="pb-3">Category</th>
                                <th class="pb-3">Amount</th>
                                <th class="pb-3">Status</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800/60" id="tx-body">
                            {% for tx in transactions %}
                            <tr class="hover:bg-slate-800/40 transition">
                                <td class="py-3 font-mono text-slate-300 font-medium">{{ tx.id }}</td>
                                <td class="py-3 font-semibold text-white">{{ tx.recipient }}</td>
                                <td class="py-3 text-slate-400">{{ tx.type }}</td>
                                <td class="py-3 font-bold text-slate-200">${{ "{:,.2f}".format(tx.amount) }}</td>
                                <td class="py-3">
                                    <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                        {{ tx.status }}
                                    </span>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Initiate Wire Transfer Card -->
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
                <div>
                    <h3 class="font-bold text-lg text-white mb-1">Initiate Wire Settlement</h3>
                    <p class="text-xs text-slate-400 mb-6">Dispatches authenticated SWIFT payment order</p>
                    
                    <form id="transfer-form" onsubmit="submitWire(event)" class="space-y-4">
                        <div>
                            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Beneficiary Payee</label>
                            <input type="text" id="wire-recipient" required placeholder="e.g. Zurich Securities Corp" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Transfer Amount (USD)</label>
                            <input type="number" id="wire-amount" required min="100" step="50" placeholder="50000" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500">
                        </div>
                        <div>
                            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Settlement Route</label>
                            <select id="wire-type" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500">
                                <option value="SWIFT Fedwire Direct">SWIFT Fedwire Direct (Instant)</option>
                                <option value="Commercial Treasury Wire">Commercial Treasury Wire</option>
                                <option value="Interbank Liquidity">Interbank Liquidity Clearing</option>
                            </select>
                        </div>
                        <button type="submit" class="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold transition shadow-lg shadow-indigo-600/30">
                            Execute Wire Settlement
                        </button>
                    </form>
                    <div id="transfer-status" class="mt-3 hidden text-xs p-2 rounded"></div>
                </div>

                <div class="mt-6 pt-4 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between">
                    <span>MFA Verified Session</span>
                    <span class="text-emerald-400"><i class="fa-solid fa-lock mr-1"></i> 256-bit TLS Encrypted</span>
                </div>
            </div>
        </div>

        <!-- INSTITUTIONAL SERVICES FOOTER BANNER -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 pt-2">
            <div class="bg-slate-900/60 border border-slate-800/80 rounded-xl p-5">
                <div class="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center mb-3">
                    <i class="fa-solid fa-globe"></i>
                </div>
                <h4 class="text-sm font-bold text-white">Cross-Border Settlement</h4>
                <p class="text-xs text-slate-400 mt-1">Direct bilateral Fedwire, CHIPS, and Target2 liquidity clearing across 42 currency corridors.</p>
            </div>
            <div class="bg-slate-900/60 border border-slate-800/80 rounded-xl p-5">
                <div class="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center mb-3">
                    <i class="fa-solid fa-building-columns"></i>
                </div>
                <h4 class="text-sm font-bold text-white">Institutional Custody</h4>
                <p class="text-xs text-slate-400 mt-1">Segregated cold and warm treasury vault architecture with real-time liquidity rebalancing.</p>
            </div>
            <div class="bg-slate-900/60 border border-slate-800/80 rounded-xl p-5">
                <div class="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center mb-3">
                    <i class="fa-solid fa-shield-halved"></i>
                </div>
                <h4 class="text-sm font-bold text-white">Zero-Trust Protocol</h4>
                <p class="text-xs text-slate-400 mt-1">Multi-signatory quorum authorizations and behavioral transport inspection protecting wire pipelines.</p>
            </div>
        </div>
    </main>

    <footer class="border-t border-slate-900 mt-12 py-6 text-center text-xs text-slate-500">
        <p>© 2026 Apex Global Financial Corp. Institutional Treasury Member FINRA & SIPC. Regulated by the Federal Reserve.</p>
    </footer>

    <script>
        async function submitWire(e) {
            e.preventDefault();
            const recipient = document.getElementById("wire-recipient").value;
            const amount = document.getElementById("wire-amount").value;
            const type = document.getElementById("wire-type").value;
            const statusDiv = document.getElementById("transfer-status");

            try {
                const res = await fetch("/api/v1/transfer", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ recipient, amount, type })
                });
                const data = await res.json();
                if (data.status === "SUCCESS") {
                    statusDiv.className = "mt-3 text-xs p-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400";
                    statusDiv.innerHTML = `[✓] Wire settlement <b>${data.transaction.id}</b> of $${parseFloat(amount).toLocaleString()} executed.`;
                    statusDiv.classList.remove("hidden");
                    setTimeout(() => location.reload(), 1500);
                }
            } catch (err) {
                statusDiv.className = "mt-3 text-xs p-2 rounded bg-red-500/10 border border-red-500/30 text-red-400";
                statusDiv.innerText = `Error: ${err.message}`;
                statusDiv.classList.remove("hidden");
            }
        }

        function filterTransactions() {
            const query = document.getElementById("tx-search").value.toLowerCase();
            const rows = document.querySelectorAll("#tx-body tr");
            rows.forEach(row => {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(query) ? "" : "none";
            });
        }
    </script>
</body>
</html>
"""

def seed_initial_flows():
    """Seed initial flow log file with benign baseline flows if empty."""
    if not LOCAL_FLOW_LOG_FILE.exists() or LOCAL_FLOW_LOG_FILE.stat().st_size == 0:
        account_id, _, server_ip = get_server_context()
        now = int(time.time())
        benign_ips = ["192.168.1.15", "192.168.1.28", "10.0.1.45", "10.0.1.50"]
        for i in range(15):
            src = random.choice(benign_ips)
            record_flow_log(
                srcaddr=src,
                dstaddr=server_ip,
                srcport=random.randint(35000, 60000),
                dstport=5000,
                packets=random.randint(15, 35),
                bytes_count=random.randint(4000, 15000),
                tcp_flags=27,
                action="ACCEPT",
                protocol=6,
                duration=random.randint(1, 5)
            )

def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="Apex Financial Portal - Cloud Shield Target Honeypot")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5000)), help="Port to bind (default: 5000 or env PORT)")
    parser.add_argument("--host", type=str, default=os.environ.get("HOST", "0.0.0.0"), help="Host to bind (default: 0.0.0.0)")
    args = parser.parse_args()

    seed_initial_flows()

    print("=" * 72)
    print("[*] APEX FINANCIAL PORTAL (Cloud Shield Target Tier)")
    print("=" * 72)
    print(f"Server URL:         http://localhost:{args.port}/")
    print(f"Network Binding:    {args.host}:{args.port}")
    print(f"VPC Flow Log File:  {LOCAL_FLOW_LOG_FILE}")
    print("Active SOAR Defense: Auto-blocking quarantined IPs")
    print("Streamlit SOC Link: http://localhost:8501")
    print("=" * 72)
    print("Ready to receive benign and simulated attack traffic...\n")

    app.run(host=args.host, port=args.port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
