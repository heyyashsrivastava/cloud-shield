import pytest
import sys
import json
import time
from pathlib import Path

# Add project root
sys.path.append(str(Path(__file__).resolve().parent.parent))
from target_website import app, record_flow_log, get_cached_quarantined_ips
from config import LOCAL_FLOW_LOG_FILE, MODELS_DIR, LABEL_NAMES, IMMUTABLE_ALLOWLIST
from ml.feature_extraction import (
    parse_flow_log_line, transform_flow_logs, assert_zero_ip_leakage
)
from soar.remediation import quarantine_ip, restore_ip, get_quarantined_ips

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_target_website_health(client):
    """Verify target website health check endpoint returns status UP and metadata."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "UP"
    assert "Apex Financial Portal" in data["service"]
    assert "honeypot_telemetry" in data

def test_target_website_dashboard(client):
    """Verify target portal renders financial dashboard with Apex branding."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Apex Global Finance" in html
    assert "Institutional Treasury" in html
    assert "Total Portfolio Balance" in html

def test_transactions_api(client):
    """Verify transactions retrieval, search filtering, and wire creation."""
    # 1. GET all
    res = client.get("/api/v1/transactions")
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] >= 5
    assert len(data["transactions"]) >= 5

    # 2. Search query filter
    res_search = client.get("/api/v1/transactions?q=Quantum")
    assert res_search.status_code == 200
    data_search = res_search.get_json()
    assert data_search["count"] >= 1
    assert any("Quantum" in t["recipient"] for t in data_search["transactions"])

    # 3. Create wire transaction
    new_wire = {
        "recipient": "Zurich Capital AG",
        "amount": 75000.0,
        "type": "Treasury Wire"
    }
    res_post = client.post("/api/v1/transactions", json=new_wire)
    assert res_post.status_code == 201
    assert res_post.get_json()["transaction"]["recipient"] == "Zurich Capital AG"

def test_login_authentication_and_bruteforce_detection(client):
    """Verify failed logins return 401 and generate credential attack signatures."""
    # Failed attempt
    res_fail = client.post(
        "/login",
        json={"username": "admin", "password": "wrongpassword123"},
        headers={"X-Attacker-IP": "185.220.101.44"}
    )
    assert res_fail.status_code == 401
    assert "Invalid credentials" in res_fail.get_json()["message"]

    # Successful attempt
    res_ok = client.post(
        "/login",
        json={"username": "admin", "password": "ApexSecure2026!"}
    )
    assert res_ok.status_code == 200
    assert "Authentication successful" in res_ok.get_json()["message"]

def test_flow_log_generation_and_schema_compliance():
    """Verify flow log records generated strictly adhere to AWS VPC Flow Log v5 specification."""
    test_line = record_flow_log(
        srcaddr="198.51.100.33",
        dstaddr="10.0.1.100",
        srcport=48211,
        dstport=5000,
        packets=25,
        bytes_count=12500,
        tcp_flags=27,
        action="ACCEPT",
        protocol=6,
        duration=2
    )

    # 1. Parse line
    parsed = parse_flow_log_line(test_line)
    assert parsed is not None
    assert parsed["version"] == "5"
    assert parsed["srcaddr"] == "198.51.100.33"
    assert parsed["dstaddr"] == "10.0.1.100"
    assert parsed["dstport"] == 5000
    assert parsed["packets"] == 25
    assert parsed["bytes"] == 12500
    assert parsed["action"] == "ACCEPT"
    assert parsed["tcp_flags"] == 27

    # 2. Extract features with zero IP leakage
    X_feat, meta = transform_flow_logs([parsed])
    assert len(X_feat) == 1
    assert_zero_ip_leakage(X_feat)
    assert X_feat.iloc[0]["packets"] == 25
    assert X_feat.iloc[0]["tcp_flags"] == 27

def test_soar_quarantine_enforcement_on_target_website(client):
    """Verify that quarantined IPs are actively blocked with HTTP 403 and logged as REJECT."""
    attacker_ip = "198.51.100.88"
    restore_ip(attacker_ip, reason="Clean test initialization", dry_run=True)

    # Normal access before quarantine
    r_before = client.get("/", headers={"X-Attacker-IP": attacker_ip})
    assert r_before.status_code == 200

    # Trigger SOAR Quarantine
    q_result = quarantine_ip(attacker_ip, reason="Test PortScan detection", dry_run=True)
    assert q_result["status"] == "SUCCESS"
    assert attacker_ip in get_quarantined_ips()

    # Active enforcement by target website
    r_blocked = client.get("/", headers={"X-Attacker-IP": attacker_ip})
    assert r_blocked.status_code == 403
    html = r_blocked.get_data(as_text=True)
    assert "ACCESS TERMINATED" in html
    assert attacker_ip in html

    # Cleanup: restore IP
    restore_ip(attacker_ip, reason="Clean test finish", dry_run=True)
    r_restored = client.get("/", headers={"X-Attacker-IP": attacker_ip})
    assert r_restored.status_code == 200

def test_attack_simulation_endpoints_and_model_classification(client):
    """Verify simulation endpoints generate compliant flows classified with high accuracy."""
    import joblib
    model_path = MODELS_DIR / "xgboost_nids.pkl"
    if not model_path.exists():
        pytest.skip("Model not found")

    model = joblib.load(model_path)

    # 1. Trigger DoS Simulation
    res_dos = client.post("/simulate/dos", headers={"X-Attacker-IP": "203.0.113.19"})
    assert res_dos.status_code == 200
    assert res_dos.get_json()["attack"] == "DoS_SYN"

    # 2. Trigger PortScan Simulation
    res_scan = client.post("/simulate/portscan", headers={"X-Attacker-IP": "198.51.100.77"})
    assert res_scan.status_code == 200
    assert res_scan.get_json()["attack"] == "PortScan"

    # 3. Trigger BruteForce Simulation
    res_bf = client.post("/simulate/bruteforce", headers={"X-Attacker-IP": "185.220.101.44"})
    assert res_bf.status_code == 200
    assert res_bf.get_json()["attack"] == "BruteForce"

    # 4. Trigger Normal Simulation
    res_norm = client.post("/simulate/normal", headers={"X-Attacker-IP": "192.168.1.55"})
    assert res_norm.status_code == 200
    assert res_norm.get_json()["traffic"] == "BENIGN"

    # Verify flow log API retrieval
    res_logs = client.get("/api/flow-logs?limit=50")
    assert res_logs.status_code == 200
    flows = res_logs.get_json()["flows"]
    assert len(flows) >= 4

    # Run ML prediction on generated flow logs
    parsed_records = [parse_flow_log_line(f["raw_line"]) for f in flows if parse_flow_log_line(f["raw_line"])]
    X_features, _ = transform_flow_logs(parsed_records)
    preds = model.predict(X_features)
    predicted_labels = set([LABEL_NAMES[p] for p in preds])

    # Must contain detections across categories
    assert "DoS_SYN" in predicted_labels
    assert "PortScan" in predicted_labels
    assert "BruteForce" in predicted_labels
    assert "BENIGN" in predicted_labels

def test_attack_headers_telemetry(client):
    """Verify that incoming requests with X-Attack-Type headers are accurately recorded as attacks."""
    client.post("/api/clear-logs")

    # 1. DoS header
    client.get("/api/v1/transactions", headers={"X-Attacker-IP": "203.0.113.88", "X-Attack-Type": "DoS"})
    res = client.get("/api/flow-logs?limit=5")
    flows = res.get_json()["flows"]
    assert len(flows) >= 1
    last_flow = flows[-1]
    assert last_flow["srcaddr"] == "203.0.113.88"
    assert last_flow["tcp_flags"] == 2
    assert last_flow["packets"] >= 1000

    # 2. PortScan header
    client.get("/", headers={"X-Attacker-IP": "198.51.100.44", "X-Attack-Type": "PortScan"})
    res = client.get("/api/flow-logs?limit=5")
    flows = res.get_json()["flows"]
    scan_flow = flows[-1]
    assert scan_flow["srcaddr"] == "198.51.100.44"
    assert scan_flow["action"] == "REJECT"
    assert scan_flow["tcp_flags"] == 2

def test_no_duplicate_benign_flows_on_failed_login(client):
    """Verify that a failed login generates strictly one flow log (BruteForce) and NO benign flow."""
    client.post("/api/clear-logs")

    client.post(
        "/login",
        json={"username": "admin", "password": "wrongpassword999"},
        headers={"X-Attacker-IP": "185.220.101.99"}
    )

    res = client.get("/api/flow-logs?limit=10")
    flows = res.get_json()["flows"]
    assert len(flows) == 1, f"Expected exactly 1 flow log, got {len(flows)}"
    assert flows[0]["srcaddr"] == "185.220.101.99"
    assert flows[0]["tcp_flags"] == 24  # PSH+ACK BruteForce
    assert flows[0]["action"] == "ACCEPT"

def test_velocity_dos_burst_detection(client):
    """Verify that high-velocity bursts from a single IP automatically trigger DoS SYN flow generation."""
    client.post("/api/clear-logs")
    burst_ip = "198.51.100.210"

    # Fire 8 rapid requests without attack headers
    for _ in range(8):
        client.get("/api/v1/transactions", headers={"X-Attacker-IP": burst_ip})

    res = client.get("/api/flow-logs?limit=15")
    flows = res.get_json()["flows"]
    assert len(flows) >= 8

    # The later flows in the burst must have transitioned to DoS SYN telemetry
    burst_flows = [f for f in flows if f["srcaddr"] == burst_ip and f["tcp_flags"] == 2 and f["packets"] >= 1000]
    assert len(burst_flows) > 0, "Velocity burst should have triggered DoS SYN flow generation"

def test_recon_scan_probe(client):
    """Verify that reconnaissance probes to sensitive scanner paths return 404 and log PortScan REJECT flows."""
    client.post("/api/clear-logs")
    scan_ip = "198.51.100.33"

    res = client.get("/.env", headers={"X-Attacker-IP": scan_ip})
    assert res.status_code == 404

    res2 = client.get("/wp-admin", headers={"X-Attacker-IP": scan_ip})
    assert res2.status_code == 404

    logs = client.get("/api/flow-logs?limit=10").get_json()["flows"]
    assert len(logs) == 2
    for l in logs:
        assert l["srcaddr"] == scan_ip
        assert l["action"] == "REJECT"
        assert l["tcp_flags"] == 2

def test_quarantine_caching_and_allowlist_immunity(client):
    """Verify cached quarantine lookup works and that allowlisted IPs are never blocked."""
    # 1. Allowlisted IP should never be blocked
    res_allow = client.get("/", headers={"X-Attacker-IP": "127.0.0.1"})
    assert res_allow.status_code == 200

    # 2. Cached quarantined set
    cached = get_cached_quarantined_ips()
    assert isinstance(cached, set)

def test_deploy_aws_infra_userdata_resilience():
    """Verify that EC2 UserData script includes required resilience directives."""
    from scripts import deploy_aws_infra
    import inspect

    src = inspect.getsource(deploy_aws_infra.deploy_infrastructure)
    assert "apex-portal.service" in src
    assert "systemctl stop httpd" in src
    assert "break-system-packages" in src
    assert "python3-flask" in src
