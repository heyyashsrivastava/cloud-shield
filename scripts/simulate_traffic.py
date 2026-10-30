"""
Cloud Shield Traffic Simulation Engine
======================================
Simulates realistic cyber attack patterns (MITRE ATT&CK) against:
  1. Local Target Website: http://localhost:5000 (Zero AWS cost)
  2. Cloud EC2 Target: http://<public_ip>:80

Attack Scenarios:
  - T1046: Network Service Discovery (Reconnaissance Port Scan)
  - T1498.001: Direct Network Flood (DoS SYN / HTTP connection burst)
  - T1110.001: Password Guessing / Credential Stuffing (Brute Force)
  - Benign: Legitimate multi-endpoint enterprise portal traffic
"""

import os
import sys
import json
import time
import socket
import random
import requests
import gzip
import io
import argparse
from urllib.parse import urlparse
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from config import (
    STATE_FILE, LOCAL_FLOW_LOG_FILE,
    get_aws_session, get_aws_identity, FLOW_LOG_FIELDS
)

def get_default_target_url():
    """Detect whether local website (port 5000) or EC2 instance is available."""
    # 1. Check if local target website is running on port 5000
    try:
        resp = requests.get("http://127.0.0.1:5000/api/health", timeout=0.5)
        if resp.status_code == 200:
            return "http://127.0.0.1:5000"
    except Exception:
        pass

    # 2. Check if EC2 public IP is in state file
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
            pub_ip = state.get("public_ip")
            if pub_ip and pub_ip != "PENDING":
                return f"http://{pub_ip}"
        except Exception:
            pass

    # Default to localhost:5000
    return "http://127.0.0.1:5000"

def parse_target(target_str: str):
    """Parse a target string into base URL, host, and port."""
    if not target_str.startswith("http://") and not target_str.startswith("https://"):
        target_str = "http://" + target_str

    parsed = urlparse(target_str)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    base_url = f"{parsed.scheme}://{host}:{port}" if parsed.port else f"{parsed.scheme}://{host}"
    return base_url, host, port

def get_target_host():
    """Legacy helper for backward compatibility."""
    _, host, _ = parse_target(get_default_target_url())
    return host

def simulate_port_scan(target_ip_or_url: str = None, ports: list = None, timeout: float = 0.25):
    """
    Simulate a reconnaissance port scan (MITRE T1046) against the target host.
    Probes open and closed TCP ports.
    """
    if target_ip_or_url is None:
        target_ip_or_url = get_default_target_url()

    base_url, target_host, _ = parse_target(target_ip_or_url)

    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5000, 8080]

    print(f"\n[!] Simulating Port Scan (T1046: Network Service Discovery) against {target_host} ({len(ports)} ports)...")
    open_ports = []
    closed_ports = []

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start_t = time.time()
        try:
            result = s.connect_ex((target_host, port))
            elapsed_ms = (time.time() - start_t) * 1000
            if result == 0:
                open_ports.append(port)
                print(f"  --> Port {port:5d}/TCP: OPEN (took {elapsed_ms:.1f}ms)")
            else:
                closed_ports.append(port)
        except Exception:
            closed_ports.append(port)
        finally:
            s.close()

    print(f"  Port scan complete. Open ports: {open_ports}, Closed/Filtered ports: {len(closed_ports)}")

    # If targeting the target website with the simulation API, trigger compliant flow logs
    try:
        resp = requests.post(
            f"{base_url}/simulate/portscan",
            headers={"X-Attacker-IP": "198.51.100.77"},
            timeout=2
        )
        if resp.status_code == 200:
            print("  VPC Flow Log Bridge: 12 AWS v5 PortScan records recorded.")
    except Exception:
        pass

    return {"open": open_ports, "closed": closed_ports}

def simulate_syn_flood(target_ip_or_url: str = None, target_port: int = None, num_packets: int = 40):
    """
    Simulate high-velocity TCP SYN flood / HTTP connection burst (MITRE T1498.001).
    Fires rapid connection bursts and HTTP flooding.
    """
    if target_ip_or_url is None:
        target_ip_or_url = get_default_target_url()

    base_url, target_host, default_port = parse_target(target_ip_or_url)
    port = target_port if target_port else default_port

    print(f"\n[!] Simulating DoS SYN / HTTP Connection Flood (T1498.001) against {target_host}:{port} ({num_packets} bursts)...")
    successes = 0
    failures = 0

    # 1. Socket connection burst
    for i in range(min(num_packets, 40)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            s.connect_ex((target_host, port))
            successes += 1
        except Exception:
            failures += 1
        finally:
            s.close()
        time.sleep(0.005)

    # 2. HTTP rapid burst with simulated attacker IP header
    dos_ip = "203.0.113.19"
    try:
        for _ in range(15):
            requests.get(
                f"{base_url}/api/v1/transactions",
                headers={"X-Attacker-IP": dos_ip, "X-Attack-Type": "DoS"},
                timeout=1
            )
    except Exception:
        pass

    # 3. Direct bridge trigger for comprehensive v5 telemetry records
    try:
        resp = requests.post(f"{base_url}/simulate/dos", headers={"X-Attacker-IP": dos_ip}, timeout=2)
        if resp.status_code == 200:
            print("  VPC Flow Log Bridge: 15 AWS v5 DoS SYN records recorded.")
    except Exception:
        pass

    print(f"  Flood simulation finished. Dispatched {num_packets} connection attempts.")
    return {"successes": successes, "failures": failures}

def simulate_brute_force(target_ip_or_url: str = None, count: int = 15):
    """
    Simulate Password Guessing / Credential Stuffing (MITRE T1110.001) against /login.
    Fires repeated failed authentication requests with varied passwords.
    """
    if target_ip_or_url is None:
        target_ip_or_url = get_default_target_url()

    base_url, _, _ = parse_target(target_ip_or_url)
    bf_ip = "185.220.101.44"
    passwords = [
        "admin123", "password", "123456", "root", "toor",
        "letmein", "Apex2025!", "welcome1", "qwerty", "master"
    ]

    print(f"\n[!] Simulating Credential Brute Force (T1110.001) against {base_url}/login ({count} attempts)...")
    successes = 0

    for i in range(count):
        pwd = random.choice(passwords)
        try:
            resp = requests.post(
                f"{base_url}/login",
                json={"username": "admin", "password": pwd},
                headers={"X-Attacker-IP": bf_ip, "X-Attack-Type": "BruteForce"},
                timeout=1.5
            )
            if resp.status_code == 401 or resp.status_code == 200:
                successes += 1
        except Exception:
            pass
        time.sleep(0.04)

    # Trigger bridge simulation for full v5 flow telemetry
    try:
        resp = requests.post(f"{base_url}/simulate/bruteforce", headers={"X-Attacker-IP": bf_ip}, timeout=2)
        if resp.status_code == 200:
            print("  VPC Flow Log Bridge: 10 AWS v5 BruteForce records recorded.")
    except Exception:
        pass

    print(f"  Brute force finished. Dispatched {count} login attempts from {bf_ip}.")
    return {"attempts": count, "responses": successes}

def simulate_normal_traffic(target_ip_or_url: str = None, count: int = 12):
    """
    Simulate legitimate user browsing behavior against financial portal endpoints.
    Hits /, /api/v1/transactions, /api/v1/balance, and creates wire transfers.
    """
    if target_ip_or_url is None:
        target_ip_or_url = get_default_target_url()

    base_url, _, _ = parse_target(target_ip_or_url)
    benign_ip = "192.168.1.55"
    print(f"\n[*] Simulating Legitimate User Traffic against {base_url} ({count} requests)...")
    successes = 0

    endpoints = [
        ("/", "GET", None),
        ("/api/v1/transactions", "GET", None),
        ("/api/v1/balance", "GET", None),
        ("/contact", "GET", None),
        ("/api/v1/transactions?q=Quantum", "GET", None),
        ("/api/v1/transfer", "POST", {"recipient": "Automated Vendor Clearing", "amount": 2500.00, "type": "Vendor Clearing"})
    ]

    for i in range(count):
        ep, method, body = random.choice(endpoints)
        url = f"{base_url}{ep}"
        headers = {"X-Attacker-IP": benign_ip}
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=2)
            else:
                resp = requests.post(url, json=body, headers=headers, timeout=2)
            if resp.status_code in [200, 201]:
                successes += 1
        except Exception:
            pass
        time.sleep(0.05)

    # Bridge telemetry
    try:
        resp = requests.post(f"{base_url}/simulate/normal", headers={"X-Attacker-IP": benign_ip}, timeout=2)
        if resp.status_code == 200:
            print("  VPC Flow Log Bridge: 12 AWS v5 BENIGN records recorded.")
    except Exception:
        pass

    print(f"  Legitimate traffic complete. {successes}/{count} HTTP requests accepted.")
    return {"status_success": successes}

def inject_s3_flow_logs(attack_type: str = "ALL"):
    """
    Generate and upload realistic AWS VPC Flow Log batch directly to S3 Data Lake.
    This enables immediate end-to-end ingestion testing without waiting for VPC log delivery timers.
    """
    if not STATE_FILE.exists():
        return

    try:
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
    except Exception:
        return

    bucket_name = state.get("s3_bucket")
    region = state.get("region")
    account_id = state.get("account_id")
    target_ip = state.get("public_ip", "10.0.1.100")

    if not bucket_name or not region or not account_id:
        return

    try:
        session = get_aws_session()
        s3 = session.client("s3", region_name=region)
    except Exception as e:
        print(f"  Notice: S3 injection skipped (AWS session offline): {e}")
        return

    now = int(time.time())
    flow_records = []

    # 1. Normal flows
    if attack_type in ["ALL", "NORMAL"]:
        for _ in range(25):
            rec = f"5 {account_id} eni-0123456789abcdef0 192.168.1.55 {target_ip} {random.randint(40000, 60000)} 80 6 {random.randint(10, 50)} {random.randint(2000, 15000)} {now-60} {now} ACCEPT OK 27 IPv4 192.168.1.55 {target_ip}"
            flow_records.append(rec)

    # 2. Port scan flows
    if attack_type in ["ALL", "PORTSCAN"]:
        attacker_ip = "198.51.100.77"
        for p in [21, 22, 23, 25, 445, 1433, 3389]:
            rec = f"5 {account_id} eni-0123456789abcdef0 {attacker_ip} {target_ip} {random.randint(40000, 60000)} {p} 6 2 96 {now-30} {now-28} REJECT OK 2 IPv4 {attacker_ip} {target_ip}"
            flow_records.append(rec)

    # 3. DoS SYN flood flows
    if attack_type in ["ALL", "DOS"]:
        dos_ip = "203.0.113.19"
        for _ in range(15):
            rec = f"5 {account_id} eni-0123456789abcdef0 {dos_ip} {target_ip} {random.randint(1024, 65535)} 80 6 {random.randint(1200, 4500)} {random.randint(60000, 220000)} {now-20} {now} ACCEPT OK 2 IPv4 {dos_ip} {target_ip}"
            flow_records.append(rec)

    # 4. Brute force flows
    if attack_type in ["ALL", "BRUTEFORCE"]:
        bf_ip = "185.220.101.44"
        for _ in range(10):
            rec = f"5 {account_id} eni-0123456789abcdef0 {bf_ip} {target_ip} {random.randint(35000, 55000)} 80 6 {random.randint(30, 80)} {random.randint(4000, 12000)} {now-45} {now-20} ACCEPT OK 24 IPv4 {bf_ip} {target_ip}"
            flow_records.append(rec)

    content = "\n".join(flow_records) + "\n"
    gz_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
        gz.write(content.encode("utf-8"))
    gz_buffer.seek(0)

    obj_key = f"vpc-flow-logs/AWSLogs/{account_id}/vpcflowlogs/{region}/{time.strftime('%Y/%m/%d')}/{account_id}_vpcflowlogs_{region}_eni-0123456789abcdef0_{now}.log.gz"
    try:
        print(f"\n[+] Uploading simulated flow log batch to s3://{bucket_name}/{obj_key} ({len(flow_records)} records)...")
        s3.put_object(
            Bucket=bucket_name,
            Key=obj_key,
            Body=gz_buffer.getvalue(),
            ContentType="application/x-gzip"
        )
        print("  Upload complete. S3 Data Lake is now populated with live test telemetry.")
    except Exception as e:
        print(f"  Notice: S3 flow log upload skipped: {e}")

def run_all_simulations(target_ip_or_url: str = None):
    """Execute complete suite of cyber attack and legitimate traffic scenarios."""
    if target_ip_or_url is None:
        target_ip_or_url = get_default_target_url()

    base_url, host, port = parse_target(target_ip_or_url)
    print("=" * 72)
    print("Cloud Shield Cyber Traffic Simulation Suite")
    print(f"Target Portal:   {base_url}")
    print(f"Host / Port:     {host}:{port}")
    print("=" * 72)

    simulate_normal_traffic(base_url, count=12)
    simulate_port_scan(base_url)
    simulate_syn_flood(base_url, target_port=port, num_packets=40)
    simulate_brute_force(base_url, count=12)

    if STATE_FILE.exists():
        inject_s3_flow_logs("ALL")

    print("\n" + "=" * 72)
    print("Simulation Completed Successfully!")
    print("Open Streamlit SOC Monitor (http://localhost:8501) to observe real-time detections.")
    print("=" * 72)

def main():
    parser = argparse.ArgumentParser(description="Cloud Shield Cyber Attack Traffic Simulator")
    parser.add_argument("--target", type=str, default=None, help="Target URL or host (e.g., http://localhost:5000 or EC2 IP)")
    parser.add_argument("--mode", type=str, default="all", choices=["all", "dos", "bruteforce", "portscan", "normal", "s3"], help="Simulation mode to run")
    parser.add_argument("--count", type=int, default=None, help="Number of packets / attempts")
    args = parser.parse_args()

    target = args.target or get_default_target_url()

    if args.mode == "all":
        run_all_simulations(target)
    elif args.mode == "dos":
        simulate_syn_flood(target, num_packets=args.count or 50)
    elif args.mode == "bruteforce":
        simulate_brute_force(target, count=args.count or 15)
    elif args.mode == "portscan":
        simulate_port_scan(target)
    elif args.mode == "normal":
        simulate_normal_traffic(target, count=args.count or 15)
    elif args.mode == "s3":
        inject_s3_flow_logs("ALL")

if __name__ == "__main__":
    main()
