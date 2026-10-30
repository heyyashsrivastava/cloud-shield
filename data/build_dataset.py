import random
import json
import time
import pandas as pd
import numpy as np
from pathlib import Path
import sys

# Ensure parent directory is in path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from config import DATA_DIR, MITRE_ATTACK_MAP, get_aws_identity
from ml.feature_extraction import transform_flow_logs, FEATURE_COLUMNS, assert_zero_ip_leakage

def generate_synthetic_flow_dataset(n_samples: int = 15000) -> pd.DataFrame:
    """
    Generate synthetic VPC Flow Logs conforming to AWS v5 schema with known attack profiles.
    Classes:
    0: BENIGN (60%)
    1: PortScan (15%)
    2: DoS_SYN (15%)
    3: BruteForce (10%)
    """
    random.seed(42)
    np.random.seed(42)

    base_time = int(time.time()) - 86400
    account_id = get_aws_identity().get("account_id", "301276846152")
    rows = []

    benign_ips = [f"192.168.1.{i}" for i in range(10, 50)] + [f"10.0.1.{i}" for i in range(10, 30)]
    web_server_ip = "10.0.1.100"
    gateway_ip = "10.0.0.1"

    attacker_ips = [
        "198.51.100.23", "203.0.113.88", "185.220.101.5",
        "45.33.32.156", "91.240.118.172", "194.26.29.111"
    ]

    for i in range(n_samples):
        # Choose class based on distribution
        dice = random.random()
        if dice < 0.60:
            attack_class = 0  # BENIGN
        elif dice < 0.75:
            attack_class = 1  # PortScan
        elif dice < 0.90:
            attack_class = 2  # DoS_SYN
        else:
            attack_class = 3  # BruteForce

        flow_start = base_time + random.randint(0, 86400)
        
        if attack_class == 0:
            # BENIGN
            src_ip = random.choice(benign_ips)
            dst_ip = web_server_ip if random.random() > 0.3 else gateway_ip
            dst_port = random.choice([80, 443, 53, 8080, 8443, 123])
            src_port = random.randint(32768, 61000)
            protocol = 17 if dst_port in [53, 123] else 6
            duration = random.randint(1, 45)
            flow_end = flow_start + duration
            packets = random.randint(5, 120)
            avg_pkt_size = random.randint(400, 1400)
            n_bytes = packets * avg_pkt_size
            # Common flags: SYN+ACK+FIN+PSH (18 + 1 + 8 = 27) or ACK (16)
            tcp_flags = random.choice([16, 24, 27, 18, 0]) if protocol == 6 else 0
            action = "ACCEPT"

        elif attack_class == 1:
            # PortScan (T1046)
            src_ip = random.choice(attacker_ips)
            dst_ip = web_server_ip
            # Random scanning port (often closed or high-range)
            dst_port = random.choice([21, 22, 23, 25, 110, 135, 139, 445, 1433, 3306, 3389, 5900, 8000, 8888, 9200])
            src_port = random.randint(40000, 65000)
            protocol = 6
            duration = random.randint(0, 2)
            flow_end = flow_start + duration
            packets = random.choice([1, 2, 3])
            n_bytes = packets * random.randint(40, 64)  # Small probe packets
            tcp_flags = 2  # SYN only
            action = "REJECT" if dst_port not in [80] else "ACCEPT"

        elif attack_class == 2:
            # DoS_SYN (T1498.001)
            src_ip = random.choice(attacker_ips)
            dst_ip = web_server_ip
            dst_port = 80
            src_port = random.randint(1024, 65535)
            protocol = 6
            duration = random.randint(0, 3)
            flow_end = flow_start + duration
            # Massive burst of pure SYN packets
            packets = random.randint(250, 4000)
            n_bytes = packets * random.randint(40, 54)  # Zero payload, pure headers
            tcp_flags = 2  # Pure SYN bitmask
            action = "ACCEPT"

        else:
            # BruteForce (T1110.001)
            src_ip = random.choice(attacker_ips)
            dst_ip = web_server_ip
            dst_port = random.choice([80, 22, 3389])
            src_port = random.randint(30000, 60000)
            protocol = 6
            duration = random.randint(3, 25)
            flow_end = flow_start + duration
            # Moderate packet exchange with PSH+ACK
            packets = random.randint(25, 90)
            n_bytes = packets * random.randint(120, 350)
            tcp_flags = random.choice([24, 25, 18])  # PSH+ACK / SYN+ACK
            action = "ACCEPT" if dst_port == 80 else "REJECT"

        record = {
            "version": "5",
            "account_id": account_id,
            "interface_id": "eni-0a1b2c3d4e5f6g7h8",
            "srcaddr": src_ip,
            "dstaddr": dst_ip,
            "srcport": src_port,
            "dstport": dst_port,
            "protocol": protocol,
            "packets": packets,
            "bytes": n_bytes,
            "start": flow_start,
            "end": flow_end,
            "action": action,
            "log_status": "OK",
            "tcp_flags": tcp_flags,
            "type": "IPv4",
            "pkt_srcaddr": src_ip,
            "pkt_dstaddr": dst_ip,
            "label": attack_class
        }
        rows.append(record)

    df = pd.DataFrame(rows)
    return df

def build_and_save_data():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print("Generating synthetic VPC flow dataset (15,000 flows)...")
    df = generate_synthetic_flow_dataset(15000)
    
    csv_path = DATA_DIR / "synthetic_vpc_flows.csv"
    df.to_csv(csv_path, index=False)
    print(f"Saved synthetic dataset to: {csv_path}")
    print(f"Class distribution:\n{df['label'].value_counts(normalize=True)}")

    # Extract sample flows for instant replay in SOC dashboard (50 flows with balanced attacks)
    sample_flows = []
    for label in [0, 1, 2, 3]:
        subset = df[df["label"] == label].sample(15, random_state=42).to_dict(orient="records")
        sample_flows.extend(subset)
    random.shuffle(sample_flows)

    sample_path = DATA_DIR / "sample_flows.json"
    with open(sample_path, "w") as f:
        json.dump(sample_flows, f, indent=2)
    print(f"Saved {len(sample_flows)} sample flows to: {sample_path}")

    # Verify Zero IP Leakage
    X_features, _ = transform_flow_logs(df)
    assert_zero_ip_leakage(X_features)
    print("Zero IP Leakage assertion PASSED: No IP addresses leaked into feature matrix.")

if __name__ == "__main__":
    build_and_save_data()
