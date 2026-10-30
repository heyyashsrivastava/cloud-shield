import pandas as pd
import numpy as np

# Exact features used by ML models (Zero IP Leakage)
FEATURE_COLUMNS = [
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "duration",
    "bytes_per_packet",
    "packet_rate",
    "byte_rate",
    "tcp_flags",
    "flag_syn",
    "flag_ack",
    "flag_fin",
    "flag_rst",
    "flag_psh",
    "flag_urg",
    "syn_only",
    "syn_ack",
    "is_well_known_port",
    "is_ephemeral_port",
    "is_http_https",
    "is_ssh_rdp",
    "action_accepted"
]

FORBIDDEN_COLUMNS = {
    "srcaddr", "dstaddr", "pkt-srcaddr", "pkt-dstaddr",
    "src_ip", "dst_ip", "ip", "interface-id", "account-id"
}

def parse_flow_log_line(line: str) -> dict:
    """
    Parse a single AWS VPC Flow Log v5 record into a dictionary.
    Format:
    version account-id interface-id srcaddr dstaddr srcport dstport
    protocol packets bytes start end action log-status tcp-flags type pkt-srcaddr pkt-dstaddr
    """
    parts = line.strip().split()
    if len(parts) < 14:
        return None
    
    try:
        # Standard fields
        record = {
            "version": parts[0],
            "account_id": parts[1],
            "interface_id": parts[2],
            "srcaddr": parts[3],
            "dstaddr": parts[4],
            "srcport": int(parts[5]) if parts[5] != "-" else 0,
            "dstport": int(parts[6]) if parts[6] != "-" else 0,
            "protocol": int(parts[7]) if parts[7] != "-" else 6,
            "packets": int(parts[8]) if parts[8] != "-" else 0,
            "bytes": int(parts[9]) if parts[9] != "-" else 0,
            "start": int(parts[10]) if parts[10] != "-" else 0,
            "end": int(parts[11]) if parts[11] != "-" else 0,
            "action": parts[12],
            "log_status": parts[13],
            "tcp_flags": int(parts[14]) if len(parts) > 14 and parts[14] != "-" else 0,
            "flow_type": parts[15] if len(parts) > 15 else "IPv4",
            "pkt_srcaddr": parts[16] if len(parts) > 16 else parts[3],
            "pkt_dstaddr": parts[17] if len(parts) > 17 else parts[4]
        }
        return record
    except Exception:
        return None

def extract_features_from_dict(row: dict) -> dict:
    """Extract zero-IP leakage behavioral features from a flow dictionary."""
    srcport = int(row.get("srcport", 0))
    dstport = int(row.get("dstport", 0))
    protocol = int(row.get("protocol", 6))
    packets = max(int(row.get("packets", 1)), 1)
    n_bytes = max(int(row.get("bytes", 0)), 0)
    
    start = int(row.get("start", 0))
    end = int(row.get("end", 0))
    duration = max(end - start, 0)
    
    # Ratios and rates
    bytes_per_packet = n_bytes / max(packets, 1)
    effective_duration = max(duration, 0.05)
    packet_rate = packets / effective_duration
    byte_rate = n_bytes / effective_duration
    
    # TCP flag bitmasks
    tcp_flags = int(row.get("tcp_flags", 0))
    flag_fin = 1 if (tcp_flags & 1) else 0
    flag_syn = 1 if (tcp_flags & 2) else 0
    flag_rst = 1 if (tcp_flags & 4) else 0
    flag_psh = 1 if (tcp_flags & 8) else 0
    flag_ack = 1 if (tcp_flags & 16) else 0
    flag_urg = 1 if (tcp_flags & 32) else 0
    syn_only = 1 if (tcp_flags == 2) else 0
    syn_ack = 1 if ((tcp_flags & 18) == 18) else 0
    
    action_val = str(row.get("action", "ACCEPT")).upper()
    action_accepted = 1 if action_val == "ACCEPT" else 0
    
    return {
        "srcport": srcport,
        "dstport": dstport,
        "protocol": protocol,
        "packets": packets,
        "bytes": n_bytes,
        "duration": duration,
        "bytes_per_packet": bytes_per_packet,
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "tcp_flags": tcp_flags,
        "flag_syn": flag_syn,
        "flag_ack": flag_ack,
        "flag_fin": flag_fin,
        "flag_rst": flag_rst,
        "flag_psh": flag_psh,
        "flag_urg": flag_urg,
        "syn_only": syn_only,
        "syn_ack": syn_ack,
        "is_well_known_port": 1 if dstport < 1024 else 0,
        "is_ephemeral_port": 1 if srcport >= 1024 else 0,
        "is_http_https": 1 if dstport in (80, 443, 8080, 8443) else 0,
        "is_ssh_rdp": 1 if dstport in (22, 3389) else 0,
        "action_accepted": action_accepted
    }

def transform_flow_logs(df_or_dicts) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Transforms raw flow log records into:
    1. X_features (Zero IP Leakage DataFrame ready for ML inference)
    2. metadata_df (Contextual info: srcaddr, dstaddr, start, action for SOC & SOAR)
    """
    if isinstance(df_or_dicts, pd.DataFrame):
        records = df_or_dicts.to_dict(orient="records")
    elif isinstance(df_or_dicts, list):
        records = df_or_dicts
    else:
        raise ValueError("Expected list of dicts or pandas DataFrame")

    feature_list = []
    metadata_list = []

    for r in records:
        f = extract_features_from_dict(r)
        feature_list.append(f)
        
        meta = {
            "srcaddr": r.get("srcaddr", "0.0.0.0"),
            "dstaddr": r.get("dstaddr", "0.0.0.0"),
            "srcport": r.get("srcport", 0),
            "dstport": r.get("dstport", 0),
            "start": r.get("start", 0),
            "end": r.get("end", 0),
            "action": r.get("action", "ACCEPT"),
            "interface_id": r.get("interface_id", "eni-00000000")
        }
        metadata_list.append(meta)

    X_df = pd.DataFrame(feature_list)[FEATURE_COLUMNS]
    meta_df = pd.DataFrame(metadata_list)

    # Zero IP Leakage Guarantee Verification
    assert_zero_ip_leakage(X_df)

    return X_df, meta_df

def assert_zero_ip_leakage(features_df: pd.DataFrame):
    """Rigorous assertion to prove no IP address or identity leaked into ML features."""
    for col in features_df.columns:
        col_l = col.lower()
        if col_l in FORBIDDEN_COLUMNS or "addr" in col_l or ("ip" in col_l and col != "is_ephemeral_port"):
            raise AssertionError(f"Zero IP Leakage Violated: Detected forbidden column '{col}' in features!")
    # Check data types: must all be numeric
    for col in features_df.columns:
        if not np.issubdtype(features_df[col].dtype, np.number):
            raise AssertionError(f"Zero IP Leakage Violated: Column '{col}' is non-numeric ({features_df[col].dtype})!")
