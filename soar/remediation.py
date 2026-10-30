import os
import sys
import json
import time
import hashlib
import ipaddress
import threading
from datetime import datetime, timezone
from pathlib import Path

# Ensure root in path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from config import IMMUTABLE_ALLOWLIST, AUDIT_LOG_FILE, STATE_FILE, get_aws_session

LEDGER_SECRET_SALT = "CloudShield-NonRepudiation-Salt-2026"
_soar_lock = threading.RLock()

class SecurityViolationError(Exception):
    """Raised when an operation attempts to violate safety rules (e.g., blocking allowlisted IP)."""
    pass

def canonicalize_ip(ip: str) -> str:
    """Canonicalize IP representation to prevent bypass tricks (hex, octal, int, CIDR, IPv4-mapped IPv6)."""
    if not isinstance(ip, str):
        ip = str(ip)
    ip_str = ip.strip()

    # Handle /32 or /128 single host CIDR notation
    if "/" in ip_str:
        try:
            net = ipaddress.ip_network(ip_str, strict=False)
            if net.num_addresses == 1:
                obj = net.network_address
            else:
                raise ValueError(f"CIDR ranges with multiple hosts ({ip_str}) are not supported for individual host quarantine.")
        except Exception as e:
            raise ValueError(f"Invalid IP address format '{ip}': {e}")
    else:
        try:
            obj = ipaddress.ip_address(ip_str)
        except Exception as e:
            raise ValueError(f"Invalid IP address format '{ip}': {e}")

    # Unpack IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254 -> 169.254.169.254)
    if isinstance(obj, ipaddress.IPv6Address) and obj.ipv4_mapped:
        obj = obj.ipv4_mapped

    return str(obj)

def is_ip_allowlisted(ip: str) -> bool:
    """
    Check if IP belongs to the Immutable Allowlist.
    Guarantees IMDS (169.254.169.254), VPC Gateway (10.0.0.1), Localhost, and Admin IP are immune.
    """
    try:
        canon_ip = canonicalize_ip(ip)
    except ValueError:
        return False

    for allow_entry in IMMUTABLE_ALLOWLIST:
        try:
            if "/" in allow_entry:
                if ipaddress.ip_address(canon_ip) in ipaddress.ip_network(allow_entry, strict=False):
                    return True
            else:
                if canon_ip == canonicalize_ip(allow_entry):
                    return True
        except Exception:
            continue
    return False

def _sign_audit_entry(entry: dict) -> str:
    """Generate SHA-256 HMAC-style signature over canonical audit fields for non-repudiation."""
    payload = f"{entry['timestamp']}|{entry['action']}|{entry['ip']}|{entry.get('reason','')}|{entry.get('operator','')}|{entry.get('status','')}|{entry.get('aws_rule_id','')}|{LEDGER_SECRET_SALT}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def _verify_entry_sig(entry: dict) -> bool:
    """Verify cryptographic signature, supporting both current and legacy canonical formats."""
    sig = entry.get("signature")
    if not sig:
        return False
    # Check current canonical payload
    if sig == _sign_audit_entry(entry):
        return True
    # Check legacy payload format
    legacy_payload = f"{entry.get('timestamp')}|{entry.get('action')}|{entry.get('ip')}|{entry.get('reason')}|{entry.get('operator')}|{LEDGER_SECRET_SALT}"
    if sig == hashlib.sha256(legacy_payload.encode("utf-8")).hexdigest():
        return True
    return False

def record_audit_entry(action: str, ip: str, reason: str, operator: str, status: str, mitre_technique: str = None, aws_rule_id: str = None):
    """Append-only write to SOAR non-repudiation audit ledger with thread safety."""
    with _soar_lock:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).isoformat()
        record = {
            "timestamp": timestamp,
            "action": action,
            "ip": ip,
            "reason": reason,
            "mitre_technique": mitre_technique or "N/A",
            "operator": operator,
            "status": status,
            "aws_rule_id": aws_rule_id or "local-simulated",
        }
        record["signature"] = _sign_audit_entry(record)

        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        return record

def verify_audit_ledger() -> list[dict]:
    """Read and cryptographically verify all entries in the non-repudiation ledger."""
    with _soar_lock:
        if not AUDIT_LOG_FILE.exists():
            return []

        verified_records = []
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    is_valid = _verify_entry_sig(entry)
                    entry["tamper_evident_valid"] = is_valid
                    verified_records.append(entry)
                except Exception:
                    continue

        return verified_records

def get_quarantined_ips() -> set[str]:
    """Derive current active set of quarantined IPs from verified audit log (ignoring tampered entries)."""
    with _soar_lock:
        records = verify_audit_ledger()
        quarantined = set()
        for r in records:
            if r.get("tamper_evident_valid", False) and r.get("status") == "SUCCESS":
                if r.get("action") == "QUARANTINE_IP":
                    quarantined.add(r.get("ip"))
                elif r.get("action") == "RESTORE_IP":
                    quarantined.discard(r.get("ip"))
        return quarantined

def quarantine_ip(ip: str, reason: str, mitre_technique: str = None, operator: str = "CloudShield-AutoSOAR", dry_run: bool = False) -> dict:
    """
    Quarantine an attacking IP.
    Enforces Immutable Allowlist, applies AWS Network ACL rule if infra is active,
    and commits to audit ledger. Thread-safe.
    """
    with _soar_lock:
        canon_ip = canonicalize_ip(ip)

        # 1. IMMUTABLE SAFETY CHECK
        if is_ip_allowlisted(canon_ip):
            msg = f"IMMUTABLE SAFETY GUARD: IP '{canon_ip}' is in protected allowlist (Gateway/IMDS/Admin) and CANNOT be quarantined!"
            record_audit_entry(
                action="QUARANTINE_REJECTED",
                ip=canon_ip,
                reason=f"REJECTED: Allowlist protection: {reason}",
                operator=operator,
                status="BLOCKED_BY_ALLOWLIST",
                mitre_technique=mitre_technique
            )
            raise SecurityViolationError(msg)

        # Check if already quarantined
        if canon_ip in get_quarantined_ips():
            return {"ip": canon_ip, "status": "ALREADY_QUARANTINED", "message": f"IP {canon_ip} is already quarantined."}

        aws_rule_id = "local-simulated"

        # 2. AWS LIVE ENFORCEMENT (If infrastructure state file exists)
        if not dry_run and STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r") as f:
                    state = json.load(f)
                nacl_id = state.get("network_acl_id")
                region = state.get("region")
                if nacl_id and region:
                    session = get_aws_session()
                    ec2 = session.client("ec2", region_name=region)
                    # Inspect existing entries to allocate non-colliding rule number
                    desc = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
                    entries = desc["NetworkAcls"][0].get("Entries", [])
                    used_rules = {e["RuleNumber"] for e in entries if not e.get("Egress")}
                    
                    # Check if IP already blocked in NACL
                    existing_entry = next((e for e in entries if e.get("CidrBlock") == f"{canon_ip}/32" and not e.get("Egress")), None)
                    if existing_entry:
                        rule_no = existing_entry["RuleNumber"]
                    else:
                        rule_no = None
                        # Prioritize rule numbers before default allow rule 100
                        for r in range(20, 100):
                            if r not in used_rules:
                                rule_no = r
                                break
                        if rule_no is None:
                            for r in range(101, 32000):
                                if r not in used_rules:
                                    rule_no = r
                                    break

                        if rule_no is None:
                            raise RuntimeError(f"Network ACL {nacl_id} has exhausted available rule slots.")

                        ec2.create_network_acl_entry(
                            NetworkAclId=nacl_id,
                            RuleNumber=rule_no,
                            Protocol="-1",
                            RuleAction="deny",
                            Egress=False,
                            CidrBlock=f"{canon_ip}/32"
                        )
                    aws_rule_id = f"nacl-rule-{rule_no}"
            except Exception as e:
                # Honest audit trail on failure
                record_audit_entry(
                    action="QUARANTINE_FAILED",
                    ip=canon_ip,
                    reason=f"AWS Enforcement Error: {e}",
                    operator=operator,
                    status="FAILED",
                    mitre_technique=mitre_technique,
                    aws_rule_id=f"aws-error: {str(e)[:40]}"
                )
                raise RuntimeError(f"Failed to enforce quarantine in AWS NACL: {e}")

        # 3. COMMIT AUDIT RECORD
        rec = record_audit_entry(
            action="QUARANTINE_IP",
            ip=canon_ip,
            reason=reason,
            operator=operator,
            status="SUCCESS",
            mitre_technique=mitre_technique,
            aws_rule_id=aws_rule_id
        )
        return {"ip": canon_ip, "status": "SUCCESS", "record": rec}

def restore_ip(ip: str, reason: str = "Analyst remediation override", operator: str = "CloudShield-Admin", dry_run: bool = False) -> dict:
    """
    Restore a quarantined IP back to normal traffic access. Thread-safe.
    """
    with _soar_lock:
        canon_ip = canonicalize_ip(ip)

        if canon_ip not in get_quarantined_ips():
            return {"ip": canon_ip, "status": "NOT_QUARANTINED", "message": f"IP {canon_ip} is not currently quarantined."}

        aws_rule_id = "local-restored"

        # AWS LIVE REVERSAL
        if not dry_run and STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r") as f:
                    state = json.load(f)
                nacl_id = state.get("network_acl_id")
                region = state.get("region")
                if nacl_id and region:
                    session = get_aws_session()
                    ec2 = session.client("ec2", region_name=region)
                    desc = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
                    entries = desc["NetworkAcls"][0].get("Entries", [])
                    deleted_any = False
                    for entry in entries:
                        if entry.get("CidrBlock") == f"{canon_ip}/32" and not entry.get("Egress"):
                            ec2.delete_network_acl_entry(
                                NetworkAclId=nacl_id,
                                RuleNumber=entry["RuleNumber"],
                                Egress=False
                            )
                            aws_rule_id = f"nacl-deleted-rule-{entry['RuleNumber']}"
                            deleted_any = True
                            break
                    if not deleted_any:
                        aws_rule_id = "nacl-rule-not-found-already-removed"
            except Exception as e:
                record_audit_entry(
                    action="RESTORE_FAILED",
                    ip=canon_ip,
                    reason=f"AWS Restoration Error: {e}",
                    operator=operator,
                    status="FAILED",
                    aws_rule_id=f"aws-error: {str(e)[:40]}"
                )
                raise RuntimeError(f"Failed to remove quarantine rule from AWS NACL: {e}")

        rec = record_audit_entry(
            action="RESTORE_IP",
            ip=canon_ip,
            reason=reason,
            operator=operator,
            status="SUCCESS",
            aws_rule_id=aws_rule_id
        )
        return {"ip": canon_ip, "status": "SUCCESS", "record": rec}

