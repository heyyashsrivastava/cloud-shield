import pytest
import sys
import json
from pathlib import Path

# Add project root
sys.path.append(str(Path(__file__).resolve().parent.parent))
from soar.remediation import (
    quarantine_ip, restore_ip, is_ip_allowlisted,
    SecurityViolationError, verify_audit_ledger, get_quarantined_ips
)
from config import IMMUTABLE_ALLOWLIST

def test_immutable_allowlist_protection():
    """Verify that IMDS (169.254.169.254) and VPC gateway (10.0.0.1) cannot be blocked."""
    assert is_ip_allowlisted("169.254.169.254") is True
    assert is_ip_allowlisted("10.0.0.1") is True
    assert is_ip_allowlisted("127.0.0.1") is True

    # Attempting to quarantine allowlisted IP MUST raise SecurityViolationError
    with pytest.raises(SecurityViolationError) as exc_info:
        quarantine_ip("169.254.169.254", reason="Attempted unauthorized block", dry_run=True)
    assert "IMMUTABLE SAFETY GUARD" in str(exc_info.value)

    with pytest.raises(SecurityViolationError) as exc_info2:
        quarantine_ip("10.0.0.1", reason="Gateway block test", dry_run=True)
    assert "IMMUTABLE SAFETY GUARD" in str(exc_info2.value)

def test_cidr_and_ipv6_mapped_allowlist_protection():
    """Verify that CIDR notation (/32) and IPv4-mapped IPv6 representations cannot bypass allowlist."""
    assert is_ip_allowlisted("169.254.169.254/32") is True
    assert is_ip_allowlisted("10.0.0.1/32") is True
    assert is_ip_allowlisted("::ffff:169.254.169.254") is True

    with pytest.raises(SecurityViolationError):
        quarantine_ip("169.254.169.254/32", reason="Bypass test with CIDR", dry_run=True)

    with pytest.raises(SecurityViolationError):
        quarantine_ip("::ffff:169.254.169.254", reason="Bypass test with IPv6 mapping", dry_run=True)

def test_quarantine_and_restore_cycle():
    """Verify reversible quarantine and restore lifecycle on an attacker IP."""
    test_ip = "198.51.100.99"
    assert is_ip_allowlisted(test_ip) is False

    # Ensure clean starting state for test IP
    restore_ip(test_ip, reason="Clean setup", dry_run=True)

    # 1. Quarantine
    q_res = quarantine_ip(test_ip, reason="SYN Flood test", mitre_technique="T1498.001", dry_run=True)
    assert q_res["status"] == "SUCCESS"
    assert test_ip in get_quarantined_ips()

    # 2. Restore
    r_res = restore_ip(test_ip, reason="Post-incident analyst clearance", dry_run=True)
    assert r_res["status"] == "SUCCESS"
    assert test_ip not in get_quarantined_ips()

def test_concurrent_quarantine_thread_safety():
    """Verify thread-safety and race condition prevention on concurrent quarantine requests."""
    import concurrent.futures
    concurrent_ip = "198.51.100.77"
    restore_ip(concurrent_ip, reason="Clean test state", dry_run=True)

    def do_quarantine(ip):
        return quarantine_ip(ip, reason="Concurrent test", dry_run=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(do_quarantine, [concurrent_ip] * 5))

    statuses = [r["status"] for r in results]
    assert statuses.count("SUCCESS") == 1
    assert statuses.count("ALREADY_QUARANTINED") == 4
    assert concurrent_ip in get_quarantined_ips()

    # Cleanup
    restore_ip(concurrent_ip, reason="Clean test state", dry_run=True)

def test_audit_ledger_non_repudiation():
    """Verify SHA-256 digital signature validity and non-repudiation in audit ledger."""
    ledger = verify_audit_ledger()
    assert len(ledger) > 0
    # Every single recorded entry must be tamper-evident valid
    for entry in ledger:
        assert entry["tamper_evident_valid"] is True
        assert len(entry["signature"]) == 64  # SHA-256 hex string length

def test_tampered_audit_ledger_entry_detection(tmp_path, monkeypatch):
    """Verify that modified ledger entries fail cryptographic verification and are excluded from active quarantined IPs."""
    from soar import remediation
    fake_log = tmp_path / "fake_audit.jsonl"
    monkeypatch.setattr(remediation, "AUDIT_LOG_FILE", fake_log)

    # Record legitimate quarantine
    rec = remediation.record_audit_entry(
        action="QUARANTINE_IP",
        ip="198.51.100.66",
        reason="Real attack",
        operator="CloudShield-AutoSOAR",
        status="SUCCESS"
    )

    # Verify initially valid
    records = remediation.verify_audit_ledger()
    assert len(records) == 1
    assert records[0]["tamper_evident_valid"] is True
    assert "198.51.100.66" in remediation.get_quarantined_ips()

    # Tamper with the ledger file (change IP to an innocent address without updating signature)
    tampered_entry = rec.copy()
    tampered_entry["ip"] = "192.168.1.10"
    with open(fake_log, "w", encoding="utf-8") as f:
        f.write(json.dumps(tampered_entry) + "\n")

    # Verify tampering is caught
    tampered_records = remediation.verify_audit_ledger()
    assert len(tampered_records) == 1
    assert tampered_records[0]["tamper_evident_valid"] is False
    # Fraudulent IP must NOT be considered quarantined
    assert "192.168.1.10" not in remediation.get_quarantined_ips()
