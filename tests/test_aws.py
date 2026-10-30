import pytest
import sys
from pathlib import Path

# Add project root
sys.path.append(str(Path(__file__).resolve().parent.parent))
from config import get_aws_identity, get_bucket_name, VPC_CIDR, SUBNET_CIDR, FLOW_LOG_FIELDS

def test_aws_identity_detection():
    """Verify live STS caller identity detection from user's AWS session."""
    identity = get_aws_identity()
    assert isinstance(identity, dict)
    assert "account_id" in identity
    assert "region" in identity
    assert len(identity["account_id"]) > 0
    assert isinstance(identity["region"], str) and len(identity["region"]) > 0
    assert identity["connected"] is True

def test_bucket_name_generation():
    """Verify generated S3 bucket name is lowercased and conforms to AWS naming rules."""
    bname = get_bucket_name(account_id="301276846152", region="ap-south-1")
    assert bname == "cloud-shield-flow-logs-301276846152-ap-south-1"
    assert bname.islower()
    assert len(bname) < 63

def test_flow_log_fields_compliance():
    """Verify enhanced VPC Flow Log schema includes transport and TCP flags."""
    assert "version" in FLOW_LOG_FIELDS
    assert "tcp-flags" in FLOW_LOG_FIELDS
    assert "protocol" in FLOW_LOG_FIELDS
    assert "packets" in FLOW_LOG_FIELDS
    assert "bytes" in FLOW_LOG_FIELDS
    assert "pkt-srcaddr" in FLOW_LOG_FIELDS
