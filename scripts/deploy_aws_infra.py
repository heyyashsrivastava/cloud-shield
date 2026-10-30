import os
import sys
import json
import time
import base64
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config import (
    get_aws_identity, get_aws_session, get_bucket_name,
    VPC_CIDR, SUBNET_CIDR, FLOW_LOG_FORMAT, STATE_FILE, PROJECT_TAG
)

def deploy_infrastructure():
    print("=" * 60)
    print("Cloud Shield: Deploying AWS Infrastructure")
    print("=" * 60)

    identity = get_aws_identity()
    if not identity.get("connected"):
        print(f"Error connecting to AWS: {identity.get('error')}")
        sys.exit(1)

    account_id = identity["account_id"]
    region = identity["region"]
    print(f"AWS Account: {account_id}")
    print(f"AWS Region:  {region}")

    session = get_aws_session()
    ec2 = session.client("ec2", region_name=region)
    s3 = session.client("s3", region_name=region)
    iam = session.client("iam", region_name=region)
    ssm = session.client("ssm", region_name=region)

    state = {
        "account_id": account_id,
        "region": region,
        "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    # 1. CREATE S3 BUCKET FOR VPC FLOW LOGS
    bucket_name = get_bucket_name(account_id, region)
    print(f"\n[1/7] Creating S3 Data Lake Bucket: {bucket_name}...")
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region}
            )
        print("  Bucket created successfully.")
    except ClientError as e:
        if e.response["Error"]["Code"] in ["BucketAlreadyOwnedByYou", "BucketAlreadyExists"]:
            print("  Bucket already exists, reusing.")
        else:
            raise e
    state["s3_bucket"] = bucket_name

    # 1.1 Enable AES256 Encryption
    print("  Enabling AES256 server-side encryption...")
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        }
    )

    # 1.2 Enable 1-Day Auto-Expiry Lifecycle Rule
    print("  Configuring 1-day auto-expiry lifecycle rule...")
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket_name,
        LifecycleConfiguration={
            "Rules": [{
                "ID": "CloudShieldFlowLogsAutoExpiry",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Expiration": {"Days": 1}
            }]
        }
    )

    # 1.3 Configure Bucket Policy for VPC Flow Logs Delivery Service
    print("  Applying IAM Bucket Policy for AWS Delivery Service...")
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSLogDeliveryWrite",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": account_id
                    }
                }
            },
            {
                "Sid": "AWSLogDeliveryAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": ["s3:GetBucketAcl", "s3:ListBucket"],
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id}
                }
            }
        ]
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    # 2. CREATE IAM ROLE & INSTANCE PROFILE FOR SSM (No SSH port 22 needed)
    role_name = "CloudShield-EC2-SSM-Role"
    profile_name = "CloudShield-EC2-SSM-Profile"
    print(f"\n[2/7] Configuring IAM SSM Instance Profile: {profile_name}...")
    assume_role_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_doc),
            Description="SSM Role for Cloud Shield Target EC2 Tier"
        )
        print("  Created IAM Role.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print("  IAM Role already exists.")
        else:
            raise e

    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    )

    try:
        iam.create_instance_profile(InstanceProfileName=profile_name)
        print("  Created IAM Instance Profile.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            pass
        else:
            raise e

    try:
        iam.add_role_to_instance_profile(
            InstanceProfileName=profile_name,
            RoleName=role_name
        )
        # Give AWS IAM a couple seconds to propagate
        time.sleep(3)
    except ClientError as e:
        if e.response["Error"]["Code"] == "LimitExceeded" or "Cannot exceed quota" in str(e):
            pass
        elif e.response["Error"]["Code"] != "EntityAlreadyExists":
            pass
    state["iam_role"] = role_name
    state["instance_profile"] = profile_name

    # 3. CREATE VPC & NETWORKING
    print(f"\n[3/7] Provisioning VPC ({VPC_CIDR})...")
    vpc_resp = ec2.create_vpc(
        CidrBlock=VPC_CIDR,
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Project", "Value": PROJECT_TAG}, {"Key": "Name", "Value": "CloudShield-VPC"}]
        }]
    )
    vpc_id = vpc_resp["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    print(f"  VPC created: {vpc_id}")
    state["vpc_id"] = vpc_id

    # Create Internet Gateway
    igw_resp = ec2.create_internet_gateway(
        TagSpecifications=[{
            "ResourceType": "internet-gateway",
            "Tags": [{"Key": "Project", "Value": PROJECT_TAG}, {"Key": "Name", "Value": "CloudShield-IGW"}]
        }]
    )
    igw_id = igw_resp["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    print(f"  Attached Internet Gateway: {igw_id}")
    state["igw_id"] = igw_id

    # Subnet
    sub_resp = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=SUBNET_CIDR,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Project", "Value": PROJECT_TAG}, {"Key": "Name", "Value": "CloudShield-PublicSubnet"}]
        }]
    )
    subnet_id = sub_resp["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    print(f"  Subnet created: {subnet_id}")
    state["subnet_id"] = subnet_id

    # Route Table
    rt_resp = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{
            "ResourceType": "route-table",
            "Tags": [{"Key": "Project", "Value": PROJECT_TAG}, {"Key": "Name", "Value": "CloudShield-RouteTable"}]
        }]
    )
    rt_id = rt_resp["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)
    print(f"  Route table associated with Internet Gateway: {rt_id}")
    state["route_table_id"] = rt_id

    # Get Default Network ACL
    nacls = ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkAcls"]
    nacl_id = nacls[0]["NetworkAclId"] if nacls else None
    print(f"  Network ACL associated: {nacl_id}")
    state["network_acl_id"] = nacl_id

    # 4. CREATE SECURITY GROUP (Port 80 OPEN for web traffic, Port 22 CLOSED - SSM managed)
    print("\n[4/7] Creating Security Group (Port 80 OPEN, Port 22 CLOSED)...")
    sg_resp = ec2.create_security_group(
        GroupName="CloudShield-TargetSG",
        Description="Cloud Shield Target Tier (HTTP Port 80 open, Port 22 closed)",
        VpcId=vpc_id,
        TagSpecifications=[{
            "ResourceType": "security-group",
            "Tags": [{"Key": "Project", "Value": PROJECT_TAG}, {"Key": "Name", "Value": "CloudShield-TargetSG"}]
        }]
    )
    sg_id = sg_resp["GroupId"]
    # Ingress rule: HTTP 80
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTP Web Traffic"}]
        }]
    )
    print(f"  Security Group configured: {sg_id} (Port 22 SSH remains strictly CLOSED)")
    state["security_group_id"] = sg_id

    # 5. CREATE CUSTOM ENHANCED VPC FLOW LOGS
    print(f"\n[5/7] Creating Custom VPC Flow Logs to S3 ({bucket_name})...")
    flow_log_resp = ec2.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="s3",
        LogDestination=f"arn:aws:s3:::{bucket_name}/vpc-flow-logs/",
        LogFormat=FLOW_LOG_FORMAT,
        MaxAggregationInterval=60,
        TagSpecifications=[{
            "ResourceType": "vpc-flow-log",
            "Tags": [{"Key": "Project", "Value": PROJECT_TAG}, {"Key": "Name", "Value": "CloudShield-FlowLogs"}]
        }]
    )
    flow_log_ids = flow_log_resp.get("FlowLogIds", [])
    flow_log_id = flow_log_ids[0] if flow_log_ids else "fl-unknown"
    print(f"  VPC Flow Log ID: {flow_log_id}")
    state["flow_log_id"] = flow_log_id

    # 6. LAUNCH EC2 TARGET TIER (Apache HTTPD + SSM)
    print("\n[6/7] Launching EC2 Target Instance with Apache HTTPD...")
    # Find latest Amazon Linux 2023 AMI
    try:
        param = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
        ami_id = param["Parameter"]["Value"]
    except Exception:
        # Fallback to general lookup
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
                {"Name": "state", "Values": ["available"]}
            ]
        )["Images"]
        images.sort(key=lambda x: x["CreationDate"], reverse=True)
        ami_id = images[0]["ImageId"] if images else "ami-0c2af51e265bd5e0e"

    # Read target_website.py to inject into EC2 UserData
    target_app_path = Path(__file__).resolve().parent.parent / "target_website.py"
    target_code_b64 = ""
    if target_app_path.exists():
        with open(target_app_path, "rb") as f:
            target_code_b64 = base64.b64encode(f.read()).decode("utf-8")

    user_data_script = f"""#!/bin/bash
dnf update -y || yum update -y
dnf install -y python3-pip httpd || yum install -y python3-pip httpd
pip3 install flask

mkdir -p /opt/cloudshield/data

cat << 'EOF_B64' | base64 -d > /opt/cloudshield/target_website.py
{target_code_b64}
EOF_B64

cat << 'EOF_SVC' > /etc/systemd/system/apex-portal.service
[Unit]
Description=Apex Financial Portal - Cloud Shield Target Tier
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/cloudshield
ExecStart=/usr/bin/python3 /opt/cloudshield/target_website.py --port 80 --host 0.0.0.0
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF_SVC

systemctl daemon-reload
systemctl enable apex-portal.service
systemctl start apex-portal.service

# Secondary safety: if Python service doesn't start, fall back to Apache HTTPD
sleep 2
if ! systemctl is-active --quiet apex-portal; then
    cat << 'EOF_HTML' > /var/www/html/index.html
<!DOCTYPE html>
<html>
<head><title>Apex Financial Portal | Cloud Shield Target Tier</title><meta http-equiv="refresh" content="5"></head>
<body style="font-family:sans-serif;background:#0b1120;color:#f8fafc;padding:40px;text-align:center;">
  <h1>⟁ Apex Global Financial Portal</h1>
  <p>VPC: {vpc_id} | Port 80 Open | Port 22 Closed</p>
  <p style="color:#10b981;">Target tier initializing Python Flask service... Auto-refreshing in 5s</p>
</body>
</html>
EOF_HTML
    systemctl start httpd
    systemctl enable httpd
fi
"""
    user_data_b64 = base64.b64encode(user_data_script.encode("utf-8")).decode("utf-8")

    instance_type = "t3.micro"
    run_resp = None
    max_launch_attempts = 12
    for attempt in range(max_launch_attempts):
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType=instance_type,
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                SecurityGroupIds=[sg_id],
                IamInstanceProfile={"Name": profile_name},
                UserData=user_data_b64,
                TagSpecifications=[{
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Project", "Value": PROJECT_TAG}, {"Key": "Name", "Value": "CloudShield-TargetEC2"}]
                }]
            )
            break
        except ClientError as e:
            err_code = e.response["Error"]["Code"]
            err_msg = e.response["Error"]["Message"]
            if "InstanceType" in str(e) or "Unsupported" in err_code:
                print(f"  Instance type {instance_type} not offered in this AZ, switching to t2.micro...")
                instance_type = "t2.micro"
            elif "iamInstanceProfile" in err_msg or "InvalidParameterValue" in err_code:
                print(f"  IAM Instance Profile replicating across AWS EC2 (attempt {attempt+1}/{max_launch_attempts}), waiting 5s...")
                time.sleep(5)
            else:
                if attempt == max_launch_attempts - 1:
                    raise e
                time.sleep(3)
    
    if not run_resp:
        raise RuntimeError("Failed to launch EC2 target tier after retries.")

    instance_id = run_resp["Instances"][0]["InstanceId"]
    print(f"  EC2 instance launched: {instance_id} ({instance_type})")
    state["instance_id"] = instance_id

    # Wait for instance public IP
    print("  Waiting for public IP assignment...")
    for _ in range(15):
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        inst = desc["Reservations"][0]["Instances"][0]
        pub_ip = inst.get("PublicIpAddress")
        if pub_ip:
            print(f"  Target Public IP: {pub_ip}")
            state["public_ip"] = pub_ip
            break
        time.sleep(2)

    # 7. SAVE STATE FILE
    print("\n[7/7] Saving deployment state...")
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    print(f"Deployment state recorded in: {STATE_FILE}")

    print("\n" + "=" * 60)
    print("Cloud Shield AWS Infrastructure Deployed Successfully!")
    print(f"Target URL: http://{state.get('public_ip', 'PENDING')}/")
    print(f"S3 Logs:    s3://{bucket_name}/vpc-flow-logs/")
    print(f"VPC ID:     {vpc_id}")
    print("=" * 60)
    return state

if __name__ == "__main__":
    deploy_infrastructure()
