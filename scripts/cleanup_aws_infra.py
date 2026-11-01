import os
import sys
import json
import time
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config import get_aws_session, get_aws_identity, STATE_FILE, PROJECT_TAG, get_bucket_name

def cleanup_infrastructure():
    print("=" * 60)
    print("Cloud Shield: 1-Command AWS Infrastructure Teardown")
    print("=" * 60)

    identity = get_aws_identity()
    account_id = identity["account_id"]
    region = identity["region"]
    session = get_aws_session()

    ec2 = session.client("ec2", region_name=region)
    s3 = session.client("s3", region_name=region)
    iam = session.client("iam", region_name=region)

    state = {}
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
        except Exception:
            pass

    # 1. DELETE VPC FLOW LOGS
    flow_log_id = state.get("flow_log_id")
    print("\n[1/8] Removing VPC Flow Logs...")
    if flow_log_id and flow_log_id != "fl-unknown":
        try:
            ec2.delete_flow_logs(FlowLogIds=[flow_log_id])
            print(f"  Deleted Flow Log: {flow_log_id}")
        except ClientError as e:
            print(f"  Flow log notice: {e.response['Error']['Message']}")
    else:
        # Lookup by tag
        try:
            fls = ec2.describe_flow_logs(Filters=[{"Name": "tag:Project", "Values": [PROJECT_TAG]}])["FlowLogs"]
            fl_ids = [f["FlowLogId"] for f in fls]
            if fl_ids:
                ec2.delete_flow_logs(FlowLogIds=fl_ids)
                print(f"  Deleted Flow Logs by tag: {fl_ids}")
        except Exception as e:
            print(f"  Flow log lookup notice: {e}")

    # 2. TERMINATE EC2 INSTANCE
    instance_id = state.get("instance_id")
    print("\n[2/8] Terminating EC2 Target Instance...")
    if instance_id:
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
            print(f"  Sent termination request for {instance_id}. Waiting for termination...")
            waiter = ec2.get_waiter("instance_terminated")
            waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 5, "MaxAttempts": 30})
            print("  Instance terminated cleanly.")
        except ClientError as e:
            print(f"  EC2 notice: {e.response['Error']['Message']}")
    else:
        try:
            insts = ec2.describe_instances(Filters=[{"Name": "tag:Project", "Values": [PROJECT_TAG]}, {"Name": "instance-state-name", "Values": ["running", "pending", "stopped"]}])
            tagged_ids = []
            for res in insts.get("Reservations", []):
                for inst in res.get("Instances", []):
                    tagged_ids.append(inst["InstanceId"])
            if tagged_ids:
                ec2.terminate_instances(InstanceIds=tagged_ids)
                print(f"  Terminated instances by tag: {tagged_ids}. Waiting for termination...")
                waiter = ec2.get_waiter("instance_terminated")
                waiter.wait(InstanceIds=tagged_ids, WaiterConfig={"Delay": 5, "MaxAttempts": 30})
                print("  Tagged instances terminated cleanly.")
        except Exception as e:
            print(f"  EC2 tag lookup notice: {e}")

    # 3. EMPTY & DELETE S3 DATA LAKE BUCKET
    bucket_name = state.get("s3_bucket") or get_bucket_name(account_id, region)
    print(f"\n[3/8] Emptying and Deleting S3 Data Lake Bucket ({bucket_name})...")
    if bucket_name:
        try:
            # Delete all object versions & delete markers
            s3_resource = session.resource("s3", region_name=region)
            bucket = s3_resource.Bucket(bucket_name)
            bucket.object_versions.delete()
            bucket.objects.all().delete()
            s3.delete_bucket(Bucket=bucket_name)
            print(f"  Deleted bucket: {bucket_name}")
        except ClientError as e:
            print(f"  S3 notice: {e.response['Error']['Message']}")

    # 4. REMOVE IAM INSTANCE PROFILE & ROLE
    profile_name = state.get("instance_profile", "CloudShield-EC2-SSM-Profile")
    role_name = state.get("iam_role", "CloudShield-EC2-SSM-Role")
    print(f"\n[4/8] Removing IAM Instance Profile and Role...")
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
        print("  Detached role from instance profile.")
    except Exception:
        pass
    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
        print("  Deleted instance profile.")
    except Exception:
        pass
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
        iam.delete_role(RoleName=role_name)
        print("  Deleted IAM role.")
    except Exception:
        pass

    # 5. DELETE SECURITY GROUP
    sg_id = state.get("security_group_id")
    print("\n[5/8] Deleting Security Group...")
    if sg_id:
        for _ in range(10):
            try:
                ec2.delete_security_group(GroupId=sg_id)
                print(f"  Deleted Security Group: {sg_id}")
                break
            except ClientError as e:
                time.sleep(3)
    else:
        try:
            sgs = ec2.describe_security_groups(Filters=[{"Name": "tag:Project", "Values": [PROJECT_TAG]}])["SecurityGroups"]
            for sg in sgs:
                ec2.delete_security_group(GroupId=sg["GroupId"])
                print(f"  Deleted Security Group by tag: {sg['GroupId']}")
        except Exception:
            pass

    # 6. ROUTE TABLE & SUBNET
    rt_id = state.get("route_table_id")
    subnet_id = state.get("subnet_id")
    print("\n[6/8] Deleting Route Table and Subnet...")
    if rt_id:
        try:
            # Disassociate custom associations
            rt_desc = ec2.describe_route_tables(RouteTableIds=[rt_id])
            for assoc in rt_desc["RouteTables"][0].get("Associations", []):
                if not assoc.get("Main"):
                    ec2.disassociate_route_table(AssociationId=assoc["RouteTableAssociationId"])
            ec2.delete_route_table(RouteTableId=rt_id)
            print(f"  Deleted Route Table: {rt_id}")
        except Exception as e:
            print(f"  Route table notice: {e}")

    if subnet_id:
        for _ in range(8):
            try:
                ec2.delete_subnet(SubnetId=subnet_id)
                print(f"  Deleted Subnet: {subnet_id}")
                break
            except Exception:
                time.sleep(3)

    # 7. INTERNET GATEWAY & VPC
    igw_id = state.get("igw_id")
    vpc_id = state.get("vpc_id")
    print("\n[7/8] Detaching and Deleting Internet Gateway and VPC...")
    if not vpc_id:
        try:
            vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Project", "Values": [PROJECT_TAG]}])["Vpcs"]
            if vpcs:
                vpc_id = vpcs[0]["VpcId"]
        except Exception:
            pass

    if igw_id and vpc_id:
        try:
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
            print(f"  Deleted Internet Gateway: {igw_id}")
        except Exception as e:
            print(f"  IGW notice: {e}")

    if vpc_id:
        for _ in range(8):
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                print(f"  Deleted VPC: {vpc_id}")
                break
            except Exception:
                time.sleep(3)

    # 8. REMOVE STATE FILE
    print("\n[8/8] Cleaning local state file...")
    if STATE_FILE.exists():
        STATE_FILE.unlink()
        print(f"  Removed: {STATE_FILE}")

    print("\n" + "=" * 60)
    print("Cloud Shield AWS Teardown Completed Successfully!")
    print("=" * 60)

    return {
        "status": "SUCCESS",
        "account_id": account_id,
        "region": region,
        "ec2_instance": instance_id or "Terminated / Not Found",
        "s3_bucket": bucket_name or "Deleted / Not Found",
        "vpc_id": vpc_id or "Deleted / Not Found",
        "subnet_id": subnet_id or "Deleted / Not Found",
        "security_group_id": sg_id or "Deleted / Not Found",
        "flow_log_id": flow_log_id or "Deleted / Not Found",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

if __name__ == "__main__":
    cleanup_infrastructure()
