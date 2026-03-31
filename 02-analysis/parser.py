"""
parser.py
---------

Reads raw, messy AWS-like JSON files and normalizes them into the same
CSV format that detect.py already expects. 

Input:
    data/raw_cloudtrail.json    — CloudTrail-format activity logs
    data/raw_resources.json     — EC2 / S3 / IAM describe output

Output:
    data/parsed_access_logs.csv
    data/parsed_resources.csv

Usage (standalone):
    python parser.py

Usage (imported):
    from parser import parse_all
    parse_all(
        cloudtrail_path="data/raw_cloudtrail.json",
        resources_path="data/raw_resources.json",
        logs_out="data/parsed_access_logs.csv",
        resources_out="data/parsed_resources.csv",
    )
"""

import json
import csv
import os
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_get(obj, *keys, default=None):
    """Safely traverse nested dicts/keys. Returns default on any miss or None."""
    for key in keys:
        if obj is None or not isinstance(obj, dict):
            return default
        obj = obj.get(key)
    return obj if obj is not None else default


def _normalize_status(response_elements: dict | None, error_code: str | None) -> str:
    """
    Derive a clean 'success' / 'fail' status from CloudTrail fields.
    errorCode present → fail
    responseElements ConsoleLogin = Failure → fail
    Everything else → success
    """
    if error_code:
        return "fail"
    login_result = _safe_get(response_elements, "ConsoleLogin", default="")
    if str(login_result).lower() == "failure":
        return "fail"
    return "success"


def _normalize_timestamp(raw: str | None) -> str:
    """Parse ISO 8601 CloudTrail timestamp → 'YYYY-MM-DD HH:MM:SS'."""
    if not raw:
        return ""
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw  # return as-is if unparseable


def _extract_resource_id(record: dict) -> str:
    """
    Best-effort resource_id extraction from a CloudTrail record.
    Tries requestParameters for common field names, falls back to eventSource prefix.
    """
    params = record.get("requestParameters") or {}
    for field in ("bucketName", "instanceId", "roleName", "userName", "instancesSet"):
        val = params.get(field)
        if val:
            if field == "instancesSet":
                # nested: { "items": [{ "instanceId": "..." }] }
                items = val.get("items", [])
                if items:
                    return items[0].get("instanceId", "unknown")
            return str(val)
    return "unknown"


# ---------------------------------------------------------------------------
# CloudTrail → parsed_access_logs
# ---------------------------------------------------------------------------

LOGS_FIELDS = ["timestamp", "user", "ip_address", "action", "resource_id", "status"]


def parse_cloudtrail(path: str) -> list[dict]:
    """
    Parse a CloudTrail JSON file into normalized access_log rows.
    Skips records with no usable user or IP.
    Logs a warning for each skipped record.
    """
    with open(path) as f:
        data = json.load(f)

    records = data.get("Records", [])
    rows = []
    skipped = 0

    for record in records:
        user = _safe_get(record, "userIdentity", "userName")
        ip   = record.get("sourceIPAddress")

        # Skip service-to-service calls (no human user) and records missing IP
        if not user or not ip:
            skipped += 1
            continue

        row = {
            "timestamp":   _normalize_timestamp(record.get("eventTime")),
            "user":        user.strip().lower(),
            "ip_address":  ip.strip(),
            "action":      record.get("eventName", "unknown"),
            "resource_id": _extract_resource_id(record),
            "status":      _normalize_status(
                               record.get("responseElements"),
                               record.get("errorCode"),
                           ),
        }
        rows.append(row)

    if skipped:
        print(f"  [parser] Skipped {skipped} CloudTrail record(s) — missing user or IP.")

    return rows


# ---------------------------------------------------------------------------
# Resource JSON → parsed_resources
# ---------------------------------------------------------------------------

RESOURCES_FIELDS = ["resource_id", "resource_type", "public_access", "port_open", "iam_role", "encryption", "monitoring_enabled"]

# IAM policy ARNs that map to admin-level access
ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}

# IAM policy ARNs that map to read-only
READONLY_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/ReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess",
}


def _classify_iam_role(attached_policies: list | None) -> str:
    """Map AWS policy ARNs to simplified role labels matching Phase 1 CSV."""
    if not attached_policies:
        return "user"
    arns = {p.get("PolicyArn", "") for p in attached_policies}
    if arns & ADMIN_POLICY_ARNS:
        return "admin"
    if arns & READONLY_POLICY_ARNS:
        return "read-only"
    return "user"


def _parse_s3_buckets(buckets: list) -> list[dict]:
    rows = []
    for bucket in buckets:
        pac = bucket.get("PublicAccessBlockConfiguration") or {}
        is_public = not (
            pac.get("BlockPublicAcls", False) and
            pac.get("RestrictPublicBuckets", False)
        )
        sse = bucket.get("ServerSideEncryptionConfiguration")
        encrypted = sse is not None and bool(_safe_get(sse, "Rules"))

        rows.append({
            "resource_id":       bucket.get("BucketId", "unknown"),
            "resource_type":     "S3",
            "public_access":     is_public,
            "port_open":         None,
            "iam_role":          "read-only",   # buckets don't have instance profiles
            "encryption":        encrypted,
            "monitoring_enabled": None,
        })
    return rows


def _parse_ec2_instances(instances: list) -> list[dict]:
    rows = []
    for inst in instances:
        # Public access = has a public IP
        is_public = bool(inst.get("PublicIpAddress"))

        # Find the lowest open port from security group ingress rules
        port_open = None
        for sg in (inst.get("SecurityGroups") or []):
            for perm in (sg.get("IpPermissions") or []):
                port = perm.get("FromPort")
                if port is not None:
                    if port_open is None or port < port_open:
                        port_open = port

        # Encryption: check first EBS volume
        bdm = inst.get("BlockDeviceMappings") or []
        encrypted = False
        if bdm:
            encrypted = bool(_safe_get(bdm[0], "Ebs", "Encrypted"))

        # IAM role from instance profile ARN name
        profile_arn = _safe_get(inst, "IamInstanceProfile", "Arn", default="")
        if "admin" in profile_arn.lower():
            iam_role = "admin"
        elif "read" in profile_arn.lower():
            iam_role = "read-only"
        else:
            iam_role = "user"

        monitoring = _safe_get(inst, "Monitoring", "State", default="")
        monitoring_enabled = str(monitoring).lower() == "enabled"

        rows.append({
            "resource_id":       inst.get("InstanceId", "unknown"),
            "resource_type":     "EC2",
            "public_access":     is_public,
            "port_open":         port_open,
            "iam_role":          iam_role,
            "encryption":        encrypted,
            "monitoring_enabled": monitoring_enabled,
        })
    return rows


def _parse_iam_roles(roles: list) -> list[dict]:
    rows = []
    for role in roles:
        policies = role.get("AttachedPolicies") or role.get("InlinePolicies") or []
        rows.append({
            "resource_id":       role.get("RoleId", "unknown"),
            "resource_type":     "IAM",
            "public_access":     False,
            "port_open":         None,
            "iam_role":          _classify_iam_role(policies),
            "encryption":        True,   # IAM roles don't store data — mark as N/A (true)
            "monitoring_enabled": None,
        })
    return rows


def parse_resources(path: str) -> list[dict]:
    """Parse raw AWS resource JSON into normalized resource rows."""
    with open(path) as f:
        data = json.load(f)

    rows = []
    rows += _parse_s3_buckets(data.get("S3Buckets", []))
    rows += _parse_ec2_instances(data.get("EC2Instances", []))
    rows += _parse_iam_roles(data.get("IAMRoles", []))
    return rows


# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------

def _write_csv(rows: list[dict], fields: list[str], path: str) -> None:
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def parse_all(
    cloudtrail_path: str = "data/raw_cloudtrail.json",
    resources_path:  str = "data/raw_resources.json",
    logs_out:        str = "data/parsed_access_logs.csv",
    resources_out:   str = "data/parsed_resources.csv",
) -> tuple[str, str]:
    """
    Parse both raw JSON files and write normalized CSVs.
    Returns (logs_out, resources_out) paths.
    """
    print(f"  [parser] Parsing CloudTrail logs from {cloudtrail_path} ...")
    log_rows = parse_cloudtrail(cloudtrail_path)
    _write_csv(log_rows, LOGS_FIELDS, logs_out)
    print(f"  [parser] Written {len(log_rows)} log rows → {logs_out}")

    print(f"  [parser] Parsing resource configs from {resources_path} ...")
    resource_rows = parse_resources(resources_path)
    _write_csv(resource_rows, RESOURCES_FIELDS, resources_out)
    print(f"  [parser] Written {len(resource_rows)} resource rows → {resources_out}")

    return logs_out, resources_out


if __name__ == "__main__":
    parse_all()
