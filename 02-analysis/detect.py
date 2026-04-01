"""
detect.py
---------
Detection engine for cloud security misconfigurations and suspicious activity.
Reads parsed_resources.csv and parsed_acxtcess_logs.csv, applies rules, returns a list of findings.

Each finding is a dict:
{
    "severity":    "HIGH" | "MEDIUM" | "LOW",
    "rule":        str,       # short rule name
    "resource_id": str,       # resource or user identifier
    "reason":      str,       # human-readable explanation
}

Usage:
    from detect import run_all_rules
    findings = run_all_rules("01-data/parsed_resources.csv", "01-data/parsed_access_logs.csv")
"""

import pandas as pd
from datetime import timedelta


# ---------------------------------------------------------------------------
# Thresholds (tweak here without digging into rule logic)
# ---------------------------------------------------------------------------
BRUTE_FORCE_THRESHOLD   = 5        # failed logins to trigger Rule 5
BRUTE_FORCE_WINDOW_MIN  = 5        # rolling time window in minutes
MULTI_IP_THRESHOLD      = 2        # distinct IPs to trigger Rule 6
MULTI_IP_WINDOW_MIN     = 30       # rolling time window in minutes
ADMIN_ACTION_THRESHOLD  = 5        # admin actions to trigger Rule 7


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

# CSVs store everything as strings, so "True" and "False" need to be explicitly mapped back to Python booleans
def load_resources(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["public_access"] = df["public_access"].astype(str).str.lower().map(
        {"true": True, "false": False}
    )
    df["encryption"] = df["encryption"].astype(str).str.lower().map(
        {"true": True, "false": False}
    )
    if "monitoring_enabled" in df.columns:
        df["monitoring_enabled"] = df["monitoring_enabled"].astype(str).str.lower().map(
            {"true": True, "false": False}
        )
    else:
        df["monitoring_enabled"] = None
    return df

# parses the timestamp column into real datetime objects
def load_logs(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


# ---------------------------------------------------------------------------
# Rules — Resources
# ---------------------------------------------------------------------------

def rule_public_storage(resources: pd.DataFrame) -> list[dict]:
    """Rule 1: Public S3 bucket — anyone on the internet can read/write data."""
    findings = []
    flagged = resources[
        (resources["resource_type"] == "S3") &
        (resources["public_access"] == True)
    ]
    for _, row in flagged.iterrows():
        findings.append({
            "severity":    "HIGH",
            "rule":        "Public Storage",
            "resource_id": row["resource_id"],
            "reason":      (
                f"S3 bucket {row['resource_id']} has public access enabled. "
                "Anyone on the internet can read or write its contents."
            ),
        })
    return findings


def rule_open_ssh(resources: pd.DataFrame) -> list[dict]:
    """Rule 2: EC2 with port 22 open and publicly accessible."""
    findings = []
    flagged = resources[
        (resources["resource_type"] == "EC2") &
        (resources["port_open"] == 22) &
        (resources["public_access"] == True)
    ]
    for _, row in flagged.iterrows():
        findings.append({
            "severity":    "HIGH",
            "rule":        "Open SSH Port",
            "resource_id": row["resource_id"],
            "reason":      (
                f"EC2 instance {row['resource_id']} has port 22 (SSH) open to the public. "
                "This allows brute-force and credential-stuffing attacks directly on the server."
            ),
        })
    return findings


def rule_overprivileged_role(resources: pd.DataFrame) -> list[dict]:
    """Rule 3: Any resource assigned an admin IAM role."""
    findings = []
    flagged = resources[resources["iam_role"] == "admin"]
    for _, row in flagged.iterrows():
        findings.append({
            "severity":    "MEDIUM",
            "rule":        "Over-Privileged Role",
            "resource_id": row["resource_id"],
            "reason":      (
                f"Resource {row['resource_id']} ({row['resource_type']}) is assigned the 'admin' role. "
                "Violates least-privilege principle — use scoped roles instead."
            ),
        })
    return findings


def rule_no_encryption(resources: pd.DataFrame) -> list[dict]:
    """Rule 4: Resource with encryption disabled."""
    findings = []
    flagged = resources[resources["encryption"] == False]
    for _, row in flagged.iterrows():
        findings.append({
            "severity":    "MEDIUM",
            "rule":        "No Encryption",
            "resource_id": row["resource_id"],
            "reason":      (
                f"Resource {row['resource_id']} ({row['resource_type']}) has encryption disabled. "
                "Data at rest is exposed if storage is compromised."
            ),
        })
    return findings

def rule_monitoring_disabled(resources: pd.DataFrame) -> list[dict]:
    """
    Rule 8: EC2 instance monitoring disabled.
    CloudWatch detailed monitoring being off means reduced visibility into
    CPU, network, and disk metrics — blind spots during an incident.
    Severity: LOW — not directly exploitable, but a hygiene issue that
    hampers detection and incident response.
    """
    findings = []
    flagged = resources[
        (resources["resource_type"] == "EC2") &
        (resources["monitoring_enabled"] == False)
    ]
    for _, row in flagged.iterrows():
        findings.append({
            "severity":    "LOW",
            "rule":        "Monitoring Disabled",
            "resource_id": row["resource_id"],
            "reason":      (
                f"EC2 instance {row['resource_id']} has CloudWatch detailed monitoring disabled. "
                "Reduced metric visibility hampers incident detection and response."
            ),
        })
    return findings
    
# ---------------------------------------------------------------------------
# Rules — Access Logs
# ---------------------------------------------------------------------------

def rule_brute_force(logs: pd.DataFrame) -> list[dict]:
    """
    Rule 5: Brute-force attempt.
    Flags any user with >= BRUTE_FORCE_THRESHOLD failed logins
    within a BRUTE_FORCE_WINDOW_MIN-minute rolling window.
    """
    findings = []
    failed = logs[logs["status"] == "fail"].copy()  # creates a df of all failed attempts
    failed = failed.sort_values("timestamp")
    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)

    flagged_users = set()
    for user, group in failed.groupby("user"):
        times = group["timestamp"].tolist()
        # Sliding window count
        for i, start in enumerate(times):
            count = sum(1 for time in times[i:] if time - start <= window)
            if count >= BRUTE_FORCE_THRESHOLD:
                flagged_users.add(user)
                break

    for user in flagged_users:
        fail_count = len(failed[failed["user"] == user])
        findings.append({
            "severity":    "HIGH",
            "rule":        "Brute Force Attempt",
            "resource_id": f"user:{user}",
            "reason":      (
                f"User '{user}' had {fail_count} failed login attempts, "
                f"with {BRUTE_FORCE_THRESHOLD}+ failures within a "
                f"{BRUTE_FORCE_WINDOW_MIN}-minute window. Possible brute-force attack."
            ),
        })
    return findings


def rule_suspicious_ip(logs: pd.DataFrame) -> list[dict]:
    """
    Rule 6: Suspicious IP behaviour.
    Flags any user who logs in from >= MULTI_IP_THRESHOLD distinct IPs
    within MULTI_IP_WINDOW_MIN minutes.
    """
    findings = []
    logins = logs[logs["action"] == "ConsoleLogin"].copy()
    logins = logins.sort_values("timestamp")
    window = timedelta(minutes=MULTI_IP_WINDOW_MIN)

    for user, group in logins.groupby("user"):
        times = group["timestamp"].tolist()
        ips   = group["ip_address"].tolist()
        for i, start in enumerate(times):
            window_entries = [
                (time, ip) for time, ip in zip(times[i:], ips[i:])
                if time - start <= window
            ]
            distinct_ips = set(ip for _, ip in window_entries)
            if len(distinct_ips) >= MULTI_IP_THRESHOLD:
                findings.append({
                    "severity":    "HIGH",
                    "rule":        "Suspicious IP Behaviour",
                    "resource_id": f"user:{user}",
                    "reason":      (
                        f"User '{user}' logged in from {len(distinct_ips)} distinct IPs "
                        f"within {MULTI_IP_WINDOW_MIN} minutes: "
                        f"{', '.join(sorted(distinct_ips))}. "
                        "Possible credential compromise or account sharing."
                    ),
                })
                break   # one finding per user is enough
    return findings


def rule_admin_overuse(logs: pd.DataFrame) -> list[dict]:
    """
    Rule 7: Admin overuse.
    Flags IAM users with 'admin' in their username performing
    >= ADMIN_ACTION_THRESHOLD actions in a single day.
    (Bonus rule — kept simple and explainable.)
    """
    findings = []
    admin_logs = logs[logs["user"].str.lower() == "admin"].copy()
    admin_logs["date"] = admin_logs["timestamp"].dt.date

    for date, group in admin_logs.groupby("date"):
        if len(group) >= ADMIN_ACTION_THRESHOLD:
            findings.append({
                "severity":    "MEDIUM",
                "rule":        "Admin Overuse",
                "resource_id": "user:admin",
                "reason":      (
                    f"Admin account performed {len(group)} actsion on {date}. "
                    f"High admin activity may indicate privilege misuse or a compromised account."
                ),
            })
    return findings



# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_all_rules(resources_path: str, logs_path: str) -> list[dict]:
    """
    Load both datasets, run every rule, and return a combined findings list.
    """
    resources = load_resources(resources_path)
    logs      = load_logs(logs_path)

    findings = []
    findings += rule_public_storage(resources)
    findings += rule_open_ssh(resources)
    findings += rule_overprivileged_role(resources)
    findings += rule_no_encryption(resources)
    findings += rule_brute_force(logs)
    findings += rule_suspicious_ip(logs)
    findings += rule_admin_overuse(logs)
    findings += rule_monitoring_disabled(resources)

    return findings


if __name__ == "__main__":
    # Quick smoke-test when run directly
    findings = run_all_rules("01-data/parsed_resources.csv", "01-data/parsed_access_logs.csv")
    for f in findings:
        print(f"[{f['severity']}] {f['rule']} — {f['resource_id']}")
    print(f"\nTotal findings: {len(findings)}")
