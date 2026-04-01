"""
report.py
---------
Takes a findings list from detect.py and produces two outputs:
  1. A formatted console report (stdout)
  2. A structured JSON file saved to output/report.json

Usage (standalone):
    python report.py

Usage (imported):
    from report import generate_report
    generate_report(findings, json_output_path="03-output/report.json")
"""

import json
import os
from datetime import datetime, timezone
from detect import run_all_rules


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

SEVERITY_LABEL = {
    "HIGH":   "🔴 HIGH  ",
    "MEDIUM": "🟡 MEDIUM",
    "LOW":    "🔵 LOW   ",
}

# Real-world explanations
RULE_EXPLANATIONS = {
    "Public Storage": {
        "why_dangerous": "Anyone on the internet can read, download, or overwrite the bucket's contents — including sensitive files, credentials, or backups.",
        "real_world_fix": "Set bucket ACL to private, disable 'Block Public Access' override, and apply a bucket policy that restricts access to specific IAM principals.",
    },
    "Open SSH Port": {
        "why_dangerous": "Exposing port 22 to 0.0.0.0/0 lets anyone on the internet attempt to authenticate. Automated bots continuously scan for open SSH ports and launch credential attacks.",
        "real_world_fix": "Restrict SSH access to known IP ranges in the Security Group. Use AWS Systems Manager Session Manager for shell access instead of opening port 22 at all.",
    },
    "Over-Privileged Role": {
        "why_dangerous": "An admin role can create users, delete resources, exfiltrate data, and modify billing — all from one compromised key or credential.",
        "real_world_fix": "Apply least-privilege IAM policies. Grant only the specific actions (e.g. s3:GetObject) a resource actually needs. Use IAM Access Analyzer to audit permissions.",
    },
    "No Encryption": {
        "why_dangerous": "If the underlying storage volume or bucket is accessed without going through the application, the data is readable in plaintext.",
        "real_world_fix": "Enable S3 server-side encryption (SSE-S3 or SSE-KMS). For EC2, enable EBS volume encryption at creation. Enforce encryption via IAM policy conditions.",
    },
    "Brute Force Attempt": {
        "why_dangerous": "Repeated login failures indicate an automated attempt to guess credentials. A successful guess gives an attacker full access to that user's permissions.",
        "real_world_fix": "Enable MFA on all IAM users. Set an account lockout policy. Use CloudWatch alarms on failed login metrics. Consider AWS WAF or GuardDuty for automated blocking.",
    },
    "Suspicious IP Behaviour": {
        "why_dangerous": "A single user authenticating from multiple geographically distinct IPs in a short window likely indicates stolen credentials being used from a different location.",
        "real_world_fix": "Enforce MFA. Use AWS IAM condition keys (aws:SourceIp) to restrict logins to trusted IP ranges. Enable GuardDuty — it detects impossible travel automatically.",
    },
    "Admin Overuse": {
        "why_dangerous": "Frequent high-privilege actions increase the blast radius of a compromise and may indicate a threat actor performing reconnaissance or staging changes.",
        "real_world_fix": "Require MFA for all admin actions. Use AWS CloudTrail to alert on sensitive API calls. Consider breaking the admin role into narrower roles (IAMAdmin, NetworkAdmin, etc.).",
    },
}


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _separator(char: str = "─", width: int = 70) -> str:
    return char * width


def _sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))


def _count_by_severity(findings: list[dict]) -> dict:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Console report
# ---------------------------------------------------------------------------

def print_report(findings: list[dict]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sorted_findings = _sort_findings(findings)
    counts = _count_by_severity(findings)

    print()
    print(_separator("═"))
    print("  CLOUD SECURITY MISCONFIGURATION & ACTIVITY ANALYZER")
    print(f"  Generated: {now}")
    print(_separator("═"))

    # Summary
    print()
    print("  SUMMARY")
    print(_separator())
    print(f"  Total findings : {len(findings)}")
    print(f"  🔴 HIGH        : {counts['HIGH']}")
    print(f"  🟡 MEDIUM      : {counts['MEDIUM']}")
    print(f"  🔵 LOW         : {counts.get('LOW', 0)}")
    print()

    if not findings:
        print("  ✅ No issues detected.")
        print()
        print(_separator("═"))
        return

    # Findings
    print("  FINDINGS")
    print(_separator())

    for i, finding in enumerate(sorted_findings, start=1):
        label       = SEVERITY_LABEL.get(finding["severity"], finding["severity"])
        rule        = finding["rule"]
        resource    = finding["resource_id"]
        reason      = finding["reason"]
        explanation = RULE_EXPLANATIONS.get(rule, {})

        print()
        print(f"  [{i}] [{label}] {rule}")
        print(f"      Resource : {resource}")
        print(f"      Reason   : {reason}")

        if explanation:
            print(f"      Why dangerous : {explanation['why_dangerous']}")
            print(f"      Real-world fix: {explanation['real_world_fix']}")

        print(_separator("·"))

    print()
    print(_separator("═"))
    print()


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def write_json_report(findings: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)

    now = datetime.now(timezone.utc).isoformat()
    counts = _count_by_severity(findings)

    report = {
        "generated_at": now,
        "summary": {
            "total":  len(findings),
            "HIGH":   counts["HIGH"],
            "MEDIUM": counts["MEDIUM"],
            "LOW":    counts.get("LOW", 0),
        },
        "findings": _sort_findings(findings),
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"  ✅ JSON report saved → {path}")
    print()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_report(
    findings: list[dict],
    json_output_path: str = "03-output/report.json",
) -> None:
    """Print console report and write JSON file."""
    print_report(findings)
    write_json_report(findings, json_output_path)


if __name__ == "__main__":
    findings = run_all_rules("01-data/parsed_resources.csv", "01-data/parsed_access_logs.csv")
    generate_report(findings, json_output_path="03-output/report.json")
