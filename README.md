# Cloud Security Misconfiguration & Activity Analyzer (Simulated)

A Python-based tool that detects insecure cloud configurations and suspicious activity using simulated cloud data. Built in two phases: local CSV analysis first, then real AWS data.

---

## Project Structure

```
cloud-security-project/
│
├── data/
│   ├── resources.csv        # Simulated cloud resource configs (EC2, S3, IAM)
│   └── access_logs.csv      # Simulated user activity logs
│
├── analysis/
│   ├── detect.py            # Detection rules — returns findings as a list
│   └── report.py            # Formats findings into console output + JSON file
│
├── output/
│   └── report.json          # Auto-generated on each run
│
├── app.py                   # Streamlit dashboard — reads from output/report.json
└── README.md
```

---

## How It Works

```
resources.csv   ──┐
                  ├──▶  detect.py  ──▶  report.py  ──▶  console + report.json  ──▶  app.py (dashboard)
access_logs.csv ──┘
```

`detect.py`, `report.py`, and `app.py` are intentionally separated:
- **`detect.py`** is pure logic. It loads the data, runs every rule, and returns a list of findings. No printing, no file writing.
- **`report.py`** is pure presentation. It takes that findings list and handles all output formatting — console and JSON.
- **`app.py`** is the dashboard. It reads `output/report.json` and renders it visually. It never calls `detect.py` directly.

This separation means the detection engine can be reused — Phase 2 only changes the input layer (AWS JSON → normalized CSV format), not the rules themselves. It also means the dashboard can be refreshed instantly by re-running `report.py`, with no changes to `app.py`.

---

## Setup

```bash
pip install pandas streamlit plotly
```

---

## Running the Analyzer

**Step 1 — Generate the report.** From inside the `analysis/` directory:

```bash
python report.py
```

This will:
1. Load both CSVs from `../data/`
2. Run all detection rules
3. Print a formatted report to the console
4. Save a structured JSON report to `../output/report.json`

**Step 2 — Launch the dashboard.** From the project root:

```bash
streamlit run app.py
```

Opens at `http://localhost:8501`. The dashboard reads `output/report.json` — re-run `report.py` and refresh the browser to pick up any changes.

**Repeat workflow:**
```bash
python analysis/report.py   # re-run analysis
streamlit run app.py        # or just refresh the browser if already running
```

---

## Detection Rules

The engine applies 7 rules across two datasets.

### Resource Rules (resources.csv)

| # | Rule | Severity | Condition |
|---|------|----------|-----------|
| 1 | Public Storage | HIGH | `resource_type = S3` AND `public_access = true` |
| 2 | Open SSH Port | HIGH | `resource_type = EC2` AND `port_open = 22` AND `public_access = true` |
| 3 | Over-Privileged Role | MEDIUM | `iam_role = 'admin'` |
| 4 | No Encryption | MEDIUM | `encryption = false` |

### Log Rules (access_logs.csv)

| # | Rule | Severity | Condition |
|---|------|----------|-----------|
| 5 | Brute Force Attempt | HIGH | ≥ 5 failed logins from same user within 5 minutes |
| 6 | Suspicious IP Behaviour | HIGH | Same user logs in from ≥ 2 distinct IPs within 30 minutes |
| 7 | Admin Overuse | MEDIUM | Admin account performs ≥ 5 actions in a single day |

Thresholds for rules 5, 6, and 7 are defined as constants at the top of `detect.py` and can be adjusted without touching rule logic.

---

## Rule Explanations

### Rule 1 — Public Storage
**Why it's dangerous:** Anyone on the internet can read, download, or overwrite the bucket's contents — including sensitive files, credentials, or backups.

**Real-world fix:** Set bucket ACL to private, disable the "Block Public Access" override, and apply a bucket policy that restricts access to specific IAM principals.

---

### Rule 2 — Open SSH Port
**Why it's dangerous:** Exposing port 22 to `0.0.0.0/0` lets anyone on the internet attempt to authenticate. Automated bots continuously scan for open SSH ports and launch credential attacks within minutes of a new instance going live.

**Real-world fix:** Restrict SSH access to known IP ranges in the Security Group. Use AWS Systems Manager Session Manager for shell access instead of opening port 22 at all.

---

### Rule 3 — Over-Privileged Role
**Why it's dangerous:** An admin role can create users, delete resources, exfiltrate data, and modify billing — all from a single compromised key or credential.

**Real-world fix:** Apply least-privilege IAM policies. Grant only the specific actions a resource actually needs (e.g. `s3:GetObject`). Use IAM Access Analyzer to audit existing permissions.

---

### Rule 4 — No Encryption
**Why it's dangerous:** If the underlying storage volume or bucket is accessed without going through the application, the data is readable in plaintext.

**Real-world fix:** Enable S3 server-side encryption (SSE-S3 or SSE-KMS). For EC2, enable EBS volume encryption at instance creation. Enforce encryption via IAM policy conditions.

---

### Rule 5 — Brute Force Attempt
**Why it's dangerous:** Repeated login failures indicate an automated attempt to guess credentials. A successful guess gives an attacker full access to that user's permissions.

**Real-world fix:** Enable MFA on all IAM users. Set an account lockout policy. Use CloudWatch alarms on failed login metrics. AWS GuardDuty also detects this pattern automatically.

---

### Rule 6 — Suspicious IP Behaviour
**Why it's dangerous:** A single user authenticating from multiple geographically distinct IPs in a short window likely indicates stolen credentials being used from a different location.

**Real-world fix:** Enforce MFA. Use IAM condition keys (`aws:SourceIp`) to restrict logins to trusted IP ranges. Enable GuardDuty — it flags impossible travel scenarios automatically.

---

### Rule 7 — Admin Overuse
**Why it's dangerous:** Frequent high-privilege actions increase the blast radius of a compromise and may indicate a threat actor performing reconnaissance or staging destructive changes.

**Real-world fix:** Require MFA for all admin actions. Use CloudTrail to alert on sensitive API calls. Break the admin role into narrower roles (e.g. `IAMAdmin`, `NetworkAdmin`, `BillingAdmin`).

---

## Sample Output

**Console (report.py):**
```
══════════════════════════════════════════════════════════════════════
  CLOUD SECURITY MISCONFIGURATION & ACTIVITY ANALYZER
  Generated: 2024-01-15 10:00:00 UTC
══════════════════════════════════════════════════════════════════════

  SUMMARY
  ──────────────────────────────────────────────────────────────────
  Total findings : 18
  🔴 HIGH        : 8
  🟡 MEDIUM      : 10
  🔵 LOW         : 0

  FINDINGS
  ──────────────────────────────────────────────────────────────────

  [1] [🔴 HIGH  ] Public Storage
      Resource : R102
      Reason   : S3 bucket R102 has public access enabled. Anyone on the internet can read or write its contents.
  ...
```

**Dashboard (app.py):** Run `streamlit run app.py` from the project root and open `http://localhost:8501`. Displays the same findings with summary metric cards, a severity bar chart, a per-rule bar chart, and a filterable findings table — all reading from `output/report.json`.

---

## Phase 2 — AWS Integration (Planned)

Phase 2 adds a parser layer that normalizes real AWS data into the same CSV format this engine already reads. The detection rules do not change.

**CloudTrail logs (JSON) → normalized `access_logs` format:**
```json
{ "eventName": "ConsoleLogin", "sourceIPAddress": "1.2.3.4" }
```
↓
```
user | ip_address | action | status
```

**AWS resource configs (IAM, S3, EC2) → normalized `resources` format**

Once the parser layer is built, running `report.py` against live AWS data works identically to Phase 1.

---

## Limitations (Phase 1)

- `port_open` stores a single integer per resource row. A resource with multiple open ports would require multiple rows or a comma-separated value. This is a known simplification for Phase 1.
- No real network traffic or live AWS data — all findings are based on simulated CSVs.
- No machine learning or behavioral baselining. Rules are deterministic and threshold-based by design.
