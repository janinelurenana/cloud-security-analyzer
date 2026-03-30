# Cloud Security Misconfiguration & Activity Analyzer

## Overview

This project simulates a simplified cloud security monitoring pipeline inspired by real-world AWS security tooling (e.g., CloudTrail + GuardDuty).

It ingests raw AWS-style logs and resource configurations, normalizes inconsistent data, applies deterministic detection rules, and produces structured security findings through both a JSON report and a local dashboard.

The system is intentionally designed with strict separation of concerns to reflect real-world pipeline architecture.

---

## System Architecture

```
raw_cloudtrail.json  ──┐
                       ├──▶  parser.py  ──▶  detect.py  ──▶  report.py  ──▶  report.json
raw_resources.json   ──┘                                              │
                                                                      ▼
                                                                 app.py (dashboard)
```

### Component Responsibilities

* **parser.py**
  Handles ingestion and normalization of raw AWS JSON. Converts nested, inconsistent data into structured CSV format.

* **detect.py**
  Pure detection engine. Applies rule-based logic and returns findings. No I/O operations.

* **report.py**
  Presentation layer. Formats findings into console output and persists them to JSON.

* **app.py**
  Read-only dashboard. Visualizes findings from `report.json` using Streamlit.
  Dashboard: https://cloud-security-analyzer-tctxnssxbmabgj4afsfabw.streamlit.app/ 

---

## Execution Pipeline

### Phase 1 — Data Ingestion & Normalization

* Parse raw CloudTrail logs and resource configurations
* Flatten nested JSON structures
* Handle null values, missing fields, and inconsistent schemas
* Output normalized datasets:

  * `parsed_access_logs.csv`
  * `parsed_resources.csv`

---

### Phase 2 — Detection Engine

* Apply deterministic rules across normalized datasets
* Evaluate both:

  * Resource misconfigurations
  * Suspicious activity patterns
* Return structured findings list

---

### Phase 3 — Reporting

* Format findings into readable console output
* Generate `output/report.json` for downstream use

---

### Phase 4 — Visualization

* Streamlit dashboard reads from `report.json`
* Displays:

  * Severity distribution
  * Rule breakdown
  * Filterable findings table

---

## Project Structure

```
cloud-security-analyzer/
│
├── data/
│   ├── raw_cloudtrail.json
│   ├── raw_resources.json
│   ├── parsed_access_logs.csv
│   └── parsed_resources.csv
│
├── analysis/
│   ├── parser.py
│   ├── detect.py
│   ├── report.py
│   └── run.py
│
├── output/
│   └── report.json
│
├── dashboard/
│   ├── summary_cards.png
│   ├── charts_breakdown.png
│   └── findings_high_only.png
│
├── app.py
├── analysis.md
└── README.md
```

---

## Setup

```bash
pip install pandas streamlit plotly
```

---

## Running the System

### Step 1 — Execute Full Pipeline

```bash
cd analysis
python run.py
```

This performs:

1. JSON → CSV normalization
2. Rule-based detection
3. Report generation (`output/report.json`)

---

### Step 2 — Launch Dashboard

```bash
streamlit run app.py
```

Access via:

```
http://localhost:8501
```

---

## Detection Logic

The engine evaluates two categories of risk:

---

### 1. Resource Misconfigurations

* Public S3 buckets
* Public EC2 instances with open SSH (port 22)
* Over-privileged IAM roles (admin-level access)
* Unencrypted storage resources

---

### 2. Suspicious Activity Patterns

* Brute force login attempts (time-window based)
* Multi-IP login anomalies
* Excessive admin activity within a short period

---

### Rule Summary

| # | Rule                    | Severity |
| - | ----------------------- | -------- |
| 1 | Public Storage          | HIGH     |
| 2 | Open SSH Port           | HIGH     |
| 3 | Over-Privileged Role    | MEDIUM   |
| 4 | No Encryption           | MEDIUM   |
| 5 | Brute Force Attempt     | HIGH     |
| 6 | Suspicious IP Behaviour | HIGH     |
| 7 | Admin Overuse           | MEDIUM   |

Thresholds for behavioral rules are configurable in `detect.py`.

---

## Design Decisions

### Why CSV as Intermediate Format?

CSV provides a flat, structured representation that simplifies rule evaluation and debugging compared to deeply nested JSON.

---

### Why Rule-Based Detection?

The system uses deterministic rules to ensure:

* Full transparency (every finding is explainable)
* Reproducibility of results
* Simplicity for controlled simulations

---

### Why Decoupled Architecture?

Separating parser, detection, and reporting allows:

* Independent testing of components
* Easy replacement of input formats
* Clear system boundaries

---

### Why Skip Service-to-Service Logs?

Service-generated events introduce noise and reduce signal quality for behavioral analysis. The system focuses on user-driven activity.

---

## Sample Output

```
[detect] 18 finding(s) returned.

SUMMARY
────────────────────────────
Total findings : 18
HIGH           : 8
MEDIUM         : 10
LOW            : 0
```

---

## Limitations & Future Improvements

### Current Limitations

* Single-port representation per resource (simplified model)
* Simulated AWS data (no live integration)
* No anomaly scoring or behavioral baselining

---

### Planned Improvements

* Support multi-port resource modeling
* Integrate real AWS log sources
* Introduce risk scoring system
* Add time-series behavioral analysis
* Expand rule set for broader coverage

---

## Key Takeaway

This project demonstrates how a cloud security monitoring pipeline can be built using:

* Structured data normalization
* Deterministic rule-based detection
* Layered system design

It prioritizes clarity, modularity, and explainability over complexity.

