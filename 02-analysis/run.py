"""
run_phase2.py
-------------
Phase 2 entry point.

Pipeline:
    raw_cloudtrail.json  ──┐
                           ├──▶  parser.py  ──▶  parsed CSVs  ──▶  detect.py  ──▶  report.py
    raw_resources.json   ──┘

detect.py and report.py are identical to Phase 1 — only the input layer changes.

Run from inside the analysis/ directory:
    python run_phase2.py
"""

import sys
import os

# Allow imports from the analysis/ directory
sys.path.insert(0, os.path.dirname(__file__))

from parser import parse_all
from detect import run_all_rules
from report import generate_report

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

CLOUDTRAIL_JSON  = "../data/raw_cloudtrail.json"
RESOURCES_JSON   = "../data/raw_resources.json"
PARSED_LOGS      = "../data/parsed_access_logs.csv"
PARSED_RESOURCES = "../data/parsed_resources.csv"
JSON_REPORT_OUT  = "../output/report.json"


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def main():
    print()
    print("=" * 60)
    print("  PHASE 2 — AWS JSON → Parser → Detection → Report")
    print("=" * 60)
    print()

    # Step 1: Parse raw JSON → normalized CSVs
    print("[ STEP 1 ] Parsing raw AWS JSON ...")
    print()
    parse_all(
        cloudtrail_path=CLOUDTRAIL_JSON,
        resources_path=RESOURCES_JSON,
        logs_out=PARSED_LOGS,
        resources_out=PARSED_RESOURCES,
    )

    print()
    print("[ STEP 2 ] Running detection engine ...")
    print()

    # Step 2: Run detection on parsed CSVs — same detect.py as Phase 1
    findings = run_all_rules(PARSED_RESOURCES, PARSED_LOGS)

    print(f"  [detect] {len(findings)} finding(s) returned.")
    print()
    print("[ STEP 3 ] Generating report ...")
    print()

    # Step 3: Output — same report.py as Phase 1
    generate_report(findings, json_output_path=JSON_REPORT_OUT)


if __name__ == "__main__":
    main()
