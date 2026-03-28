"""
app.py
------
Streamlit dashboard for the Cloud Security Misconfiguration & Activity Analyzer.
Reads from output/report.json — run report.py first to generate it.

Run from the project root:
    streamlit run app.py
"""

import json
import os
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REPORT_PATH = Path("output/report.json")

SEVERITY_COLORS = {
    "HIGH":   "#e63946",
    "MEDIUM": "#f4a261",
    "LOW":    "#457b9d",
}

SEVERITY_ORDER = ["HIGH", "MEDIUM", "LOW"]

st.set_page_config(
    page_title="Cloud Security Analyzer",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Custom CSS — dark terminal aesthetic
# ---------------------------------------------------------------------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Syne', sans-serif;
    background-color: #0a0e17;
    color: #c9d1d9;
}

/* Main background */
.stApp {
    background-color: #0a0e17;
}

/* Header */
.dash-header {
    padding: 2rem 0 1.5rem 0;
    border-bottom: 1px solid #21262d;
    margin-bottom: 2rem;
}
.dash-title {
    font-size: 1.9rem;
    font-weight: 800;
    color: #e6edf3;
    letter-spacing: -0.02em;
    font-family: 'Syne', sans-serif;
}
.dash-subtitle {
    font-size: 0.85rem;
    color: #6e7681;
    font-family: 'JetBrains Mono', monospace;
    margin-top: 0.3rem;
}

/* Metric cards */
.metric-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 1.2rem 1.5rem;
    text-align: center;
    transition: border-color 0.2s;
}
.metric-card:hover { border-color: #30363d; }
.metric-value {
    font-size: 2.4rem;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
}
.metric-label {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #6e7681;
    margin-top: 0.4rem;
}

/* Section headers */
.section-header {
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #6e7681;
    border-bottom: 1px solid #21262d;
    padding-bottom: 0.5rem;
    margin: 2rem 0 1rem 0;
    font-family: 'JetBrains Mono', monospace;
}

/* Findings table rows */
.finding-row {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.6rem;
}
.finding-rule {
    font-size: 0.95rem;
    font-weight: 700;
    color: #e6edf3;
}
.finding-resource {
    font-size: 0.8rem;
    font-family: 'JetBrains Mono', monospace;
    color: #8b949e;
    margin-top: 0.15rem;
}
.finding-reason {
    font-size: 0.85rem;
    color: #8b949e;
    margin-top: 0.5rem;
    line-height: 1.5;
}

.badge-HIGH   { background:#e6394622; color:#e63946; border:1px solid #e6394644;
                padding:2px 10px; border-radius:20px; font-size:0.72rem;
                font-weight:700; font-family:'JetBrains Mono',monospace;
                letter-spacing:0.06em; }
.badge-MEDIUM { background:#f4a26122; color:#f4a261; border:1px solid #f4a26144;
                padding:2px 10px; border-radius:20px; font-size:0.72rem;
                font-weight:700; font-family:'JetBrains Mono',monospace;
                letter-spacing:0.06em; }
.badge-LOW    { background:#457b9d22; color:#457b9d; border:1px solid #457b9d44;
                padding:2px 10px; border-radius:20px; font-size:0.72rem;
                font-weight:700; font-family:'JetBrains Mono',monospace;
                letter-spacing:0.06em; }

/* Streamlit native overrides */
div[data-testid="stMetric"] { display: none; }
section[data-testid="stSidebar"] { background: #0d1117; border-right: 1px solid #21262d; }
.stSelectbox label, .stMultiSelect label { color: #8b949e !important; font-size: 0.8rem !important; }
div[data-baseweb="select"] { background: #161b22 !important; border-color: #30363d !important; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Data loader
# ---------------------------------------------------------------------------

@st.cache_data
def load_report(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Chart builders
# ---------------------------------------------------------------------------

def chart_by_severity(df: pd.DataFrame) -> go.Figure:
    counts = (
        df["severity"]
        .value_counts()
        .reindex(SEVERITY_ORDER)
        .fillna(0)
        .reset_index()
    )
    counts.columns = ["severity", "count"]

    fig = px.bar(
        counts,
        x="severity",
        y="count",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        text="count",
    )
    fig.update_traces(
        textposition="outside",
        textfont=dict(family="JetBrains Mono", size=13, color="#e6edf3"),
        marker_line_width=0,
    )
    fig.update_layout(
        plot_bgcolor="#161b22",
        paper_bgcolor="#161b22",
        font=dict(family="Syne", color="#8b949e"),
        showlegend=False,
        xaxis=dict(title="", tickfont=dict(family="JetBrains Mono", size=11, color="#8b949e"), gridcolor="#21262d"),
        yaxis=dict(title="Findings", tickfont=dict(family="JetBrains Mono", size=11, color="#8b949e"), gridcolor="#21262d"),
        margin=dict(t=20, b=10, l=10, r=10),
        bargap=0.35,
    )
    return fig


def chart_by_rule(df: pd.DataFrame) -> go.Figure:
    counts = df["rule"].value_counts().reset_index()
    counts.columns = ["rule", "count"]
    counts = counts.sort_values("count", ascending=True)

    # Color each bar by the severity of that rule
    rule_severity = df.drop_duplicates("rule").set_index("rule")["severity"]
    bar_colors = [SEVERITY_COLORS.get(rule_severity.get(r, "LOW"), "#457b9d") for r in counts["rule"]]

    fig = go.Figure(go.Bar(
        x=counts["count"],
        y=counts["rule"],
        orientation="h",
        marker_color=bar_colors,
        marker_line_width=0,
        text=counts["count"],
        textposition="outside",
        textfont=dict(family="JetBrains Mono", size=12, color="#e6edf3"),
    ))
    fig.update_layout(
        plot_bgcolor="#161b22",
        paper_bgcolor="#161b22",
        font=dict(family="Syne", color="#8b949e"),
        xaxis=dict(title="Findings", tickfont=dict(family="JetBrains Mono", size=11, color="#8b949e"), gridcolor="#21262d"),
        yaxis=dict(title="", tickfont=dict(family="JetBrains Mono", size=11, color="#e6edf3")),
        margin=dict(t=20, b=10, l=10, r=40),
        bargap=0.3,
    )
    return fig


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------

def main():
    # — Load data —
    if not REPORT_PATH.exists():
        st.error(
            f"**`{REPORT_PATH}` not found.**\n\n"
            "Run the analysis first:\n```bash\npython analysis/report.py\n```"
        )
        st.stop()

    report  = load_report(REPORT_PATH)
    summary = report["summary"]
    findings_raw = report["findings"]

    df = pd.DataFrame(findings_raw) if findings_raw else pd.DataFrame(
        columns=["severity", "rule", "resource_id", "reason"]
    )

    generated_at = report.get("generated_at", "unknown")

    # — Header —
    st.markdown(f"""
    <div class="dash-header">
        <div class="dash-title">🛡️ Cloud Security Analyzer</div>
        <div class="dash-subtitle">report generated {generated_at} &nbsp;·&nbsp;</div>
    </div>
    """, unsafe_allow_html=True)

    # — Sidebar filters —
    with st.sidebar:
        st.markdown("### Filters")
        selected_severities = st.multiselect(
            "Severity",
            options=SEVERITY_ORDER,
            default=SEVERITY_ORDER,
        )
        all_rules = sorted(df["rule"].unique().tolist()) if not df.empty else []
        selected_rules = st.multiselect(
            "Rule",
            options=all_rules,
            default=all_rules,
        )
        st.markdown("---")
        st.markdown(
            "<div style='font-size:0.75rem;color:#6e7681;font-family:JetBrains Mono,monospace;'>"
            "Cloud Security Analyzer<br>Phase 1 — Local CSV<br><br>"
            "Run <code>python analysis/report.py</code><br>to refresh report.json</div>",
            unsafe_allow_html=True,
        )

    # Apply filters
    filtered = df[
        df["severity"].isin(selected_severities) &
        df["rule"].isin(selected_rules)
    ] if not df.empty else df

    # — Summary cards —
    st.markdown('<div class="section-header">Summary</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    cards = [
        (c1, summary["total"],  "#e6edf3", "Total Findings"),
        (c2, summary["HIGH"],   SEVERITY_COLORS["HIGH"],   "High"),
        (c3, summary["MEDIUM"], SEVERITY_COLORS["MEDIUM"], "Medium"),
        (c4, summary["LOW"],    SEVERITY_COLORS["LOW"],    "Low"),
    ]
    for col, value, color, label in cards:
        with col:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value" style="color:{color}">{value}</div>
                <div class="metric-label">{label}</div>
            </div>
            """, unsafe_allow_html=True)

    # — Charts —
    st.markdown('<div class="section-header">Breakdown</div>', unsafe_allow_html=True)
    if filtered.empty:
        st.info("No findings match the selected filters.")
    else:
        col_a, col_b = st.columns([1, 2])
        with col_a:
            st.markdown("**By Severity**")
            st.plotly_chart(chart_by_severity(filtered), use_container_width=True)
        with col_b:
            st.markdown("**By Rule**")
            st.plotly_chart(chart_by_rule(filtered), use_container_width=True)

    # — Findings table —
    st.markdown('<div class="section-header">Findings</div>', unsafe_allow_html=True)

    if filtered.empty:
        st.info("No findings to display.")
    else:
        severity_order_map = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_df = filtered.copy()
        sorted_df["_order"] = sorted_df["severity"].map(severity_order_map)
        sorted_df = sorted_df.sort_values("_order").drop(columns="_order")

        for _, row in sorted_df.iterrows():
            sev = row["severity"]
            st.markdown(f"""
            <div class="finding-row">
                <div style="display:flex; align-items:center; gap:0.75rem;">
                    <span class="badge-{sev}">{sev}</span>
                    <span class="finding-rule">{row['rule']}</span>
                </div>
                <div class="finding-resource">{row['resource_id']}</div>
                <div class="finding-reason">{row['reason']}</div>
            </div>
            """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
