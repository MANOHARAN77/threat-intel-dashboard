import os
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from cve_fetch import ensure_cves_csv
from cve_nlp import categorize, risk_score, severity_from_cvss

st.set_page_config(page_title="Threat Intel Dashboard", layout="wide")

st.title("🛡️ AI-Powered Threat Intelligence Dashboard (CVE)")
st.caption("Risk score = CVSS base score + keyword signals (capped at 10).")

# -----------------------------
# Data: ensure CSV exists (cloud-safe)
# -----------------------------
DATA_DIR = Path("data")
CSV_PATH = DATA_DIR / "cves.csv"

with st.sidebar:
    st.header("Data Refresh")
    days = st.number_input("Fetch CVEs from last N days", min_value=1, max_value=30, value=3, step=1)
    max_results = st.number_input("Max results", min_value=10, max_value=2000, value=200, step=10)
    force_refresh = st.button("🔄 Force refresh from NVD")

# Ensure CSV exists (or refresh if needed)
ensure_cves_csv(
    csv_path=CSV_PATH,
    days=int(days),
    max_results=int(max_results),
    force=bool(force_refresh),
)

if not CSV_PATH.exists():
    st.error("cves.csv not found and could not be generated. Check Streamlit logs / NVD connectivity.")
    st.stop()

# Load CSV safely
try:
    df = pd.read_csv(CSV_PATH)
except pd.errors.EmptyDataError:
    st.error("cves.csv exists but is empty. Try Force refresh.")
    st.stop()

if df.empty:
    st.warning("No CVEs returned for the selected period. Try increasing N days.")
    st.stop()

# -----------------------------
# Enrich data
# -----------------------------
# Make sure expected columns exist
for col in ["cve_id", "published", "last_modified", "cvss_base_score", "severity", "description"]:
    if col not in df.columns:
        df[col] = None

df["description"] = df["description"].fillna("")

df["category"] = df["description"].apply(categorize)
df["risk_score"] = df.apply(lambda r: risk_score(r.get("cvss_base_score"), r.get("description")), axis=1)
df["severity_calc"] = df["cvss_base_score"].apply(severity_from_cvss)

# -----------------------------
# Sidebar filters
# -----------------------------
with st.sidebar:
    st.header("Filters")

    # Use calculated severity because NVD may not always provide a simple severity column
    sev_options = sorted([s for s in df["severity_calc"].dropna().unique().tolist() if str(s).strip() != ""])
    selected_sev = st.multiselect("Severity", sev_options, default=[])

    cat_options = sorted(df["category"].dropna().unique().tolist())
    selected_cat = st.multiselect("Category", cat_options, default=[])

    min_risk = st.slider("Minimum Risk Score", 0.0, 10.0, 6.0, 0.1)

# Apply filters
filtered = df.copy()

if selected_sev:
    filtered = filtered[filtered["severity_calc"].isin(selected_sev)]
if selected_cat:
    filtered = filtered[filtered["category"].isin(selected_cat)]

filtered = filtered[filtered["risk_score"] >= float(min_risk)]

# -----------------------------
# Metrics
# -----------------------------
c1, c2, c3 = st.columns(3)
c1.metric("Total CVEs", len(df))
c2.metric("Filtered CVEs", len(filtered))
c3.metric("High Risk (>=9)", int((filtered["risk_score"] >= 9).sum()))

# -----------------------------
# Table
# -----------------------------
st.subheader("Top High-Risk CVEs")

show_cols = [
    "cve_id",
    "published",
    "cvss_base_score",
    "severity_calc",
    "category",
    "risk_score",
    "description",
]

# Sort by risk then CVSS
top = filtered.sort_values(["risk_score", "cvss_base_score"], ascending=[False, False]).head(30)

st.dataframe(
    top[show_cols],
    use_container_width=True,
    hide_index=True,
)

# -----------------------------
# Chart
# -----------------------------
st.subheader("Category Distribution (Filtered)")
counts = filtered["category"].value_counts()
st.bar_chart(counts)

# Footer info
try:
    mtime = datetime.fromtimestamp(CSV_PATH.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    st.caption(f"Data source: NVD CVE API | CSV last updated: {mtime}")
except Exception:
    pass