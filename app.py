import streamlit as st
import pandas as pd
from cve_nlp import categorize, risk_score

st.set_page_config(page_title="Threat Intel Dashboard", layout="wide")
st.title("🛡️ AI-Powered Threat Intelligence Dashboard (CVE)")

# --- helper: compute severity from CVSS ---
def cvss_to_severity(score):
    try:
        s = float(score)
        if s != s:  # NaN
            return "Unknown"
    except Exception:
        return "Unknown"

    if s >= 9.0:
        return "Critical"
    elif s >= 7.0:
        return "High"
    elif s >= 4.0:
        return "Medium"
    elif s > 0:
        return "Low"
    return "Unknown"

# --- Load data ---
df = pd.read_csv("data/cves.csv")
df["description"] = df["description"].fillna("").astype(str)

# --- Enrich ---
df["category"] = df["description"].apply(categorize)
df["risk_score"] = df.apply(lambda r: risk_score(r["cvss_base_score"], r["description"]), axis=1)
df["severity_calc"] = df["cvss_base_score"].apply(cvss_to_severity)

# --- Sidebar filters ---
st.sidebar.header("Filters")

sev_options = ["Critical", "High", "Medium", "Low", "Unknown"]
cat_options = sorted(df["category"].dropna().unique().tolist())

severity = st.sidebar.multiselect("Severity", sev_options, default=[])
category = st.sidebar.multiselect("Category", cat_options, default=[])
min_risk = st.sidebar.slider("Minimum Risk Score", 0.0, 10.0, 6.0, 0.5)

filtered = df.copy()
if severity:
    filtered = filtered[filtered["severity_calc"].isin(severity)]
if category:
    filtered = filtered[filtered["category"].isin(category)]
filtered = filtered[filtered["risk_score"] >= min_risk]

# --- Metrics ---
c1, c2, c3 = st.columns(3)
c1.metric("Total CVEs", len(df))
c2.metric("Filtered CVEs", len(filtered))
c3.metric("High Risk (>=9)", int((filtered["risk_score"] >= 9).sum()))

st.caption("Risk score = CVSS base score + keyword signals (capped at 10).")

# --- Table ---
st.subheader("Top High-Risk CVEs")
st.dataframe(
    filtered.sort_values("risk_score", ascending=False)[
        ["cve_id", "published", "cvss_base_score", "severity_calc", "category", "risk_score", "description"]
    ].head(30),
    use_container_width=True
)

# --- Category chart ---
st.subheader("Category Distribution (Filtered)")
st.bar_chart(filtered["category"].value_counts())

# --- Trend chart ---
st.subheader("CVE Publish Trend (Filtered)")
filtered["published_date"] = pd.to_datetime(filtered["published"], errors="coerce").dt.date
trend = filtered.dropna(subset=["published_date"]).groupby("published_date").size()
st.line_chart(trend)