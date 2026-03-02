import requests
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cves(days=3, max_results=50):
    end = datetime.utcnow()
    start = end - timedelta(days=days)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": max_results
    }

    print("Starting CVE fetch...")
    print("Requesting NVD...", params)

    r = requests.get(NVD_API, params=params, timeout=60)
    print("HTTP Status:", r.status_code)

    if r.status_code != 200:
        print("Response (first 400 chars):")
        print(r.text[:400])
        r.raise_for_status()

    data = r.json()

    vulns = data.get("vulnerabilities", [])
    print("Vulnerabilities received:", len(vulns))

    rows = []
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        published = cve.get("published")
        last_modified = cve.get("lastModified")

        metrics = cve.get("metrics", {})
        base_score = None
        severity = None  # Often None in NVD v2.0 response

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                metric = metrics[key][0]
                if "cvssData" in metric:
                    base_score = metric["cvssData"].get("baseScore")
                    severity = metric.get("baseSeverity")
                break

        rows.append({
            "cve_id": cve_id,
            "published": published,
            "last_modified": last_modified,
            "cvss_base_score": base_score,
            "severity": severity,
            "description": desc
        })

    return pd.DataFrame(rows)

if __name__ == "__main__":
    Path("data").mkdir(exist_ok=True)
    df = fetch_cves(days=3, max_results=50)

    out = Path("data") / "cves.csv"
    if df.empty:
        print("❌ No data received. Not writing cves.csv")
    else:
        df.to_csv(out, index=False)
        print(f"✅ Saved {len(df)} CVEs -> {out.resolve()}")