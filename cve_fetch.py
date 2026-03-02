from pathlib import Path
from datetime import datetime, timedelta, timezone
import requests
import pandas as pd

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _iso_format(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_cves(days: int = 3, max_results: int = 200) -> pd.DataFrame:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    params = {
        "pubStartDate": _iso_format(start),
        "pubEndDate": _iso_format(end),
        "resultsPerPage": max_results,
    }

    response = requests.get(NVD_API, params=params, timeout=60)
    response.raise_for_status()
    data = response.json()

    rows = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        # Get English description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value")
                break

        published = cve.get("published")
        last_modified = cve.get("lastModified")

        base_score = None

        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            base_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            base_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            base_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        rows.append({
            "cve_id": cve_id,
            "published": published,
            "last_modified": last_modified,
            "cvss_base_score": base_score,
            "description": desc,
        })

    return pd.DataFrame(rows)


def ensure_cves_csv(csv_path: Path, days: int = 3, max_results: int = 200, force: bool = False):
    """
    Ensures CSV exists. If not, fetches from NVD.
    """
    csv_path.parent.mkdir(exist_ok=True)

    if not csv_path.exists() or force:
        print("Fetching CVEs from NVD...")
        df = fetch_cves(days=days, max_results=max_results)

        if not df.empty:
            df.to_csv(csv_path, index=False)
            print(f"Saved {len(df)} CVEs → {csv_path}")
        else:
            print("No CVEs fetched.")