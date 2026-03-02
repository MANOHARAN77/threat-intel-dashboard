# 🛡️ AI-Powered Threat Intelligence Dashboard (CVE)

An interactive Streamlit dashboard that fetches real-time CVE data from the NVD API, enriches it using rule-based NLP classification, and computes a contextual risk score to assist in vulnerability triage and prioritization.

---

## 🚀 Features

- Fetches latest CVEs from NVD API
- Stores structured vulnerability data in CSV format
- Categorizes vulnerabilities (RCE, SQLi, XSS, SSRF, DoS, etc.)
- Computes a custom **Risk Score** (CVSS + exploit-signal keywords)
- Auto-calculates severity (Critical / High / Medium / Low)
- Interactive filtering (Severity, Category, Risk Score)
- Visual insights:
  - Category distribution chart
  - CVE publish trend chart
  - High-risk CVE table

---

## 🏗️ Project Structure
threat-intel-dashboard/
│
├── app.py # Streamlit dashboard
├── cve_fetch.py # Fetches CVE data from NVD API
├── cve_nlp.py # Categorization + risk scoring logic
├── requirements.txt # Project dependencies
├── data/
│ └── cves.csv # Generated vulnerability dataset
└── README.md


---

## ⚙️ How To Run

1. Install dependencies:

pip install -r requirements.txt


2. Fetch latest CVEs:

python cve_fetch.py


3. Run the dashboard:

streamlit run app.py

CODE:


---

## 🧠 Risk Scoring Logic

Final Risk Score =  
CVSS Base Score + Exploit-Signal Keyword Weights (Capped at 10)

This enhances traditional CVSS scoring by incorporating contextual threat signals such as:
- remote
- unauthenticated
- actively exploited
- exploit available

---

## 🎯 Use Case

Helps security teams:
- Prioritize vulnerability remediation
- Identify high-risk exploit patterns
- Monitor vulnerability trends
- Accelerate threat triage

---

## 👨‍💻 Author

Built as a cybersecurity + AI portfolio project.