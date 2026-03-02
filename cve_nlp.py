import re

CATEGORY_RULES = [
    ("RCE", r"(remote code execution|code execution|execute arbitrary)"),
    ("SQLi", r"(sql injection|sqli)"),
    ("XSS", r"(cross-site scripting|xss)"),
    ("Auth Bypass", r"(authentication bypass|auth bypass|bypass authentication)"),
    ("Privilege Escalation", r"(privilege escalation|elevation of privilege)"),
    ("Path Traversal", r"(path traversal|directory traversal)"),
    ("SSRF", r"(server-side request forgery|ssrf)"),
    ("DoS", r"(denial of service|\bdos\b)"),
]

RISK_KEYWORDS = [
    ("exploit", 1.5),
    ("remote", 1.0),
    ("unauthenticated", 1.2),
    ("actively exploited", 2.5),
    ("publicly available", 1.0),
    ("wormable", 2.0),
]

def categorize(text: str) -> str:
    t = (text or "").lower()
    for cat, pattern in CATEGORY_RULES:
        if re.search(pattern, t):
            return cat
    return "Other"

def risk_score(cvss_base_score, description: str) -> float:
    # Safe convert (handles None / NaN / strings)
    try:
        base = float(cvss_base_score)
        if base != base:  # NaN
            base = 4.0
    except Exception:
        base = 4.0

    t = (description or "").lower()
    bonus = 0.0
    for kw, w in RISK_KEYWORDS:
        if kw in t:
            bonus += w

    return round(min(10.0, base + bonus), 2)