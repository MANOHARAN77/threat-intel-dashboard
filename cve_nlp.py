import re

CATEGORY_KEYWORDS = {
    "SQLi": ["sql injection", "sqli", "blind sql", "union select"],
    "XSS": ["cross-site scripting", "xss", "dom xss", "stored xss", "reflected xss"],
    "SSRF": ["ssrf", "server-side request forgery"],
    "RCE": ["remote code execution", "rce", "command injection", "os command", "code execution"],
    "Path Traversal": ["path traversal", "directory traversal", "../", "..\\"],
    "Privilege Escalation": ["privilege escalation", "elevation of privilege", "escalation"],
    "DoS": ["denial of service", "dos", "resource exhaustion", "infinite loop", "crash"],
}

SIGNAL_WEIGHTS = {
    "remote": 1.0,
    "unauthenticated": 1.5,
    "authentication bypass": 2.0,
    "privilege escalation": 1.5,
    "actively exploited": 2.0,
    "exploit available": 1.5,
    "wormable": 2.0,
}

def categorize(text: str) -> str:
    t = (text or "").lower()
    for cat, kws in CATEGORY_KEYWORDS.items():
        for kw in kws:
            if kw in t:
                return cat
    return "Other"

def risk_score(cvss_base_score, description: str) -> float:
    """
    Simple enhanced risk score:
    - Start with CVSS base score (0-10)
    - Add extra weights if description contains threat signals
    - Cap final score at 10
    """
    base = 0.0
    try:
        if cvss_base_score is not None:
            base = float(cvss_base_score)
    except Exception:
        base = 0.0

    t = (description or "").lower()

    extra = 0.0
    for signal, w in SIGNAL_WEIGHTS.items():
        if signal in t:
            extra += w

    final = min(10.0, base + extra)
    return round(final, 2)

def severity_from_cvss(cvss_base_score):
    """
    CVSS severity buckets:
    None/0-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10 Critical
    """
    try:
        s = float(cvss_base_score)
    except Exception:
        return "Unknown"

    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"