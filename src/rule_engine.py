import re
from urllib.parse import urlparse

PHISHING_KEYWORDS = [
    "otp", "password", "login", "verify", "account", "bank",
    "urgent", "free", "gift", "click", "limited", "security",
    "كود", "رمز", "تحقق", "حسابك", "بنك", "اضغط", "رابط",
    "هدية", "مجاني", "عاجل", "تسجيل الدخول"
]

SOCIAL_ENGINEERING_KEYWORDS = [
    "send me", "trust me", "don't tell anyone", "secret",
    "حول", "ابعت", "ابعث", "لا تحكي", "سري", "ثق فيني",
    "بسرعة", "لا تخبر", "ضروري", "خاص", "لا تقول"
]

TELEGRAM_INDICATORS = [
    "t.me",
    "telegram.me",
    "telegram.org",
    "joinchat",
    "telegram",
    "تيليجرام",
    "تلجرام"
]

SUSPICIOUS_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "grabify.link",
    "iplogger.org",
    "shorturl.at",
    "rebrand.ly",
    "cutt.ly",
    "is.gd",
    "rb.gy"
]

SUSPICIOUS_PORTS = {
    21: "FTP clear-text service",
    22: "SSH remote access",
    23: "Telnet insecure remote access",
    25: "SMTP mail service",
    80: "HTTP unencrypted web traffic",
    443: "HTTPS encrypted web traffic",
    445: "SMB file sharing",
    3389: "RDP remote desktop",
    4444: "Common reverse shell port",
    8080: "Alternative web proxy/service",
}


def extract_urls(text: str):
    if not text:
        return []
    return re.findall(r"(https?://[^\s]+|www\.[^\s]+|t\.me/[^\s]+)", text, re.IGNORECASE)


def normalize_domain(url: str):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return parsed.netloc.lower().replace("www.", "")


def keyword_matches(text: str, keywords: list):
    text_lower = (text or "").lower()
    return [kw for kw in keywords if kw.lower() in text_lower]


def check_phishing_urls(text: str):
    urls = extract_urls(text)
    hits = []

    for url in urls:
        domain = normalize_domain(url)

        for suspicious in SUSPICIOUS_DOMAINS:
            if suspicious in domain:
                hits.append({
                    "url": url,
                    "domain": domain,
                    "reason": "Suspicious shortened/tracking domain"
                })

        if "login" in url.lower() or "verify" in url.lower() or "otp" in url.lower():
            hits.append({
                "url": url,
                "domain": domain,
                "reason": "URL contains phishing-related keyword"
            })

    return hits


def check_ports(port_value):
    if port_value is None or str(port_value).strip() == "":
        return {
            "port": "N/A",
            "is_suspicious": False,
            "service": "No port provided",
            "recommendation": "No port was provided for checking."
        }

    try:
        port = int(str(port_value).strip())
    except ValueError:
        return {
            "port": str(port_value),
            "is_suspicious": False,
            "service": "Invalid port input",
            "recommendation": "Enter a valid numeric port."
        }

    service = SUSPICIOUS_PORTS.get(port, "Unknown/normal service")

    if port in [21, 23, 3389, 4444, 445]:
        return {
            "port": port,
            "is_suspicious": True,
            "service": service,
            "recommendation": "Investigate this port and restrict access if unnecessary."
        }

    if port == 80:
        return {
            "port": port,
            "is_suspicious": True,
            "service": service,
            "recommendation": "HTTP detected. Prefer HTTPS for secure communication."
        }

    if port == 443:
        return {
            "port": port,
            "is_suspicious": False,
            "service": service,
            "recommendation": "HTTPS is encrypted, but URLs and certificates should still be inspected."
        }

    return {
        "port": port,
        "is_suspicious": False,
        "service": service,
        "recommendation": "No high-risk rule matched."
    }


def analyze_rule_based(text: str, port=None, source="manual"):
    phishing_keywords = keyword_matches(text, PHISHING_KEYWORDS)
    social_hits = keyword_matches(text, SOCIAL_ENGINEERING_KEYWORDS)
    telegram_hits = keyword_matches(text, TELEGRAM_INDICATORS)
    phishing_urls = check_phishing_urls(text)
    port_result = check_ports(port)

    score = 0
    score += len(phishing_keywords) * 2
    score += len(social_hits) * 2
    score += len(telegram_hits) * 2
    score += len(phishing_urls) * 4

    if port_result["is_suspicious"]:
        score += 4

    matched_rules = []

    if phishing_keywords:
        matched_rules.append("Phishing Keywords")
    if social_hits:
        matched_rules.append("Social Engineering")
    if telegram_hits:
        matched_rules.append("Telegram Indicators")
    if phishing_urls:
        matched_rules.append("Suspicious URL")
    if port_result["is_suspicious"]:
        matched_rules.append("Suspicious Port / Protocol")

    if not matched_rules:
        matched_rules.append("No Rule Matched")

    if score >= 9:
        risk_level = "High"
        alert_status = "ALERT_TRIGGERED"
    elif score >= 5:
        risk_level = "Medium"
        alert_status = "SUSPICIOUS_ACTIVITY"
    else:
        risk_level = "Low"
        alert_status = "NO_CRITICAL_RULE_MATCH"

    return {
        "source": source,
        "rule_risk_level": risk_level,
        "rule_score": score,
        "alert_status": alert_status,
        "matched_rules": ", ".join(matched_rules),
        "phishing_keywords": ", ".join(phishing_keywords),
        "social_engineering_hits": ", ".join(social_hits),
        "telegram_indicators": ", ".join(telegram_hits),
        "phishing_urls": phishing_urls,
        "port": port_result["port"],
        "port_service": port_result["service"],
        "port_recommendation": port_result["recommendation"],
    }
