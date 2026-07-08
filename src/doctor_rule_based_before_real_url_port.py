import os
import re
import csv
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_FILE = PROJECT_ROOT / "data" / "cybershieldx_20k_full_arabic_UTF8.csv"
RULE_AUDIT_FILE = PROJECT_ROOT / "outputs" / "doctor_rule_based_audit.csv"
LOGIN_ALERT_FILE = PROJECT_ROOT / "outputs" / "login_signin_alerts.csv"

PHISHING_RULES = [
    "otp", "password", "login", "verify", "account", "bank", "click",
    "free", "gift", "urgent", "wallet", "crypto",
    "كود", "رمز", "تحقق", "حسابك", "بنك", "اضغط", "رابط",
    "مجاني", "هدية", "عاجل", "محفظة", "تسجيل الدخول"
]

SOCIAL_ENGINEERING_RULES = [
    "send me", "trust me", "secret", "don't tell anyone",
    "ابعت", "ابعث", "ارسل", "لا تحكي", "لا تخبر", "سري",
    "خاص", "ثق فيني", "بسرعة", "ضروري", "حول", "ادفع"
]

TELEGRAM_RULES = [
    "telegram", "t.me", "telegram.me", "telegram.org", "joinchat",
    "تلجرام", "تيليجرام"
]

RISKY_PORTS = {
    21: "FTP clear-text",
    23: "Telnet insecure remote access",
    80: "HTTP not encrypted",
    445: "SMB exposure",
    3389: "RDP remote desktop",
    4444: "Common reverse shell",
    8080: "Alternative HTTP service",
}

NORMAL_PORTS = {
    22: "SSH",
    25: "SMTP",
    443: "HTTPS encrypted traffic",
}


def ensure_outputs():
    (PROJECT_ROOT / "outputs").mkdir(exist_ok=True)


def append_csv(path, header, row):
    ensure_outputs()
    exists = path.exists()
    with open(path, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        if not exists:
            writer.writerow(header)
        writer.writerow(row)


def log_login_alert(uid, event_type, status, details=""):
    append_csv(
        LOGIN_ALERT_FILE,
        ["time", "uid", "event_type", "status", "details"],
        [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), uid or "UNKNOWN", event_type, status, details],
    )


def log_rule_audit(uid, text, port, url, risk, score, matched_rules):
    append_csv(
        RULE_AUDIT_FILE,
        ["time", "uid", "text", "port", "url", "risk", "score", "matched_rules"],
        [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), uid, text, port, url, risk, score, matched_rules],
    )


def load_dataset():
    if not DATASET_FILE.exists():
        return pd.DataFrame()

    try:
        return pd.read_csv(DATASET_FILE, encoding="utf-8", engine="python", on_bad_lines="skip").fillna("")
    except Exception:
        return pd.read_csv(DATASET_FILE, encoding="utf-8-sig", engine="python", on_bad_lines="skip").fillna("")


def detect_text_column(df):
    preferred = ["text", "نص_الرسالة", "message", "raw_text", "normalized_text", "incident_text"]
    for col in preferred:
        if col in df.columns:
            return col

    if df.empty:
        return None

    best_col = None
    best_len = -1
    for col in df.columns:
        avg_len = df[col].astype(str).str.len().mean()
        if avg_len > best_len:
            best_len = avg_len
            best_col = col

    return best_col


def detect_label_column(df):
    preferred = ["label", "نوع_الحالة", "predicted_label", "case_type", "category", "classification"]
    for col in preferred:
        if col in df.columns:
            return col
    return None


def words(text):
    return [w for w in re.findall(r"[\w\u0600-\u06FF]+", str(text).lower()) if len(w) >= 4]


def contains_rules(text, rules):
    text = str(text).lower()
    return [rule for rule in rules if rule.lower() in text]


def extract_urls(text):
    return re.findall(r"(https?://[^\s]+|www\.[^\s]+|t\.me/[^\s]+)", str(text), re.IGNORECASE)


def extract_ports(text):
    """
    Auto-detect ports from message text.
    Examples:
    - port 4444
    - Port: 3389
    - :443
    - tcp/80
    - https port 443
    """
    text = str(text or "").lower()
    ports = set()

    patterns = [
        r"port\s*[:=]?\s*(\d{1,5})",
        r"tcp\s*/\s*(\d{1,5})",
        r"udp\s*/\s*(\d{1,5})",
        r":(\d{2,5})\b",
        r"\b(21|22|23|25|80|443|445|3389|4444|8080)\b",
    ]

    for pattern in patterns:
        for match in re.findall(pattern, text):
            try:
                port = int(match)
                if 1 <= port <= 65535:
                    ports.add(port)
            except Exception:
                pass

    return sorted(list(ports))


def check_https(url):
    url = str(url or "").strip()

    if not url:
        return {
            "url": "N/A",
            "https_status": "No URL",
            "is_risky": False,
            "note": "No URL was provided."
        }

    if url.startswith("https://"):
        return {
            "url": url,
            "https_status": "HTTPS",
            "is_risky": False,
            "note": "HTTPS is encrypted. Continue checking domain and content."
        }

    if url.startswith("http://"):
        return {
            "url": url,
            "https_status": "HTTP",
            "is_risky": True,
            "note": "HTTP is not encrypted. Prefer HTTPS."
        }

    if "t.me" in url.lower() or "telegram" in url.lower():
        return {
            "url": url,
            "https_status": "Telegram Link",
            "is_risky": False,
            "note": "Telegram indicator found. Check social engineering context."
        }

    return {
        "url": url,
        "https_status": "Unknown Protocol",
        "is_risky": True,
        "note": "URL has unclear/missing protocol."
    }


def check_port(port):
    if port is None or str(port).strip() == "":
        return {
            "port": "N/A",
            "is_risky": False,
            "service": "No port",
            "recommendation": "No port was provided."
        }

    try:
        p = int(str(port).strip())
    except ValueError:
        return {
            "port": str(port),
            "is_risky": False,
            "service": "Invalid input",
            "recommendation": "Enter numeric port only."
        }

    if p in RISKY_PORTS:
        return {
            "port": p,
            "is_risky": True,
            "service": RISKY_PORTS[p],
            "recommendation": "Investigate and restrict this port if not required."
        }

    if p in NORMAL_PORTS:
        return {
            "port": p,
            "is_risky": False,
            "service": NORMAL_PORTS[p],
            "recommendation": "Known port. Continue inspection based on context."
        }

    return {
        "port": p,
        "is_risky": False,
        "service": "Unknown/normal service",
        "recommendation": "No risky port rule matched."
    }


def dataset_as_rules_match(text, search_filter=""):
    df = load_dataset()

    if df.empty:
        return pd.DataFrame(), "Dataset not found", None, None

    text_col = detect_text_column(df)
    label_col = detect_label_column(df)

    if not text_col:
        return pd.DataFrame(), "Dataset text column not found", None, None

    input_words = set(words(text))
    search_filter = str(search_filter or "").lower().strip()
    results = []

    for idx, row in df.iterrows():
        rule_text = str(row.get(text_col, ""))
        label = str(row.get(label_col, "")) if label_col else ""

        if search_filter:
            joined = f"{rule_text} {label}".lower()
            if search_filter not in joined:
                continue

        rule_words = set(words(rule_text))
        matched = input_words.intersection(rule_words)

        if matched:
            results.append({
                "rule_id": idx,
                "match_score": len(matched),
                "matched_words": ", ".join(list(matched)[:15]),
                "dataset_label": label,
                "rule_text": rule_text[:350],
            })

    out = pd.DataFrame(results)
    if not out.empty:
        out = out.sort_values("match_score", ascending=False).head(25)

    return out, "OK", text_col, label_col


def analyze_doctor_requirements(uid, text, port="", url="", search_filter=""):
    uid = str(uid or "").strip()
    text = str(text or "").strip()

    if not uid:
        return {"valid": False, "error": "UID is mandatory / UID إجباري."}

    phishing = contains_rules(text, PHISHING_RULES)
    social = contains_rules(text, SOCIAL_ENGINEERING_RULES)
    telegram = contains_rules(text, TELEGRAM_RULES)

    # Auto URL detection from message text
    urls = extract_urls(text)
    if url:
        urls.append(url)

    # Auto Port detection from message text
    auto_ports = extract_ports(text)
    if port:
        try:
            manual_port = int(str(port).strip())
            if manual_port not in auto_ports:
                auto_ports.append(manual_port)
        except Exception:
            pass

    https_checks = [check_https(u) for u in urls] if urls else [check_https(url)]

    # Check all detected ports, not just one
    port_checks = [check_port(p) for p in auto_ports] if auto_ports else [check_port(port)]
    port_check = max(port_checks, key=lambda x: 1 if x.get("is_risky") else 0)

    dataset_matches, dataset_status, text_col, label_col = dataset_as_rules_match(text, search_filter)

    score = 0
    score += len(phishing) * 2
    score += len(social) * 2
    score += len(telegram) * 2
    score += 4 if any(x["is_risky"] for x in port_checks) else 0
    score += 3 if any(x["is_risky"] for x in https_checks) else 0

    if not dataset_matches.empty:
        score += min(6, int(dataset_matches.iloc[0]["match_score"]))

    matched = []
    if phishing:
        matched.append("Phishing Rule")
    if social:
        matched.append("Social Engineering Rule")
    if telegram:
        matched.append("Telegram Rule")
    if any(x["is_risky"] for x in port_checks):
        matched.append("Port Rule")
    if any(x["is_risky"] for x in https_checks):
        matched.append("HTTPS/HTTP Rule")
    if not dataset_matches.empty:
        matched.append("Dataset Rule-Based Match")

    if not matched:
        matched.append("No Rule Matched")

    if score >= 10:
        risk = "High"
        alert = "ALERT_TRIGGERED"
    elif score >= 5:
        risk = "Medium"
        alert = "SUSPICIOUS_ACTIVITY"
    else:
        risk = "Low"
        alert = "NO_CRITICAL_RULE_MATCH"

    matched_rules = ", ".join(matched)

    log_rule_audit(uid, text, port, url, risk, score, matched_rules)

    return {
        "valid": True,
        "uid": uid,
        "risk": risk,
        "score": score,
        "alert": alert,
        "matched_rules": matched_rules,
        "phishing": ", ".join(phishing),
        "social": ", ".join(social),
        "telegram": ", ".join(telegram),
        "https_checks": https_checks,
        "auto_detected_urls": urls,
        "auto_detected_ports": auto_ports,
        "port_checks": port_checks,
        "port_check": port_check,
        "dataset_matches": dataset_matches,
        "dataset_status": dataset_status,
        "dataset_text_col": text_col,
        "dataset_label_col": label_col,
    }
