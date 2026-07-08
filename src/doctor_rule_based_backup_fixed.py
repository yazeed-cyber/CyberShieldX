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
    """
    Extract real URLs from Telegram/message text.
    Supports:
    - https://domain.com/path
    - http://domain.com:8080/path
    - www.domain.com/path
    - t.me/channel
    """
    return re.findall(
        r"(https?://[^\s]+|www\.[^\s]+|t\.me/[^\s]+|telegram\.me/[^\s]+)",
        str(text),
        re.IGNORECASE
    )


def normalize_url(url):
    url = str(url or "").strip().rstrip(".,،؛;)")
    if not url:
        return ""

    if url.startswith("www."):
        return "https://" + url

    if url.startswith("t.me/") or url.startswith("telegram.me/"):
        return "https://" + url

    return url


def parse_real_url(url):
    """
    Parse actual URL data:
    - scheme
    - domain
    - path
    - explicit port if exists
    - default port by scheme
    """
    clean_url = normalize_url(url)

    if not clean_url:
        return {
            "url": "N/A",
            "scheme": "N/A",
            "domain": "N/A",
            "path": "",
            "port": "N/A",
            "is_https": False,
            "is_http": False,
            "note": "No URL provided."
        }

    parsed = urlparse(clean_url)
    scheme = parsed.scheme.lower()
    domain = parsed.hostname or parsed.netloc or "N/A"
    path = parsed.path or ""

    explicit_port = parsed.port

    if explicit_port:
        port = explicit_port
    elif scheme == "https":
        port = 443
    elif scheme == "http":
        port = 80
    else:
        port = "N/A"

    return {
        "url": clean_url,
        "scheme": scheme or "unknown",
        "domain": domain,
        "path": path,
        "port": port,
        "is_https": scheme == "https",
        "is_http": scheme == "http",
        "note": "Parsed from real URL."
    }


def extract_ports_from_text(text):
    """
    Extract explicit ports from normal text.
    Examples:
    - port 4444
    - tcp/3389
    - udp/53
    - :8080 inside URL or text
    """
    text = str(text or "").lower()
    ports = set()

    patterns = [
        r"\bport\s*[:=]?\s*(\d{1,5})\b",
        r"\btcp\s*/\s*(\d{1,5})\b",
        r"\budp\s*/\s*(\d{1,5})\b",
        r":(\d{2,5})\b",
        r"\b(21|22|23|25|53|80|443|445|3389|4444|8080|8443)\b",
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
    parsed = parse_real_url(url)

    if parsed["url"] == "N/A":
        return {
            "url": "N/A",
            "scheme": "N/A",
            "domain": "N/A",
            "port": "N/A",
            "https_status": "No URL",
            "is_risky": False,
            "note": "No URL was provided."
        }

    if parsed["is_https"]:
        return {
            "url": parsed["url"],
            "scheme": parsed["scheme"],
            "domain": parsed["domain"],
            "port": parsed["port"],
            "https_status": "HTTPS",
            "is_risky": False,
            "note": "HTTPS detected. Still inspect domain, Telegram source, and phishing context."
        }

    if parsed["is_http"]:
        return {
            "url": parsed["url"],
            "scheme": parsed["scheme"],
            "domain": parsed["domain"],
            "port": parsed["port"],
            "https_status": "HTTP",
            "is_risky": True,
            "note": "HTTP detected. Traffic is not encrypted; high phishing risk."
        }

    return {
        "url": parsed["url"],
        "scheme": parsed["scheme"],
        "domain": parsed["domain"],
        "port": parsed["port"],
        "https_status": "Unknown Protocol",
        "is_risky": True,
        "note": "Unknown or missing protocol."
    }


def check_port(port):
    if port is None or str(port).strip() == "" or str(port) == "N/A":
        return {
            "port": "N/A",
            "is_risky": False,
            "service": "No port",
            "recommendation": "No port was detected."
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
            "recommendation": "Known port. Continue inspection based on URL, Telegram source, and message context."
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
