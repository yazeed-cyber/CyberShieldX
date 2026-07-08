import os
import re
import csv
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_FILE = PROJECT_ROOT / "data" / "cybershieldx_20k_full_arabic_UTF8.csv"
LOGIN_ALERTS_FILE = PROJECT_ROOT / "outputs" / "login_alerts.csv"
RULE_AUDIT_FILE = PROJECT_ROOT / "outputs" / "rule_based_audit.csv"


PHISHING_KEYWORDS = [
    "otp", "password", "login", "verify", "account", "bank", "urgent",
    "free", "gift", "click", "security", "wallet", "crypto",
    "كود", "رمز", "تحقق", "حسابك", "بنك", "اضغط", "رابط",
    "هدية", "مجاني", "عاجل", "تسجيل الدخول", "محفظة"
]

SOCIAL_ENGINEERING_KEYWORDS = [
    "send me", "trust me", "don't tell anyone", "secret",
    "ابعت", "ابعث", "لا تحكي", "لا تخبر", "سري", "خاص",
    "ثق فيني", "بسرعة", "ضروري", "حول", "ادفع"
]

TELEGRAM_KEYWORDS = [
    "telegram", "t.me", "telegram.me", "joinchat", "تلجرام", "تيليجرام"
]

RISKY_PORTS = {
    21: "FTP clear-text service",
    23: "Telnet insecure remote access",
    80: "HTTP unencrypted traffic",
    445: "SMB file sharing",
    3389: "RDP remote desktop",
    4444: "Common reverse shell port",
    8080: "Alternative web service / proxy"
}

NORMAL_PORTS = {
    22: "SSH remote access",
    25: "SMTP mail service",
    443: "HTTPS encrypted traffic"
}


def _ensure_outputs():
    (PROJECT_ROOT / "outputs").mkdir(exist_ok=True)


def _append_csv(path, header, row):
    _ensure_outputs()
    exists = path.exists()
    with open(path, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        if not exists:
            writer.writerow(header)
        writer.writerow(row)


def log_login_alert(uid, event_type, status, details=""):
    _append_csv(
        LOGIN_ALERTS_FILE,
        ["time", "uid", "event_type", "status", "details"],
        [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            uid or "UNKNOWN",
            event_type,
            status,
            details
        ]
    )


def log_rule_audit(uid, text, port, url, risk, score, matched):
    _append_csv(
        RULE_AUDIT_FILE,
        ["time", "uid", "text", "port", "url", "risk", "score", "matched_rules"],
        [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            uid,
            text,
            port,
            url,
            risk,
            score,
            matched
        ]
    )


@st.cache_data
def load_dataset_rules():
    if not DATASET_FILE.exists():
        return pd.DataFrame()

    try:
        df = pd.read_csv(DATASET_FILE, encoding="utf-8", engine="python", on_bad_lines="skip")
    except Exception:
        df = pd.read_csv(DATASET_FILE, encoding="utf-8-sig", engine="python", on_bad_lines="skip")

    df = df.fillna("")
    return df


def detect_text_column(df):
    candidates = [
        "text", "نص_الرسالة", "message", "raw_text", "normalized_text",
        "incident_text", "content"
    ]
    for col in candidates:
        if col in df.columns:
            return col

    for col in df.columns:
        if df[col].astype(str).str.len().mean() > 15:
            return col

    return df.columns[0] if len(df.columns) else None


def detect_label_column(df):
    candidates = [
        "label", "نوع_الحالة", "predicted_label", "case_type",
        "classification", "category"
    ]
    for col in candidates:
        if col in df.columns:
            return col
    return None


def extract_words(text):
    text = str(text).lower()
    words = re.findall(r"[\w\u0600-\u06FF]+", text)
    return [w for w in words if len(w) >= 4]


def contains_any(text, keywords):
    low = str(text).lower()
    return [k for k in keywords if k.lower() in low]


def extract_urls(text):
    return re.findall(r"(https?://[^\s]+|www\.[^\s]+|t\.me/[^\s]+)", str(text), re.IGNORECASE)


def check_https(url):
    if not url:
        return {
            "https_status": "No URL provided",
            "https_risk": False,
            "https_note": "No URL was entered."
        }

    url = str(url).strip()

    if url.startswith("https://"):
        return {
            "https_status": "HTTPS",
            "https_risk": False,
            "https_note": "HTTPS is used. Still inspect domain and content."
        }

    if url.startswith("http://"):
        return {
            "https_status": "HTTP",
            "https_risk": True,
            "https_note": "HTTP is not encrypted. Prefer HTTPS."
        }

    if "t.me" in url or "telegram" in url.lower():
        return {
            "https_status": "Telegram Link",
            "https_risk": False,
            "https_note": "Telegram link detected. Inspect for social engineering/phishing."
        }

    return {
        "https_status": "Unknown",
        "https_risk": True,
        "https_note": "URL format is unclear or missing protocol."
    }


def check_port(port):
    if port is None or str(port).strip() == "":
        return {
            "port": "N/A",
            "port_risk": False,
            "service": "No port provided",
            "recommendation": "No port selected."
        }

    try:
        p = int(str(port).strip())
    except ValueError:
        return {
            "port": str(port),
            "port_risk": False,
            "service": "Invalid port",
            "recommendation": "Enter a numeric port."
        }

    if p in RISKY_PORTS:
        return {
            "port": p,
            "port_risk": True,
            "service": RISKY_PORTS[p],
            "recommendation": "Investigate this port and restrict it if unnecessary."
        }

    if p in NORMAL_PORTS:
        return {
            "port": p,
            "port_risk": False,
            "service": NORMAL_PORTS[p],
            "recommendation": "Known service. Continue inspection based on context."
        }

    return {
        "port": p,
        "port_risk": False,
        "service": "Unknown/normal service",
        "recommendation": "No risky port rule matched."
    }


def dataset_rule_match(input_text):
    df = load_dataset_rules()

    if df.empty:
        return pd.DataFrame(), "Dataset not found", None, None

    text_col = detect_text_column(df)
    label_col = detect_label_column(df)

    if not text_col:
        return pd.DataFrame(), "No text column found", None, None

    input_words = set(extract_words(input_text))
    results = []

    for idx, row in df.iterrows():
        rule_text = str(row.get(text_col, ""))
        rule_words = set(extract_words(rule_text))

        if not rule_words:
            continue

        matched_words = input_words.intersection(rule_words)
        match_score = len(matched_words)

        if match_score > 0:
            results.append({
                "rule_id": idx,
                "match_score": match_score,
                "matched_words": ", ".join(list(matched_words)[:12]),
                "dataset_label": row.get(label_col, "") if label_col else "",
                "rule_text": rule_text[:300],
            })

    result_df = pd.DataFrame(results)

    if not result_df.empty:
        result_df = result_df.sort_values(by="match_score", ascending=False).head(20)

    return result_df, "OK", text_col, label_col


def analyze_required_rule_based(uid, text, port, url):
    if not uid or not str(uid).strip():
        return {
            "valid": False,
            "error": "UID is required.",
        }

    phishing_hits = contains_any(text, PHISHING_KEYWORDS)
    social_hits = contains_any(text, SOCIAL_ENGINEERING_KEYWORDS)
    telegram_hits = contains_any(text, TELEGRAM_KEYWORDS)

    detected_urls = extract_urls(text)
    if url:
        detected_urls.append(url)

    https_results = [check_https(u) for u in detected_urls] if detected_urls else [check_https(url)]
    port_result = check_port(port)
    dataset_matches, dataset_status, text_col, label_col = dataset_rule_match(text)

    score = 0
    score += len(phishing_hits) * 2
    score += len(social_hits) * 2
    score += len(telegram_hits) * 2

    if port_result["port_risk"]:
        score += 4

    if any(x["https_risk"] for x in https_results):
        score += 3

    if not dataset_matches.empty:
        score += min(6, int(dataset_matches.iloc[0]["match_score"]))

    matched_rules = []

    if phishing_hits:
        matched_rules.append("Phishing")
    if social_hits:
        matched_rules.append("Social Engineering")
    if telegram_hits:
        matched_rules.append("Telegram")
    if port_result["port_risk"]:
        matched_rules.append("Port Rule")
    if any(x["https_risk"] for x in https_results):
        matched_rules.append("HTTP/HTTPS Rule")
    if not dataset_matches.empty:
        matched_rules.append("Dataset Rule Match")

    if not matched_rules:
        matched_rules.append("No Rule Matched")

    if score >= 10:
        risk = "High"
        alert = "ALERT_TRIGGERED"
    elif score >= 5:
        risk = "Medium"
        alert = "SUSPICIOUS_ACTIVITY"
    else:
        risk = "Low"
        alert = "NO_CRITICAL_RULE_MATCH"

    log_rule_audit(
        uid=uid,
        text=text,
        port=port,
        url=url,
        risk=risk,
        score=score,
        matched=", ".join(matched_rules)
    )

    return {
        "valid": True,
        "uid": uid,
        "risk": risk,
        "score": score,
        "alert": alert,
        "matched_rules": ", ".join(matched_rules),
        "phishing_hits": ", ".join(phishing_hits),
        "social_hits": ", ".join(social_hits),
        "telegram_hits": ", ".join(telegram_hits),
        "detected_urls": detected_urls,
        "https_results": https_results,
        "port_result": port_result,
        "dataset_matches": dataset_matches,
        "dataset_status": dataset_status,
        "dataset_text_col": text_col,
        "dataset_label_col": label_col,
    }


def render_required_rule_based_center():
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">🧠 Required Rule-Based Detection Center</div>', unsafe_allow_html=True)

    st.write(
        "This module implements the required doctor notes: mandatory UID, login/sign-in alerting, rule-based text matching, dataset-as-rules matching, port check, HTTPS check, Telegram indicators, phishing, and social engineering detection."
    )

    uid = st.text_input(
        "UID / User ID",
        placeholder="Required. Example: user_202130045",
        key="required_uid"
    )

    message_text = st.text_area(
        "Message Text as Rule-Based Input",
        placeholder="Example: لا تخبر أحد، ابعتلي كود التحقق عبر تلجرام https://t.me/support_login",
        height=170,
        key="required_rule_text"
    )

    c1, c2 = st.columns(2)

    with c1:
        port = st.text_input(
            "Port Check",
            placeholder="Example: 443 / 80 / 3389 / 4444",
            key="required_port"
        )

    with c2:
        url = st.text_input(
            "HTTPS / URL Check",
            placeholder="Example: https://example.com/login",
            key="required_url"
        )

    if st.button("Run Required Rule-Based Check", use_container_width=True, key="required_run_rule_check"):
        result = analyze_required_rule_based(uid, message_text, port, url)

        if not result["valid"]:
            st.error(result["error"])
            st.markdown("</div>", unsafe_allow_html=True)
            return

        risk = result["risk"]
        risk_class = "risk-high" if risk == "High" else "risk-medium" if risk == "Medium" else "risk-low"

        st.markdown(
            f'<div class="risk-pill {risk_class}">{risk}</div>',
            unsafe_allow_html=True
        )

        if risk == "High":
            st.error("🚨 ALERT: High-risk rule-based match detected.")
        elif risk == "Medium":
            st.warning("⚠️ Suspicious activity detected by rule-based engine.")
        else:
            st.success("✅ No critical rule-based match detected.")

        k1, k2, k3, k4 = st.columns(4)

        with k1:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-label">UID</div>
                <div class="metric-value">OK</div>
                <div class="metric-sub">{result["uid"]}</div>
            </div>
            """, unsafe_allow_html=True)

        with k2:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-label">Rule Score</div>
                <div class="metric-value">{result["score"]}</div>
                <div class="metric-sub">Calculated rule score</div>
            </div>
            """, unsafe_allow_html=True)

        with k3:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-label">Alert</div>
                <div class="metric-value">ON</div>
                <div class="metric-sub">{result["alert"]}</div>
            </div>
            """, unsafe_allow_html=True)

        with k4:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-label">Port</div>
                <div class="metric-value">{result["port_result"]["port"]}</div>
                <div class="metric-sub">{result["port_result"]["service"]}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="explain-panel">
            <div class="panel-key">🎯 Matched Rule-Based Categories</div>
            <div class="panel-value">{result["matched_rules"]}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="explain-panel">
            <div class="panel-key">🎣 Phishing Indicators</div>
            <div class="panel-value">{result["phishing_hits"] or "None"}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="explain-panel">
            <div class="panel-key">👥 Social Engineering Indicators</div>
            <div class="panel-value">{result["social_hits"] or "None"}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="explain-panel">
            <div class="panel-key">✈️ Telegram Indicators</div>
            <div class="panel-value">{result["telegram_hits"] or "None"}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="law-panel">
            <div class="panel-key">🌐 Port Rule-Based Check</div>
            <div class="panel-value">
                Port: {result["port_result"]["port"]}<br>
                Service: {result["port_result"]["service"]}<br>
                Recommendation: {result["port_result"]["recommendation"]}
            </div>
        </div>
        """, unsafe_allow_html=True)

        if result["https_results"]:
            st.write("**HTTPS / URL Rule Check:**")
            st.dataframe(pd.DataFrame(result["https_results"]), use_container_width=True)

        if not result["dataset_matches"].empty:
            st.write("**Dataset Rows Matched as Rule-Based Rules:**")
            st.caption(
                f'Dataset text column: {result["dataset_text_col"]} | label column: {result["dataset_label_col"]}'
            )
            st.dataframe(result["dataset_matches"], use_container_width=True, height=350)
        else:
            st.info("No dataset rule matched this message.")

    st.markdown("</div>", unsafe_allow_html=True)


def render_login_alert_panel():
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">🔐 Login / Sign-in Alerts</div>', unsafe_allow_html=True)

    if LOGIN_ALERTS_FILE.exists():
        df = pd.read_csv(LOGIN_ALERTS_FILE, encoding="utf-8-sig")
        st.dataframe(df.tail(50), use_container_width=True, height=250)
    else:
        st.info("No login alerts recorded yet.")

    st.markdown("</div>", unsafe_allow_html=True)
