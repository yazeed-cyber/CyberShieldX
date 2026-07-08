import os
import csv
import requests
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ALERTS_FILE = PROJECT_ROOT / "outputs" / "realtime_alerts.csv"


def ensure_outputs():
    (PROJECT_ROOT / "outputs").mkdir(exist_ok=True)


def save_alert(alert):
    ensure_outputs()
    exists = ALERTS_FILE.exists()

    with open(ALERTS_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(alert.keys()))
        if not exists:
            writer.writeheader()
        writer.writerow(alert)


def send_email_alert(subject, html_body):
    api_key = os.getenv("RESEND_API_KEY")
    from_email = os.getenv("RESEND_FROM_EMAIL")
    to_email = os.getenv("ALERT_EMAIL_TO")

    if not api_key or not from_email or not to_email:
        return False, "Email alert credentials are not configured"

    response = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "from": from_email,
            "to": [to_email],
            "subject": subject,
            "html": html_body,
        },
        timeout=20,
    )

    if response.status_code >= 300:
        return False, response.text

    return True, "Email alert sent"


def send_telegram_alert(message):
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_ALERT_CHAT_ID")

    if not bot_token or not chat_id:
        return False, "Telegram bot credentials are not configured"

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    response = requests.post(
        url,
        json={
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": False,
        },
        timeout=20,
    )

    if response.status_code >= 300:
        return False, response.text

    return True, "Telegram alert sent"


def should_alert(risk, matched_rules):
    risk = str(risk or "").lower()
    rules = str(matched_rules or "").lower()

    if risk == "high":
        return True

    keywords = [
        "phishing",
        "blackmail",
        "ابتزاز",
        "suspicious url",
        "https/http",
        "port rule",
        "dangerous port",
        "telegram rule",
        "social engineering",
    ]

    return any(k in rules for k in keywords)


def trigger_realtime_alert(source, uid, risk, score, matched_rules, text, urls="", ports="", chat_title="", sender_name=""):
    if not should_alert(risk, matched_rules):
        return {
            "alert_triggered": False,
            "email_status": "not_required",
            "telegram_status": "not_required",
        }

    alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    subject = f"CyberShieldX Alert - {risk} Risk Detected"

    html_body = f"""
    <div style="font-family:Segoe UI,Arial,sans-serif;line-height:1.6">
        <h2>🚨 CyberShieldX Real-Time Alert</h2>
        <p><b>Time:</b> {alert_time}</p>
        <p><b>Source:</b> {source}</p>
        <p><b>UID:</b> {uid}</p>
        <p><b>Risk:</b> {risk}</p>
        <p><b>Score:</b> {score}</p>
        <p><b>Matched Rules:</b> {matched_rules}</p>
        <p><b>URLs:</b> {urls}</p>
        <p><b>Ports:</b> {ports}</p>
        <p><b>Chat:</b> {chat_title}</p>
        <p><b>Sender:</b> {sender_name}</p>
        <hr>
        <p><b>Message:</b></p>
        <p>{text}</p>
    </div>
    """

    telegram_message = f"""
🚨 <b>CyberShieldX Real-Time Alert</b>

<b>Time:</b> {alert_time}
<b>Source:</b> {source}
<b>UID:</b> {uid}
<b>Risk:</b> {risk}
<b>Score:</b> {score}
<b>Matched Rules:</b> {matched_rules}

<b>URLs:</b> {urls}
<b>Ports:</b> {ports}
<b>Chat:</b> {chat_title}
<b>Sender:</b> {sender_name}

<b>Message:</b>
{text[:900]}
"""

    email_ok, email_msg = send_email_alert(subject, html_body)
    telegram_ok, telegram_msg = send_telegram_alert(telegram_message)

    alert = {
        "time": alert_time,
        "source": source,
        "uid": uid,
        "risk": risk,
        "score": score,
        "matched_rules": matched_rules,
        "urls": urls,
        "ports": ports,
        "chat_title": chat_title,
        "sender_name": sender_name,
        "message_text": text,
        "email_status": email_msg,
        "telegram_status": telegram_msg,
    }

    save_alert(alert)

    return {
        "alert_triggered": True,
        "email_status": email_msg,
        "telegram_status": telegram_msg,
    }
