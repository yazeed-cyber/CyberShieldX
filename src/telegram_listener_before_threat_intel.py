import os
import csv
import asyncio
from datetime import datetime
from pathlib import Path

from telethon import TelegramClient, events

from src.doctor_rule_based import analyze_doctor_requirements
from src.alert_engine import trigger_realtime_alert

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUT_FILE = PROJECT_ROOT / "outputs" / "telegram_live_dataset.csv"

API_ID = int(os.getenv("TELEGRAM_API_ID", "0"))
API_HASH = os.getenv("TELEGRAM_API_HASH", "")
SESSION_NAME = os.getenv("TELEGRAM_SESSION_NAME", "cybershieldx_session")

if not API_ID or not API_HASH:
    raise ValueError("Set TELEGRAM_API_ID and TELEGRAM_API_HASH first.")

PROJECT_ROOT.joinpath("outputs").mkdir(exist_ok=True)


def append_row(row):
    exists = OUT_FILE.exists()

    with open(OUT_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))

        if not exists:
            writer.writeheader()

        writer.writerow(row)


def get_chat_type(event):
    if event.is_private:
        return "PRIVATE_CHAT"

    if event.is_group:
        return "GROUP"

    if event.is_channel:
        return "CHANNEL"

    return "UNKNOWN"


def detect_bot(entity):
    try:
        return bool(getattr(entity, "bot", False))
    except:
        return False


def safe_str(v):
    try:
        return str(v)
    except:
        return ""


client = TelegramClient(
    SESSION_NAME,
    API_ID,
    API_HASH
)


@client.on(events.NewMessage)
async def telegram_monitor(event):

    try:
        message = event.message
        text = message.message or ""

        if not text.strip():
            return

        sender = await event.get_sender()
        chat = await event.get_chat()

        sender_id = safe_str(event.sender_id)
        chat_id = safe_str(event.chat_id)
        message_id = safe_str(message.id)

        sender_name = (
            getattr(sender, "username", None)
            or getattr(sender, "first_name", None)
            or "Unknown"
        )

        chat_title = (
            getattr(chat, "title", None)
            or getattr(chat, "username", None)
            or getattr(chat, "first_name", None)
            or "Unknown"
        )

        chat_type = get_chat_type(event)
        is_bot = detect_bot(sender)

        uid = f"TG-{sender_id}"

        rule_result = analyze_doctor_requirements(
            uid=uid,
            text=text,
            port="",
            url="",
            search_filter=""
        )

        urls = rule_result.get("auto_detected_urls", [])
        ports = rule_result.get("auto_detected_ports", [])
        https_checks = rule_result.get("https_checks", [])
        port_checks = rule_result.get("port_checks", [])

        row = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            "platform": "telegram",

            "uid": uid,

            "chat_type": chat_type,

            "is_bot": is_bot,

            "sender_id": sender_id,
            "sender_name": sender_name,

            "chat_id": chat_id,
            "chat_title": chat_title,

            "message_id": message_id,

            "message_text": text,

            "risk": rule_result.get("risk", ""),
            "score": rule_result.get("score", ""),
            "alert": rule_result.get("alert", ""),

            "matched_rules": rule_result.get("matched_rules", ""),

            "urls": ", ".join(urls),
            "ports": ", ".join(map(str, ports)),

            "https_checks": safe_str(https_checks),
            "port_checks": safe_str(port_checks),

            "phishing": rule_result.get("phishing", ""),
            "social_engineering": rule_result.get("social", ""),
            "telegram_indicators": rule_result.get("telegram", ""),
        }

        alert_result = trigger_realtime_alert(
            source="telegram",
            uid=uid,
            risk=row.get("risk", ""),
            score=row.get("score", ""),
            matched_rules=row.get("matched_rules", ""),
            text=text,
            urls=row.get("urls", ""),
            ports=row.get("ports", ""),
            chat_title=chat_title,
            sender_name=sender_name,
        )

        row["alert_triggered"] = alert_result.get("alert_triggered", False)
        row["email_alert_status"] = alert_result.get("email_status", "")
        row["telegram_alert_status"] = alert_result.get("telegram_status", "")

        append_row(row)

        print("=" * 100)
        print("[CyberShieldX Telegram Monitor]")
        print(f"TYPE={chat_type}")
        print(f"BOT={is_bot}")
        print(f"UID={uid}")
        print(f"SENDER={sender_name}")
        print(f"CHAT={chat_title}")
        print(f"RISK={row['risk']}")
        print(f"SCORE={row['score']}")
        print(f"ALERT={row['alert']}")
        print(f"RULES={row['matched_rules']}")
        print(f"URLS={row['urls']}")
        print(f"PORTS={row['ports']}")
        print(f"TEXT={text}")
        print("=" * 100)

    except Exception as e:
        print(f"[ERROR] {e}")


async def startup_info():
    me = await client.get_me()

    print("=" * 100)
    print("[CyberShieldX]")
    print("Telegram Real-Time Monitoring Started")
    print(f"Logged in as: {me.first_name}")
    print("Monitoring:")
    print(" - Private Chats")
    print(" - Groups")
    print(" - Channels")
    print(" - Bots")
    print("=" * 100)


async def main():
    await client.start()
    await startup_info()
    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
