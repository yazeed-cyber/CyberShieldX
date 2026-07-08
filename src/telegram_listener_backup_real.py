import os
import csv
import asyncio
from datetime import datetime
from pathlib import Path

from telethon import TelegramClient, events

from src.doctor_rule_based import analyze_doctor_requirements

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUT_FILE = PROJECT_ROOT / "outputs" / "telegram_live_dataset.csv"

API_ID = int(os.getenv("TELEGRAM_API_ID", "0"))
API_HASH = os.getenv("TELEGRAM_API_HASH", "")
SESSION_NAME = os.getenv("TELEGRAM_SESSION_NAME", "cybershieldx_session")

if not API_ID or not API_HASH:
    raise ValueError("Set TELEGRAM_API_ID and TELEGRAM_API_HASH first.")


def append_row(row):
    PROJECT_ROOT.joinpath("outputs").mkdir(exist_ok=True)
    exists = OUT_FILE.exists()

    with open(OUT_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        if not exists:
            writer.writeheader()
        writer.writerow(row)


client = TelegramClient(SESSION_NAME, API_ID, API_HASH)


@client.on(events.NewMessage)
async def handler(event):
    msg = event.message
    text = msg.message or ""

    if not text.strip():
        return

    sender_id = event.sender_id
    chat_id = event.chat_id
    message_id = msg.id

    uid = f"TG-{sender_id}"

    rule_result = analyze_doctor_requirements(
        uid=uid,
        text=text,
        port="",
        url="",
        search_filter=""
    )

    row = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform": "telegram",
        "uid": uid,
        "sender_id": sender_id,
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "risk": rule_result.get("risk", ""),
        "score": rule_result.get("score", ""),
        "alert": rule_result.get("alert", ""),
        "matched_rules": rule_result.get("matched_rules", ""),
        "auto_urls": ", ".join(rule_result.get("auto_detected_urls", [])),
        "auto_ports": ", ".join(map(str, rule_result.get("auto_detected_ports", []))),
        "phishing": rule_result.get("phishing", ""),
        "social_engineering": rule_result.get("social", ""),
        "telegram_indicators": rule_result.get("telegram", ""),
    }

    append_row(row)

    print("=" * 70)
    print(f"[Telegram] Chat={chat_id} Sender={sender_id} Msg={message_id}")
    print(f"Risk={row['risk']} Score={row['score']} Alert={row['alert']}")
    print(f"Rules={row['matched_rules']}")
    print(f"Text={text[:200]}")


async def main():
    print("[CyberShieldX] Telegram listener started...")
    print("[CyberShieldX] Waiting for Telegram messages...")
    await client.start()
    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
