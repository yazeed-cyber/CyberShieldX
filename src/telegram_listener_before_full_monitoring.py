import os
import csv
import asyncio
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

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
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def analyze_url_items(https_checks):
    items = []
    for item in https_checks:
        items.append(
            f'{item.get("url","")} | domain={item.get("domain","")} | '
            f'scheme={item.get("scheme","")} | port={item.get("port","")} | '
            f'status={item.get("https_status","")} | risky={item.get("is_risky","")}'
        )
    return " || ".join(items)


def analyze_port_items(port_checks):
    items = []
    for item in port_checks:
        items.append(
            f'port={item.get("port","")} | service={item.get("service","")} | '
            f'risky={item.get("is_risky","")} | recommendation={item.get("recommendation","")}'
        )
    return " || ".join(items)


client = TelegramClient(SESSION_NAME, API_ID, API_HASH)


@client.on(events.NewMessage)
async def handler(event):
    msg = event.message
    text = msg.message or ""

    if not text.strip():
        return

    telegram_uid = event.sender_id
    chat_id = event.chat_id
    message_id = msg.id

    uid = f"TG-{telegram_uid}"

    result = analyze_doctor_requirements(
        uid=uid,
        text=text,
        port="",
        url="",
        search_filter=""
    )

    urls = result.get("auto_detected_urls", [])
    ports = result.get("auto_detected_ports", [])
    https_checks = result.get("https_checks", [])
    port_checks = result.get("port_checks", [])

    row = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform": "telegram",
        "uid": uid,
        "telegram_sender_id": telegram_uid,
        "telegram_chat_id": chat_id,
        "telegram_message_id": message_id,
        "message_text": text,
        "risk": result.get("risk", ""),
        "score": result.get("score", ""),
        "alert": result.get("alert", ""),
        "matched_rules": result.get("matched_rules", ""),
        "urls": ", ".join(urls),
        "ports": ", ".join(map(str, ports)),
        "url_analysis": analyze_url_items(https_checks),
        "port_analysis": analyze_port_items(port_checks),
        "phishing": result.get("phishing", ""),
        "social_engineering": result.get("social", ""),
        "telegram_indicators": result.get("telegram", ""),
    }

    append_row(row)

    print("=" * 90)
    print(f"[Telegram Real Message]")
    print(f"UID={uid}")
    print(f"Telegram Sender ID={telegram_uid}")
    print(f"Chat ID={chat_id}")
    print(f"Message ID={message_id}")
    print(f"Risk={row['risk']} | Score={row['score']} | Alert={row['alert']}")
    print(f"Matched Rules={row['matched_rules']}")
    print(f"URLs={row['urls']}")
    print(f"Ports={row['ports']}")
    print(f"URL Analysis={row['url_analysis']}")
    print(f"Port Analysis={row['port_analysis']}")
    print(f"Text={text}")
    print("=" * 90)


async def main():
    print("[CyberShieldX] Telegram listener started.")
    print("[CyberShieldX] Waiting for real Telegram messages...")
    await client.start()
    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
