import asyncio
from telethon import TelegramClient, events

from src.detection_engine import detect_threat

# ---------------------------------
# Telegram API credentials
# ---------------------------------
api_id = 33947174             # <-- حط api_id تبعك هنا
api_hash = "4b2d6fe22f51cf212d1e2f03a12c3c7a"    # <-- حط api_hash تبعك هنا
session_name = "cybershieldx_session"

# ---------------------------------
# Create client
# ---------------------------------
client = TelegramClient(session_name, api_id, api_hash)

# ---------------------------------
# Event handler: any new incoming message
# ---------------------------------
@client.on(events.NewMessage(incoming=True))
async def handle_new_message(event):
    try:
        message_text = event.raw_text.strip()

        if not message_text:
            return

        print("\n=== New Telegram Message ===")
        print(message_text)

        result = detect_threat(message_text)

        print("=== Detection Result ===")
        for key, value in result.items():
            print(f"{key}: {value}")
        print("-" * 60)

    except Exception as e:
        print(f"Error processing message: {e}")

# ---------------------------------
# Main runner
# ---------------------------------
async def main():
    print("CyberShieldX Telegram listener is running...")
    print("Waiting for new Telegram messages...")
    await client.run_until_disconnected()

with client:
    client.loop.run_until_complete(main())
