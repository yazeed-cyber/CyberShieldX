import csv
import uuid
import socket
import platform
import hashlib
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TRACKING_FILE = PROJECT_ROOT / "outputs" / "real_user_tracking.csv"


def ensure_outputs():
    (PROJECT_ROOT / "outputs").mkdir(exist_ok=True)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"


def get_device_fingerprint():
    raw = f"{socket.gethostname()}-{uuid.getnode()}-{platform.system()}-{platform.machine()}"
    return "DEV-" + hashlib.sha256(raw.encode()).hexdigest()[:20].upper()


def get_session_id():
    raw = f"{datetime.now().date()}-{get_device_fingerprint()}"
    return "SES-" + hashlib.sha256(raw.encode()).hexdigest()[:16].upper()


def save_tracking_event(row):
    ensure_outputs()
    exists = TRACKING_FILE.exists()

    with open(TRACKING_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def build_tracking_event(
    platform_name,
    uid,
    sender_id,
    sender_name,
    chat_id,
    chat_title,
    chat_type,
    message_id,
    message_text,
    urls,
    ports,
    risk,
    threat_type,
    matched_rules,
    alert,
):
    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform": platform_name,
        "session_id": get_session_id(),
        "device_fingerprint": get_device_fingerprint(),
        "local_ip": get_local_ip(),

        "uid": uid,
        "telegram_sender_id": sender_id,
        "sender_name": sender_name,

        "telegram_chat_id": chat_id,
        "chat_title": chat_title,
        "chat_type": chat_type,

        "message_id": message_id,
        "message_text": message_text,

        "urls": ", ".join(urls) if isinstance(urls, list) else str(urls),
        "ports": ", ".join(map(str, ports)) if isinstance(ports, list) else str(ports),

        "risk": risk,
        "threat_type": threat_type,
        "matched_rules": matched_rules,
        "alert": alert,
    }
