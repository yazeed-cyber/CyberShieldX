import os
import time
import random
import csv
from datetime import datetime

import requests

OTP_VALIDITY_SECONDS = 120
OTP_RESEND_COOLDOWN_SECONDS = 30
MAX_OTP_ATTEMPTS = 3
LOCKOUT_SECONDS = 60
OTP_AUDIT_FILE = "outputs/otp_audit_log.csv"


def generate_otp_code(length=6):
    return "".join(str(random.randint(0, 9)) for _ in range(length))


def session_expired(login_time, timeout_seconds=300):
    if login_time is None:
        return False
    return (time.time() - login_time) > timeout_seconds


def otp_code_expired(otp_created_at):
    if otp_created_at is None:
        return True
    return (time.time() - otp_created_at) > OTP_VALIDITY_SECONDS


def resend_cooldown_active(last_sent_at):
    if last_sent_at is None:
        return False
    return (time.time() - last_sent_at) < OTP_RESEND_COOLDOWN_SECONDS


def cooldown_remaining(last_sent_at):
    if last_sent_at is None:
        return 0
    remaining = OTP_RESEND_COOLDOWN_SECONDS - (time.time() - last_sent_at)
    return max(0, int(remaining))


def lockout_active(lockout_until):
    if lockout_until is None:
        return False
    return time.time() < lockout_until


def lockout_remaining(lockout_until):
    if lockout_until is None:
        return 0
    remaining = lockout_until - time.time()
    return max(0, int(remaining))


def mask_destination(destination, channel):
    destination = str(destination).strip()

    if channel == "email":
        if "@" not in destination:
            return destination
        name, domain = destination.split("@", 1)
        if len(name) <= 2:
            masked_name = name[0] + "*"
        else:
            masked_name = name[:2] + "*" * max(2, len(name) - 2)
        return f"{masked_name}@{domain}"

    if channel == "sms":
        if len(destination) <= 4:
            return "*" * len(destination)
        return "*" * (len(destination) - 4) + destination[-4:]

    return destination


def write_otp_audit(action, channel, destination, status, details=""):
    os.makedirs("outputs", exist_ok=True)
    exists = os.path.isfile(OTP_AUDIT_FILE)

    with open(OTP_AUDIT_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)

        if not exists:
            writer.writerow([
                "time",
                "action",
                "channel",
                "destination",
                "status",
                "details",
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            action,
            channel,
            destination,
            status,
            details,
        ])


def send_email_otp(recipient_email, otp_code):
    api_key = os.getenv("RESEND_API_KEY")
    from_email = os.getenv("RESEND_FROM_EMAIL")

    if not api_key or not from_email:
        raise ValueError("Resend credentials are not configured.")

    payload = {
        "from": from_email,
        "to": [recipient_email],
        "subject": "CyberShieldX OTP Code",
        "html": f"""
            <div style="font-family:Segoe UI,Arial,sans-serif;line-height:1.6">
                <h2>CyberShieldX Verification</h2>
                <p>Your OTP code is:</p>
                <div style="font-size:32px;font-weight:800;letter-spacing:4px">{otp_code}</div>
                <p>This code expires in {OTP_VALIDITY_SECONDS} seconds.</p>
            </div>
        """,
    }

    response = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=20,
    )

    if response.status_code >= 300:
        raise ValueError(f"Resend API error: {response.text}")

    return True


def send_sms_verification(phone_number):
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    verify_service_sid = os.getenv("TWILIO_VERIFY_SERVICE_SID")

    if not all([account_sid, auth_token, verify_service_sid]):
        raise ValueError("Twilio Verify credentials are not configured.")

    from twilio.rest import Client

    client = Client(account_sid, auth_token)

    verification = (
        client.verify.v2.services(verify_service_sid)
        .verifications
        .create(to=phone_number, channel="sms")
    )

    return verification.status


def check_sms_verification(phone_number, code):
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    verify_service_sid = os.getenv("TWILIO_VERIFY_SERVICE_SID")

    if not all([account_sid, auth_token, verify_service_sid]):
        raise ValueError("Twilio Verify credentials are not configured.")

    from twilio.rest import Client

    client = Client(account_sid, auth_token)

    verification_check = (
        client.verify.v2.services(verify_service_sid)
        .verification_checks
        .create(to=phone_number, code=code)
    )

    return verification_check.status == "approved"
