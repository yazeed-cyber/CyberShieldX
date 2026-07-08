import re
import csv
import random
import smtplib
import hashlib
import os
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText

AUTH_FILE = Path("outputs/auth_users.csv")
AUTH_LOG = Path("outputs/auth_log.csv")


def ensure_files():
    AUTH_FILE.parent.mkdir(exist_ok=True)

    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("email,password_hash,created_at\n", encoding="utf-8")

    if not AUTH_LOG.exists():
        AUTH_LOG.write_text("time,email,event,status,details\n", encoding="utf-8")


def log_auth(email, event, status, details=""):
    ensure_files()

    with AUTH_LOG.open("a", newline="", encoding="utf-8-sig") as f:
        csv.writer(f).writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            email,
            event,
            status,
            details
        ])


def is_valid_email(email):
    return re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email or "") is not None


def check_password_strength(password):
    password = password or ""
    errors = []

    if len(password) < 12:
        errors.append("minimum 12 characters")

    if not re.search(r"[A-Z]", password):
        errors.append("uppercase letter")

    if not re.search(r"[a-z]", password):
        errors.append("lowercase letter")

    if not re.search(r"[0-9]", password):
        errors.append("number")

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\",.<>/?]", password):
        errors.append("special character")

    weak_words = [
        "password", "admin", "qwerty", "123456",
        "cybershieldx", "yazeed", "kali", "test"
    ]

    for word in weak_words:
        if word in password.lower():
            errors.append(f"must not contain weak word: {word}")

    if errors:
        return False, "Weak password. Required: " + " | ".join(errors)

    return True, "Strong password accepted."


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def load_users():
    ensure_files()
    users = {}

    for line in AUTH_FILE.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split(",")
        if len(parts) >= 2:
            users[parts[0].strip().lower()] = parts[1].strip()

    return users


def create_user(email, password):
    email = (email or "").strip().lower()

    if not is_valid_email(email):
        log_auth(email, "sign_in", "failed", "invalid email")
        return False, "Enter a valid email address."

    strong, msg = check_password_strength(password)

    if not strong:
        log_auth(email, "sign_in", "failed", msg)
        return False, msg

    users = load_users()

    if email in users:
        log_auth(email, "sign_in", "failed", "already registered")
        return False, "This email is already registered. Use Login."

    with AUTH_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{email},{hash_password(password)},{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    log_auth(email, "sign_in", "success", "account created")
    return True, "Account created successfully."


def validate_login(email, password):
    email = (email or "").strip().lower()

    if not is_valid_email(email):
        log_auth(email, "login", "failed", "invalid email")
        return False, "Enter a valid email address."

    strong, msg = check_password_strength(password)

    if not strong:
        log_auth(email, "login", "failed", msg)
        return False, msg

    users = load_users()

    if email not in users:
        log_auth(email, "login", "failed", "not registered")
        return False, "Email is not registered. Please Sign in first."

    if users[email] != hash_password(password):
        log_auth(email, "login", "failed", "wrong password")
        return False, "Invalid password."

    log_auth(email, "login", "password_ok", "password verified")
    return True, "Password verified."


def generate_otp():
    return str(random.randint(100000, 999999))


def send_email_otp(to_email, otp):
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_email = os.getenv("SMTP_EMAIL", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")

    if not smtp_email or not smtp_password:
        return False, "SMTP credentials are not configured."

    body = f"""CyberShieldX MFA Verification

Your OTP code is: {otp}

This code expires in 5 minutes.
"""

    msg = MIMEText(body)
    msg["Subject"] = "CyberShieldX OTP Verification"
    msg["From"] = smtp_email
    msg["To"] = to_email

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=20)
        server.starttls()
        server.login(smtp_email, smtp_password)
        server.sendmail(smtp_email, [to_email], msg.as_string())
        server.quit()

        log_auth(to_email, "otp", "sent", "email otp sent")
        return True, "OTP sent successfully."
    except Exception as e:
        log_auth(to_email, "otp", "failed", str(e))
        return False, f"Failed to send OTP: {e}"
