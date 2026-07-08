import re
import csv
import hashlib
from pathlib import Path
from datetime import datetime

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
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            email,
            event,
            status,
            details
        ])


def is_valid_email(email):
    email = str(email or "").strip().lower()
    return re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email) is not None


def check_password_strength(password):
    password = str(password or "").strip()

    weak_words = [
        "password",
        "admin",
        "123456",
        "12345678",
        "123456789",
        "qwerty",
        "cybershieldx",
        "yazeed",
        "test",
        "welcome",
        "kali"
    ]

    if len(password) < 12:
        return False, "Password must be at least 12 characters long."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."

    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\",.<>/?\\|]", password):
        return False, "Password must contain at least one special character."

    for word in weak_words:
        if word.lower() in password.lower():
            return False, f"Weak password detected: password must not contain '{word}'."

    return True, "Strong password accepted."


def hash_password(password):
    return hashlib.sha256(str(password or "").encode()).hexdigest()


def load_users():
    ensure_files()
    users = {}

    lines = AUTH_FILE.read_text(encoding="utf-8").splitlines()[1:]

    for line in lines:
        parts = line.split(",")
        if len(parts) >= 2:
            email = parts[0].strip().lower()
            password_hash = parts[1].strip()
            users[email] = password_hash

    return users


def create_user(email, password):
    email = str(email or "").strip().lower()

    if not is_valid_email(email):
        log_auth(email, "sign_in", "failed", "invalid email")
        return False, "Invalid email address."

    strong, msg = check_password_strength(password)

    if not strong:
        log_auth(email, "sign_in", "failed", msg)
        return False, msg

    users = load_users()

    if email in users:
        log_auth(email, "sign_in", "failed", "email already registered")
        return False, "This email is already registered. Use Login."

    ensure_files()

    with AUTH_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{email},{hash_password(password)},{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    log_auth(email, "sign_in", "success", "account created")
    return True, "Account created successfully with a strong password."


def validate_login(email, password):
    email = str(email or "").strip().lower()

    if not is_valid_email(email):
        log_auth(email, "login", "failed", "invalid email")
        return False, "Invalid email address."

    strong, msg = check_password_strength(password)

    if not strong:
        log_auth(email, "login", "failed", msg)
        return False, msg

    users = load_users()

    if email not in users:
        log_auth(email, "login", "failed", "email not registered")
        return False, "Email is not registered. Please Sign in first."

    if users[email] != hash_password(password):
        log_auth(email, "login", "failed", "wrong password")
        return False, "Invalid password."

    log_auth(email, "login", "success", "login successful")
    return True, "Login successful."


# Compatibility alias
def login_user(email, password):
    return validate_login(email, password)
