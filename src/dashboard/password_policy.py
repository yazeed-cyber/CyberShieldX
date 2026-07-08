import re

WEAK_WORDS = [
    "password",
    "admin",
    "qwerty",
    "123456",
    "123456789",
    "cybershieldx",
    "yazeed",
    "test",
    "kali",
]

def check_password_strength(password):
    password = password or ""
    errors = []

    if len(password) < 12:
        errors.append("Password must be at least 12 characters.")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")

    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one number.")

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\",.<>/?]", password):
        errors.append("Password must contain at least one special character.")

    for word in WEAK_WORDS:
        if word.lower() in password.lower():
            errors.append(f"Password must not contain weak word: {word}")

    if errors:
        return False, " ".join(errors)

    return True, "Strong password accepted."
