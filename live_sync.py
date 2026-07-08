import csv, re, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "outputs" / "telegram_live_dataset.csv"
OUT = ROOT / "outputs" / "dashboard_live_clean.csv"

HIGH_WORDS = [
    "ابتزاز", "ادفع", "تدفع", "سأقوم بنشر", "سأنشر",
    "بنشر صورك", "نشرت صورك", "صورك الخاصة",
    "فضيحة", "تهديد", "500 دينار", "لا تخبر أحد",
    "كود التحقق", "otp", "fake-login", "password"
]

MEDIUM_WORDS = [
    "رابط", "اضغط", "تحقق", "حسابك", "جائزة", "اربح", "login", "verify"
]

def risk_5x5(text, ai_label, old_risk):
    full = f"{text} {ai_label}".lower()

    if any(w in full for w in HIGH_WORDS):
        likelihood = 5
        impact = 5
    elif str(old_risk).lower() == "high":
        likelihood = 5
        impact = 4
    elif any(w in full for w in MEDIUM_WORDS) or str(old_risk).lower() == "medium":
        likelihood = 3
        impact = 3
    else:
        likelihood = 1
        impact = 2

    score = likelihood * impact

    if score <= 5:
        level = "Low"
    elif score <= 10:
        level = "Medium"
    elif score <= 15:
        level = "High"
    else:
        level = "Critical"

    return likelihood, impact, score, level

def split_records(text):
    return [p.strip() for p in re.split(r'\n(?=\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},)', text) if p.strip()]

while True:
    try:
        if SRC.exists():
            raw = SRC.read_text(encoding="utf-8", errors="ignore")
            records = split_records(raw)
            rows = []

            for rec in records[-300:]:
                try:
                    r = next(csv.reader([rec]))
                except:
                    continue

                msg_text = r[10] if len(r) > 10 else ""
                old_risk = r[11] if len(r) > 11 else "Low"
                old_alert = r[13] if len(r) > 13 else ""
                matched_rules = r[14] if len(r) > 14 else ""
                ai_label = r[30] if len(r) > 30 else ""
                incident_id = r[-2] if len(r) > 2 else ""

                likelihood, impact, score, level = risk_5x5(msg_text, ai_label, old_risk)

                if level in ["High", "Critical"]:
                    old_alert = "RISK_MATRIX_HIGH_ALERT"

                rows.append([
                    r[0] if len(r)>0 else "",
                    r[1] if len(r)>1 else "",
                    r[2] if len(r)>2 else "",
                    r[6] if len(r)>6 else "",
                    msg_text,
                    likelihood,
                    impact,
                    score,
                    level,
                    old_alert,
                    matched_rules,
                    ai_label,
                    incident_id,
                    "Risk = Likelihood × Impact"
                ])

            with OUT.open("w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow([
                    "time","platform","uid","sender_name","text",
                    "likelihood","impact","risk_score","risk",
                    "alert","matched_rules","ai_label","incident_id",
                    "risk_formula"
                ])
                w.writerows(rows)

            print(f"synced {len(rows)} records with 5x5 risk matrix", flush=True)

    except Exception as e:
        print("sync error:", e, flush=True)

    time.sleep(2)
