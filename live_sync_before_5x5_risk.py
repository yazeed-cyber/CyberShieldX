import csv, re, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "outputs" / "telegram_live_dataset.csv"
OUT = ROOT / "outputs" / "dashboard_live_clean.csv"

HIGH_WORDS = [
    "ابتزاز", "ادفع", "تدفع", "سأقوم بنشر", "سأنشر", "بنشر صورك",
    "نشرت صورك", "صورك الخاصة", "فضيحة", "تهديد", "500 دينار",
    "لا تخبر أحد", "كود التحقق", "otp", "fake-login"
]

def fix_risk(text, ai_label, old_risk, old_score):
    full = f"{text} {ai_label}".lower()
    if any(w in full for w in HIGH_WORDS):
        return "High", "15", "CRITICAL_RISK_OVERRIDE"
    return old_risk or "Low", old_score or "0", ""

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
                old_score = r[12] if len(r) > 12 else "0"
                old_alert = r[13] if len(r) > 13 else ""
                ai_label = r[30] if len(r) > 30 else ""

                fixed_risk, fixed_score, fixed_alert = fix_risk(msg_text, ai_label, old_risk, old_score)
                if fixed_alert:
                    old_alert = fixed_alert

                rows.append([
                    r[0] if len(r)>0 else "",
                    r[1] if len(r)>1 else "",
                    r[2] if len(r)>2 else "",
                    r[6] if len(r)>6 else "",
                    msg_text,
                    fixed_risk,
                    fixed_score,
                    old_alert,
                    r[14] if len(r)>14 else "",
                    ai_label,
                    r[-2] if len(r)>2 else "",
                ])

            with OUT.open("w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["time","platform","uid","sender_name","text","risk","score","alert","matched_rules","ai_label","incident_id"])
                w.writerows(rows)

            print(f"synced {len(rows)} records", flush=True)

    except Exception as e:
        print("sync error:", e, flush=True)

    time.sleep(2)
