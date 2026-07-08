import csv
import random
import hashlib
from pathlib import Path
from datetime import datetime

from src.hybrid_detection_engine import analyze_hybrid
from src.incident_center import create_incident_from_telegram

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REDTEAM_FILE = PROJECT_ROOT / "outputs" / "red_team_simulation.csv"

SCENARIOS = [
    {
        "name": "Phishing Simulation",
        "attack_type": "phishing",
        "text": "اضغط على الرابط للتحقق من حسابك http://fake-login.com:8080/verify tcp/4444",
        "source": "telegram_campaign"
    },
    {
        "name": "Fake Login Detection",
        "attack_type": "fake_login",
        "text": "Your account is locked. Login now to verify your OTP http://secure-login-check.com/login",
        "source": "fake_login_page"
    },
    {
        "name": "Social Engineering",
        "attack_type": "social_engineering",
        "text": "لا تخبر أحد، ابعتلي كود التحقق بسرعة حتى أساعدك",
        "source": "private_chat"
    },
    {
        "name": "Blackmail Simulation",
        "attack_type": "blackmail",
        "text": "إذا ما دفعت 100 دينار رح أنشر صورك على تلجرام",
        "source": "telegram_private"
    },
    {
        "name": "Suspicious Telegram Campaign",
        "attack_type": "telegram_campaign",
        "text": "Join this Telegram support group t.me/support_login_verify and send your password",
        "source": "telegram_group"
    }
]


def ensure_outputs():
    (PROJECT_ROOT / "outputs").mkdir(exist_ok=True)


def make_sim_uid():
    return "RT-" + hashlib.sha256(str(datetime.now().timestamp()).encode()).hexdigest()[:10].upper()


def append_row(row):
    ensure_outputs()
    exists = REDTEAM_FILE.exists()

    with open(REDTEAM_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def run_single_simulation(scenario):
    uid = make_sim_uid()
    message_id = "SIM-" + hashlib.sha256((uid + scenario["text"]).encode()).hexdigest()[:8].upper()

    result = analyze_hybrid(
        uid=uid,
        text=scenario["text"],
        port="",
        url="",
        search_filter=""
    )

    row = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "simulation_id": message_id,
        "uid": uid,
        "source": scenario["source"],
        "scenario_name": scenario["name"],
        "attack_type": scenario["attack_type"],
        "message_text": scenario["text"],
        "risk": result.get("hybrid_risk", ""),
        "score": result.get("hybrid_score", ""),
        "alert": result.get("hybrid_alert", ""),
        "matched_rules": result.get("matched_rules", ""),
        "urls": ", ".join(result.get("auto_detected_urls", [])),
        "ports": ", ".join(map(str, result.get("auto_detected_ports", []))),
        "ai_label": result.get("ai_label", ""),
        "ai_risk": result.get("ai_risk", ""),
        "hybrid_reason": result.get("hybrid_reason", "")
    }

    incident_row = {
        "uid": uid,
        "message_id": message_id,
        "message_text": scenario["text"],
        "risk": row["risk"],
        "alert": row["alert"],
        "matched_rules": row["matched_rules"],
        "urls": row["urls"],
        "ports": row["ports"],
        "sender_id": uid,
        "sender_name": "RedTeamSimulator",
        "chat_id": "SIMULATED",
        "chat_title": scenario["source"],
        "chat_type": "RED_TEAM_SIMULATION",
        "ai_label": row["ai_label"],
        "ai_risk": row["ai_risk"],
        "ai_confidence": "",
        "hybrid_risk": row["risk"],
        "hybrid_score": row["score"],
        "hybrid_reason": row["hybrid_reason"],
        "rule_risk": "",
        "rule_score": "",
    }

    incident_result = create_incident_from_telegram(incident_row)

    row["incident_created"] = incident_result.get("created", False)
    row["incident_id"] = incident_result.get("incident_id", "")

    append_row(row)
    return row


def run_all_simulations():
    results = []
    for scenario in SCENARIOS:
        results.append(run_single_simulation(scenario))
    return results


def run_random_simulation():
    return run_single_simulation(random.choice(SCENARIOS))
