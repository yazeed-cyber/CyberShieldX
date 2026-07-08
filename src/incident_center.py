import csv
import hashlib
from pathlib import Path
from datetime import datetime
from src.jordanian_law_engine import detect_law_case

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INCIDENT_FILE = PROJECT_ROOT / "outputs" / "incident_center.csv"


def ensure_outputs():
    (PROJECT_ROOT / "outputs").mkdir(exist_ok=True)


def make_incident_id(uid, message_id, text):
    raw = f"{uid}-{message_id}-{text}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    return "INC-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()


def map_jordanian_law(threat_type, matched_rules, text):
    law_result = detect_law_case(
        text=text,
        matched_rules=matched_rules,
        ai_label=threat_type
    )

    return {
        "law_category": law_result.get("crime", ""),
        "law_reference": law_result.get("article", ""),
        "legal_note": law_result.get("legal_mapping", ""),
        "penalty": law_result.get("penalty", ""),
        "law_severity": law_result.get("severity", ""),
        "matched_keywords": law_result.get("matched_keywords", ""),
    }


def should_create_incident(risk, alert, matched_rules):
    risk = str(risk or "").lower()
    alert = str(alert or "").lower()
    matched_rules = str(matched_rules or "").lower()

    if risk in ["high", "critical"]:
        return True

    if "alert" in alert:
        return True

    important_rules = [
        "phishing",
        "blackmail",
        "social engineering",
        "port rule",
        "https/http",
        "telegram",
        "dataset rule-based match"
    ]

    return any(rule in matched_rules for rule in important_rules)


def save_incident(row):
    ensure_outputs()
    exists = INCIDENT_FILE.exists()

    with open(INCIDENT_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))

        if not exists:
            writer.writeheader()

        writer.writerow(row)


def create_incident_from_telegram(row):
    risk = row.get("risk", "")
    alert = row.get("alert", "")
    matched_rules = row.get("matched_rules", "")

    if not should_create_incident(risk, alert, matched_rules):
        return {
            "created": False,
            "incident_id": "",
            "reason": "No incident threshold matched"
        }

    uid = row.get("uid", "")
    message_id = row.get("message_id", "") or row.get("telegram_message_id", "")
    text = row.get("message_text", "")

    incident_id = make_incident_id(uid, message_id, text)

    threat_type = (
        row.get("ai_label", "")
        or row.get("threat_type", "")
        or row.get("matched_rules", "")
    )

    law = map_jordanian_law(threat_type, matched_rules, text)

    incident = {
        "incident_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "incident_id": incident_id,
        "status": "Open",
        "severity": risk,
        "risk_level": risk,
        "alert": alert,

        "telegram_uid": uid,
        "telegram_sender_id": row.get("sender_id", "") or row.get("telegram_sender_id", ""),
        "sender_name": row.get("sender_name", ""),
        "telegram_chat_id": row.get("chat_id", "") or row.get("telegram_chat_id", ""),
        "chat_title": row.get("chat_title", ""),
        "chat_type": row.get("chat_type", ""),
        "message_id": message_id,

        "evidence_text": text,
        "evidence_urls": row.get("urls", ""),
        "evidence_ports": row.get("ports", ""),
        "evidence_rules": matched_rules,

        "ai_classification": row.get("ai_label", ""),
        "ai_risk": row.get("ai_risk", ""),
        "ai_confidence": row.get("ai_confidence", ""),

        "hybrid_risk": row.get("hybrid_risk", ""),
        "hybrid_score": row.get("hybrid_score", ""),
        "hybrid_reason": row.get("hybrid_reason", ""),

        "rule_risk": row.get("rule_risk", ""),
        "rule_score": row.get("rule_score", ""),

        "law_category": law["law_category"],
        "law_reference": law["law_reference"],
        "legal_penalty": law.get("penalty", ""),
        "law_severity": law.get("law_severity", ""),
        "law_matched_keywords": law.get("matched_keywords", ""),
        "legal_note": law["legal_note"],

        "analyst_action": "Review evidence, verify source, preserve logs, and escalate if confirmed."
    }

    save_incident(incident)

    return {
        "created": True,
        "incident_id": incident_id,
        "reason": "Incident created"
    }
