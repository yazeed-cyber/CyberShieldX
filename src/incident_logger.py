import os
import csv
from datetime import datetime

FILE = "outputs/incidents_log.csv"


def save_incident(incident):
    os.makedirs("outputs", exist_ok=True)
    exists = os.path.isfile(FILE)

    with open(FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)

        if not exists:
            writer.writerow([
                "time",
                "original_text",
                "cleaned_text",
                "predicted_label",
                "confidence_score",
                "risk_level",
                "main_law",
                "all_laws",
                "law_count",
                "alert_status",
                "case_explanation"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            incident.get("original_text", ""),
            incident.get("cleaned_text", ""),
            incident.get("predicted_label", ""),
            incident.get("confidence_score", ""),
            incident.get("risk_level", ""),
            incident.get("main_law", ""),
            incident.get("all_laws", ""),
            incident.get("law_count", 1),
            incident.get("alert_status", ""),
            incident.get("case_explanation", ""),
        ])
