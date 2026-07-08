import os
import csv
from datetime import datetime
import streamlit as st
from src.detection_engine import detect_threat

REPORTS_FILE = "outputs/reports_log.csv"


def save_report(data):
    os.makedirs("outputs", exist_ok=True)
    exists = os.path.isfile(REPORTS_FILE)

    with open(REPORTS_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)

        if not exists:
            writer.writerow([
                "time",
                "full_name",
                "phone",
                "email",
                "case_type_selected",
                "incident_text",
                "extra_notes",
                "predicted_label",
                "risk_level",
                "main_law",
                "alert_status"
            ])

        writer.writerow(data)


def render_victim_page():
    st.markdown("## 🚨 Victim Reporting Page")
    st.write("Submit a cyber incident report for analysis, legal mapping, and review.")

    full_name = st.text_input("Full Name")
    phone = st.text_input("Phone Number")
    email = st.text_input("Email Address")

    case_type_selected = st.selectbox(
        "Type of Case",
        ["ابتزاز", "تحرش", "تشهير", "احتيال", "تهديد", "رابط مشبوه", "أخرى"]
    )

    incident_text = st.text_area("Incident Text / Message", height=220)
    extra_notes = st.text_area("Additional Notes", height=120)

    if st.button("Submit Report", use_container_width=True):
        if not incident_text.strip():
            st.error("Please enter the incident text first.")
            return

        try:
            result = detect_threat(incident_text.strip())

            save_report([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                full_name,
                phone,
                email,
                case_type_selected,
                incident_text,
                extra_notes,
                result.get("predicted_label", ""),
                result.get("risk_level", ""),
                result.get("main_law", ""),
                result.get("alert_status", "")
            ])

            st.success("Report submitted successfully.")
            st.write("**Predicted Label:**", result.get("predicted_label", ""))
            st.write("**Risk Level:**", result.get("risk_level", ""))
            st.write("**Jordanian Law Applied:**", result.get("main_law", ""))
            st.write("**Explanation:**", result.get("case_explanation", ""))
            st.write("**Alert Status:**", result.get("alert_status", ""))

        except Exception as e:
            st.error(f"Failed to submit report: {e}")
