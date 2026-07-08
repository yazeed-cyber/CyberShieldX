import os
import pandas as pd
import streamlit as st

INCIDENTS_FILE = "outputs/incidents_log.csv"
REPORTS_FILE = "outputs/reports_log.csv"
OTP_AUDIT_FILE = "outputs/otp_audit_log.csv"

def safe_load_csv(path):
    try:
        if os.path.exists(path):
            return pd.read_csv(path, encoding="utf-8", engine="python", on_bad_lines="skip")
        return pd.DataFrame()
    except Exception:
        return pd.DataFrame()

def render_admin_page():
    st.markdown("## 🛡️ Admin Control Panel")

    incidents_df = safe_load_csv(INCIDENTS_FILE)
    reports_df = safe_load_csv(REPORTS_FILE)
    otp_df = safe_load_csv(OTP_AUDIT_FILE)

    total_incidents = len(incidents_df)
    total_reports = len(reports_df)

    high_risk = 0
    if not incidents_df.empty and "risk_level" in incidents_df.columns:
        high_risk = (incidents_df["risk_level"].astype(str) == "High").sum()

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Incidents", total_incidents)
    c2.metric("Total Reports", total_reports)
    c3.metric("High Risk", high_risk)

    st.markdown("### Incident Log")
    if incidents_df.empty:
        st.info("No incidents found.")
    else:
        st.dataframe(incidents_df, use_container_width=True, height=300)

    st.markdown("### Victim Reports")
    if reports_df.empty:
        st.info("No reports found.")
    else:
        st.dataframe(reports_df, use_container_width=True, height=300)

    st.markdown("### OTP Audit Logs")
    if otp_df.empty:
        st.info("No OTP audit logs found.")
    else:
        st.dataframe(otp_df, use_container_width=True, height=300)
