import os
import time
import csv
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from src.dashboard.otp_security import (
    generate_otp_code,
    send_email_otp,
    send_sms_verification,
    check_sms_verification,
    session_expired,
    otp_code_expired,
    resend_cooldown_active,
    cooldown_remaining,
    lockout_active,
    lockout_remaining,
    mask_destination,
    write_otp_audit,
    OTP_VALIDITY_SECONDS,
    MAX_OTP_ATTEMPTS,
    LOCKOUT_SECONDS,
)

INCIDENTS_FILE = "outputs/incidents_log.csv"
DATASET_FILE = "data/cybershieldx_20k_full_arabic_UTF8.csv"
OTP_AUDIT_FILE = "outputs/otp_audit_log.csv"
REPORTS_FILE = "outputs/reports_log.csv"
SESSION_TIMEOUT_SECONDS = 300

st.set_page_config(
    page_title="CyberShieldX Secure Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DEFAULTS = {
    "authenticated": False,
    "login_time": None,
    "otp_code": None,
    "otp_attempts": 0,
    "otp_created_at": None,
    "otp_last_sent_at": None,
    "lockout_until": None,
    "last_channel": None,
    "last_destination": None,
    "otp_delivery_channel": None,
}

for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


@st.cache_data
def load_csv(file_path: str) -> pd.DataFrame:
    try:
        if os.path.exists(file_path):
            return pd.read_csv(file_path, encoding="utf-8", engine="python", on_bad_lines="skip")
        return pd.DataFrame()
    except Exception:
        return pd.DataFrame()


def refresh_data():
    load_csv.clear()


def safe_text(value):
    if pd.isna(value):
        return ""
    return str(value)


def get_risk_pill_class(risk_value: str) -> str:
    value = safe_text(risk_value).strip().lower()
    if value == "high":
        return "risk-high"
    if value == "medium":
        return "risk-medium"
    return "risk-low"


def save_report_row(row):
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
                "alert_status",
            ])

        writer.writerow(row)


def analyze_message_runtime(text):
    from src.detection_engine import detect_threat
    return detect_threat(text)


def send_otp_with_fallback(channel, phone, email):
    if channel == "sms":
        if not phone:
            st.error("Please enter a phone number.")
            return False, ""

        try:
            status = send_sms_verification(phone)
            write_otp_audit("send_otp", "sms", phone, "success", str(status))

            st.success("OTP sent via SMS ✔️")
            st.session_state.last_channel = "sms"
            st.session_state.last_destination = phone
            st.session_state.otp_delivery_channel = "sms"

            return True, "sms"

        except Exception as sms_error:
            write_otp_audit("send_otp", "sms", phone, "failed", str(sms_error))

            if email:
                try:
                    code = generate_otp_code()
                    st.session_state.otp_code = code

                    send_email_otp(email, code)

                    write_otp_audit(
                        "send_otp",
                        "email",
                        email,
                        "fallback_success",
                        "auto_fallback_from_sms",
                    )

                    st.warning("⚠️ SMS failed. OTP was sent automatically via Email.")
                    st.session_state.last_channel = "email"
                    st.session_state.last_destination = email
                    st.session_state.otp_delivery_channel = "email"

                    return True, "email"

                except Exception as email_error:
                    write_otp_audit("send_otp", "email", email, "fallback_failed", str(email_error))
                    st.error(f"Both SMS and Email failed: {email_error}")
                    return False, ""

            st.error("SMS OTP failed and no email was provided for fallback.")
            return False, ""

    if not email:
        st.error("Please enter an email address.")
        return False, ""

    try:
        code = generate_otp_code()
        st.session_state.otp_code = code

        send_email_otp(email, code)

        write_otp_audit("send_otp", "email", email, "success", "email_sent")

        st.success("OTP sent via Email ✔️")
        st.session_state.last_channel = "email"
        st.session_state.last_destination = email
        st.session_state.otp_delivery_channel = "email"

        return True, "email"

    except Exception as email_error:
        write_otp_audit("send_otp", "email", email, "failed", str(email_error))
        st.error(f"Failed to send Email OTP: {email_error}")
        return False, ""


def render_admin_dashboard():
    incidents_df = load_csv(INCIDENTS_FILE)
    dataset_df = load_csv(DATASET_FILE)
    otp_audit_df = load_csv(OTP_AUDIT_FILE)
    reports_df = load_csv(REPORTS_FILE)

    for df in [incidents_df, dataset_df, otp_audit_df, reports_df]:
        if not df.empty:
            for col in df.columns:
                df[col] = df[col].fillna("")

    incident_total = len(incidents_df)
    dataset_total = len(dataset_df)
    reports_total = len(reports_df)
    otp_total = len(otp_audit_df)

    filtered_incidents = incidents_df.copy()
    filtered_dataset = dataset_df.copy()

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Platform Mode")
    st.sidebar.caption("Enterprise Cyber Defense Interface")

    if st.sidebar.button("🔄 Refresh Data", use_container_width=True, key="refresh_admin_data"):
        refresh_data()
        st.rerun()

    show_incidents = st.sidebar.checkbox(
        "Show Live Incidents",
        value=True,
        key="show_live_incidents",
    )
    show_dataset = st.sidebar.checkbox(
        "Show Original Dataset",
        value=True,
        key="show_original_dataset",
    )

    incident_label_options = []
    risk_options = []
    dataset_label_options = []

    if not incidents_df.empty and "predicted_label" in incidents_df.columns:
        incident_label_options = sorted(incidents_df["predicted_label"].astype(str).unique())

    if not incidents_df.empty and "risk_level" in incidents_df.columns:
        risk_options = sorted(incidents_df["risk_level"].astype(str).unique())

    if not dataset_df.empty and "نوع_الحالة" in dataset_df.columns:
        dataset_label_options = sorted(dataset_df["نوع_الحالة"].astype(str).unique())

    selected_incident_labels = st.sidebar.multiselect(
        "Threat Type",
        options=incident_label_options,
        default=incident_label_options,
        key="incident_labels_filter",
    )

    selected_risks = st.sidebar.multiselect(
        "Risk Level",
        options=risk_options,
        default=risk_options,
        key="risk_filter",
    )

    incident_search = st.sidebar.text_input(
        "Search Incident Text",
        key="incident_search_filter",
    )

    selected_dataset_labels = st.sidebar.multiselect(
        "Dataset Case Type",
        options=dataset_label_options,
        default=dataset_label_options,
        key="dataset_case_filter",
    )

    dataset_search = st.sidebar.text_input(
        "Search Dataset Text",
        key="dataset_search_filter",
    )

    if not filtered_incidents.empty:
        if selected_incident_labels and "predicted_label" in filtered_incidents.columns:
            filtered_incidents = filtered_incidents[
                filtered_incidents["predicted_label"].astype(str).isin(selected_incident_labels)
            ]

        if selected_risks and "risk_level" in filtered_incidents.columns:
            filtered_incidents = filtered_incidents[
                filtered_incidents["risk_level"].astype(str).isin(selected_risks)
            ]

        if incident_search and "original_text" in filtered_incidents.columns:
            filtered_incidents = filtered_incidents[
                filtered_incidents["original_text"].astype(str).str.contains(
                    incident_search, case=False, na=False
                )
            ]

    if not filtered_dataset.empty:
        if selected_dataset_labels and "نوع_الحالة" in filtered_dataset.columns:
            filtered_dataset = filtered_dataset[
                filtered_dataset["نوع_الحالة"].astype(str).isin(selected_dataset_labels)
            ]

        if dataset_search and "نص_الرسالة" in filtered_dataset.columns:
            filtered_dataset = filtered_dataset[
                filtered_dataset["نص_الرسالة"].astype(str).str.contains(
                    dataset_search, case=False, na=False
                )
            ]

    incident_filtered = len(filtered_incidents)
    high_risk_count = 0
    top_threat = "N/A"

    if not filtered_incidents.empty and "risk_level" in filtered_incidents.columns:
        high_risk_count = (filtered_incidents["risk_level"].astype(str) == "High").sum()

    if not filtered_incidents.empty and "predicted_label" in filtered_incidents.columns:
        top_threat = filtered_incidents["predicted_label"].value_counts().idxmax()

    if high_risk_count > 0:
        st.markdown(f"""
        <div class="status-alert">
            🚨 Threat activity detected. Current high-risk incidents: <b>{high_risk_count}</b>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="status-ok">
            🟢 System status normal. No critical live threats detected right now.
        </div>
        """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="glass-card">
        <div class="card-title">🛰️ Monitor Status</div>
        ACTIVE &nbsp;&nbsp;|&nbsp;&nbsp;
        Incidents Loaded: <b>{incident_total}</b> &nbsp;&nbsp;|&nbsp;&nbsp;
        Filtered: <b>{incident_filtered}</b> &nbsp;&nbsp;|&nbsp;&nbsp;
        High Risk: <b>{high_risk_count}</b> &nbsp;&nbsp;|&nbsp;&nbsp;
        Top Threat: <b>{top_threat}</b>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-label">Live Incidents</div>
            <div class="metric-value">{incident_total}</div>
            <div class="metric-sub">All monitored records</div>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-label">High Risk</div>
            <div class="metric-value">{high_risk_count}</div>
            <div class="metric-sub">Requires immediate attention</div>
        </div>
        """, unsafe_allow_html=True)

    with c3:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-label">Victim Reports</div>
            <div class="metric-value">{reports_total}</div>
            <div class="metric-sub">Submitted cases</div>
        </div>
        """, unsafe_allow_html=True)

    with c4:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-label">OTP Events</div>
            <div class="metric-value">{otp_total}</div>
            <div class="metric-sub">Authentication audit logs</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">🧪 Red Team Simulation Panel</div>', unsafe_allow_html=True)

    test_message = st.text_area(
        "Simulate Attack Message",
        placeholder="Example: اذا ما دفعت رح انشر صورك",
        key="red_team_text",
    )

    if st.button("🚨 Run Test Attack", use_container_width=True, key="run_test_attack"):
        if not test_message.strip():
            st.error("Please enter a message first.")
        else:
            try:
                with st.spinner("AI engine is analyzing the simulated attack..."):
                    result = analyze_message_runtime(test_message.strip())
                refresh_data()
                st.success("Attack simulation completed and analyzed.")

                risk_class = get_risk_pill_class(result.get("risk_level", "Low"))
                st.markdown(
                    f'<div class="risk-pill {risk_class}">{result.get("risk_level", "Low")}</div>',
                    unsafe_allow_html=True
                )

                st.write("**Detected Label:**", result.get("predicted_label", ""))
                st.write("**Confidence Score:**", result.get("confidence_score", ""))

                law_text = result.get("main_law", "")
                case_explanation = result.get("case_explanation", "")

                st.markdown(f"""
                <div class="law-panel">
                    <div class="panel-key">⚖️ Jordanian Law Applied</div>
                    <div class="panel-value">{law_text}</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="explain-panel">
                    <div class="panel-key">🧠 AI Legal Explanation</div>
                    <div class="panel-value">{case_explanation}</div>
                </div>
                """, unsafe_allow_html=True)

            except Exception as error:
                st.error(f"Simulation failed: {error}")

    st.markdown("</div>", unsafe_allow_html=True)

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📡 Live Incidents",
        "🗂️ Original Dataset",
        "📊 Analytics",
        "🔎 Detail View",
        "🧾 OTP Audit Logs",
        "🚨 Victim Reports",
    ])

    with tab1:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">📡 Live Incident Feed</div>', unsafe_allow_html=True)

        if not show_incidents:
            st.info("Live incidents are hidden from sidebar.")
        elif filtered_incidents.empty:
            st.warning("No live incidents found.")
        else:
            preferred_cols = [
                "time",
                "original_text",
                "predicted_label",
                "confidence_score",
                "risk_level",
                "main_law",
                "alert_status",
            ]
            existing_cols = [col for col in preferred_cols if col in filtered_incidents.columns]
            st.dataframe(filtered_incidents[existing_cols], use_container_width=True, height=460)

        st.markdown("</div>", unsafe_allow_html=True)

    with tab2:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🗂️ Jordanian Law Source Dataset</div>', unsafe_allow_html=True)

        if not show_dataset:
            st.info("Original dataset is hidden from sidebar.")
        elif filtered_dataset.empty:
            st.warning("No dataset rows found.")
        else:
            st.dataframe(filtered_dataset.head(200), use_container_width=True, height=460)

        st.markdown("</div>", unsafe_allow_html=True)

    with tab3:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">📊 Executive Analytics</div>', unsafe_allow_html=True)

        col_left, col_right = st.columns(2)

        with col_left:
            if not filtered_incidents.empty and "predicted_label" in filtered_incidents.columns:
                counts = filtered_incidents["predicted_label"].value_counts().reset_index()
                counts.columns = ["Threat Type", "Count"]
                fig_inc = px.bar(
                    counts,
                    x="Threat Type",
                    y="Count",
                    title="Live Threat Distribution",
                    text_auto=True
                )
                fig_inc.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="white",
                )
                st.plotly_chart(fig_inc, use_container_width=True)
            else:
                st.info("No incident threat data available.")

        with col_right:
            if not filtered_incidents.empty and "risk_level" in filtered_incidents.columns:
                risk_counts = filtered_incidents["risk_level"].value_counts().reset_index()
                risk_counts.columns = ["Risk Level", "Count"]
                fig_risk = px.pie(
                    risk_counts,
                    names="Risk Level",
                    values="Count",
                    title="Risk Distribution",
                    hole=0.55
                )
                fig_risk.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="white",
                )
                st.plotly_chart(fig_risk, use_container_width=True)
            else:
                st.info("No incident risk data available.")

        st.markdown("---")

        col_left2, col_right2 = st.columns(2)

        with col_left2:
            if not filtered_dataset.empty and "نوع_الحالة" in filtered_dataset.columns:
                ds_counts = filtered_dataset["نوع_الحالة"].value_counts().reset_index()
                ds_counts.columns = ["نوع_الحالة", "Count"]
                fig_ds = px.bar(
                    ds_counts,
                    x="نوع_الحالة",
                    y="Count",
                    title="Original Dataset Case Distribution",
                    text_auto=True,
                )
                fig_ds.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="white",
                )
                st.plotly_chart(fig_ds, use_container_width=True)
            else:
                st.info("No dataset distribution available.")

        with col_right2:
            if not filtered_incidents.empty and "time" in filtered_incidents.columns:
                timeline_df = filtered_incidents.copy()
                timeline_df["time"] = pd.to_datetime(timeline_df["time"], errors="coerce")
                timeline_df = timeline_df.dropna(subset=["time"])

                if not timeline_df.empty:
                    timeline_df["hour"] = timeline_df["time"].dt.strftime("%Y-%m-%d %H:00")
                    trend = timeline_df.groupby("hour").size().reset_index(name="count")

                    fig_timeline = px.line(
                        trend,
                        x="hour",
                        y="count",
                        title="Incident Activity Timeline",
                        markers=True
                    )
                    fig_timeline.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="white"
                    )
                    st.plotly_chart(fig_timeline, use_container_width=True)
                else:
                    st.info("No valid time data available.")
            else:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Original Dataset Records</div>
                    <div class="metric-value">{dataset_total}</div>
                    <div class="metric-sub">Jordanian law mapping source</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

    with tab4:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🔎 Incident Detail Inspector</div>', unsafe_allow_html=True)

        if not filtered_incidents.empty:
            selected_idx = st.selectbox(
                "Select Incident Row",
                filtered_incidents.index.tolist(),
                key="incident_detail_selector"
            )
            row = filtered_incidents.loc[selected_idx]

            risk_value = safe_text(row.get("risk_level", ""))
            pill_class = get_risk_pill_class(risk_value)

            st.markdown(
                f'<div class="risk-pill {pill_class}">{risk_value}</div>',
                unsafe_allow_html=True
            )

            st.write("**Original Text:**", row.get("original_text", ""))
            st.write("**Predicted Label:**", row.get("predicted_label", ""))
            st.write("**Confidence Score:**", row.get("confidence_score", ""))
            st.write("**Alert Status:**", row.get("alert_status", ""))
            st.write("**Time:**", row.get("time", ""))

            st.markdown(f"""
            <div class="law-panel">
                <div class="panel-key">⚖️ Jordanian Law Applied</div>
                <div class="panel-value">{row.get("main_law", "")}</div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown(f"""
            <div class="explain-panel">
                <div class="panel-key">🧠 AI Legal Explanation</div>
                <div class="panel-value">{row.get("case_explanation", "")}</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("No incident selected.")

        st.markdown("</div>", unsafe_allow_html=True)

    with tab5:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🧾 OTP Audit Logs</div>', unsafe_allow_html=True)

        if otp_audit_df.empty:
            st.info("No OTP audit logs found yet.")
        else:
            st.dataframe(otp_audit_df, use_container_width=True, height=460)

        st.markdown("</div>", unsafe_allow_html=True)

    with tab6:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🚨 Victim Reports Control View</div>', unsafe_allow_html=True)

        if reports_df.empty:
            st.info("No victim reports found yet.")
        else:
            st.dataframe(reports_df, use_container_width=True, height=460)

        st.markdown("</div>", unsafe_allow_html=True)


st.markdown("""
<style>
    .stApp {
        background:
            radial-gradient(circle at 0% 0%, rgba(0, 255, 170, 0.07), transparent 18%),
            radial-gradient(circle at 100% 0%, rgba(0, 140, 255, 0.08), transparent 22%),
            radial-gradient(circle at 50% 100%, rgba(0, 90, 200, 0.06), transparent 30%),
            linear-gradient(180deg, #06101c 0%, #0a1322 42%, #0d1829 100%);
        color: #eaf2ff;
    }

    html, body, [class*="css"] {
        font-family: "Segoe UI", "Inter", sans-serif;
        color: #eaf2ff !important;
    }

    section[data-testid="stSidebar"] {
        background:
            linear-gradient(180deg, rgba(8,16,29,0.98) 0%, rgba(12,22,40,0.98) 100%);
        border-right: 1px solid rgba(255,255,255,0.06);
    }

    [data-testid="stSidebar"] .stRadio label,
    [data-testid="stSidebar"] .stMarkdown,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] span,
    [data-testid="stSidebar"] div {
        color: #dce9ff !important;
    }

    .main-hero {
        position: relative;
        overflow: hidden;
        background:
            linear-gradient(135deg, rgba(0,98,255,0.96), rgba(0,210,180,0.90));
        border: 1px solid rgba(255,255,255,0.16);
        border-radius: 30px;
        padding: 34px 34px 28px 34px;
        margin-bottom: 20px;
        box-shadow: 0 24px 70px rgba(0,0,0,0.30);
    }

    .main-hero::after {
        content: "";
        position: absolute;
        top: -30px;
        right: -30px;
        width: 180px;
        height: 180px;
        border-radius: 50%;
        background: rgba(255,255,255,0.08);
        filter: blur(6px);
    }

    .main-hero h1 {
        margin: 0;
        font-size: 2.35rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: #ffffff !important;
    }

    .main-hero p {
        margin-top: 12px;
        margin-bottom: 0;
        font-size: 1.02rem;
        line-height: 1.65;
        color: #eef8ff !important;
        max-width: 900px;
    }

    .hero-badges {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        margin-top: 18px;
    }

    .hero-badge {
        padding: 8px 14px;
        border-radius: 999px;
        font-size: 0.84rem;
        font-weight: 600;
        background: rgba(255,255,255,0.16);
        border: 1px solid rgba(255,255,255,0.18);
        color: #ffffff !important;
        box-shadow: inset 0 1px 0 rgba(255,255,255,0.06);
    }

    .glass-card {
        background:
            linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.022));
        border: 1px solid rgba(255,255,255,0.09);
        border-radius: 24px;
        padding: 20px;
        box-shadow: 0 14px 40px rgba(0,0,0,0.22);
        margin-bottom: 20px;
        backdrop-filter: blur(10px);
    }

    .card-title {
        font-size: 1.08rem;
        font-weight: 700;
        color: #ffffff !important;
        margin-bottom: 14px;
        letter-spacing: 0.01em;
    }

    .metric-box {
        background:
            linear-gradient(180deg, rgba(255,255,255,0.07), rgba(255,255,255,0.03));
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 24px;
        padding: 20px;
        min-height: 124px;
        box-shadow: 0 12px 35px rgba(0,0,0,0.18);
    }

    .metric-label {
        font-size: 0.85rem;
        color: #b7c8eb !important;
        margin-bottom: 10px;
        letter-spacing: 0.02em;
    }

    .metric-value {
        font-size: 2.1rem;
        font-weight: 800;
        line-height: 1.05;
        color: #ffffff !important;
    }

    .metric-sub {
        font-size: 0.80rem;
        color: #95add7 !important;
        margin-top: 10px;
        line-height: 1.4;
    }

    .status-ok {
        background: linear-gradient(90deg, rgba(0,214,143,0.16), rgba(0,140,255,0.10));
        border: 1px solid rgba(0,214,143,0.28);
        border-radius: 18px;
        padding: 14px 18px;
        margin-bottom: 16px;
        color: #edfffa !important;
        box-shadow: 0 0 20px rgba(0,214,143,0.06);
    }

    .status-alert {
        background: linear-gradient(90deg, rgba(255,77,109,0.20), rgba(255,128,0,0.10));
        border: 1px solid rgba(255,77,109,0.30);
        border-radius: 18px;
        padding: 14px 18px;
        margin-bottom: 16px;
        color: #fff2f6 !important;
        box-shadow: 0 0 24px rgba(255,77,109,0.08);
    }

    .law-panel {
        background: linear-gradient(180deg, rgba(0,214,143,0.08), rgba(255,255,255,0.02));
        border: 1px solid rgba(0,214,143,0.28);
        border-radius: 20px;
        padding: 18px;
        margin-top: 12px;
        margin-bottom: 12px;
    }

    .explain-panel {
        background: linear-gradient(180deg, rgba(0,140,255,0.08), rgba(255,255,255,0.02));
        border: 1px solid rgba(0,140,255,0.28);
        border-radius: 20px;
        padding: 18px;
        margin-top: 12px;
        margin-bottom: 12px;
    }

    .panel-key {
        font-size: 0.82rem;
        font-weight: 600;
        color: #9fc9ff !important;
        margin-bottom: 8px;
        letter-spacing: 0.02em;
    }

    .panel-value {
        font-size: 1rem;
        color: #ffffff !important;
        line-height: 1.72;
        word-break: break-word;
    }

    .risk-pill {
        display: inline-block;
        padding: 7px 13px;
        border-radius: 999px;
        font-size: 0.82rem;
        font-weight: 700;
        margin-bottom: 12px;
        letter-spacing: 0.02em;
    }

    .risk-high {
        background: rgba(255,77,109,0.18);
        border: 1px solid rgba(255,77,109,0.35);
        color: #ff9bb0 !important;
    }

    .risk-medium {
        background: rgba(255,193,7,0.18);
        border: 1px solid rgba(255,193,7,0.35);
        color: #ffe082 !important;
    }

    .risk-low {
        background: rgba(0,214,143,0.16);
        border: 1px solid rgba(0,214,143,0.35);
        color: #7cf0c9 !important;
    }

    .login-box {
        max-width: 960px;
        margin: 0 auto;
        background: linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02));
        border: 1px solid rgba(255,255,255,0.09);
        border-radius: 30px;
        padding: 30px;
        box-shadow: 0 24px 70px rgba(0,0,0,0.28);
    }

    .login-title {
        font-size: 1.65rem;
        font-weight: 800;
        margin-bottom: 8px;
        color: white !important;
    }

    .login-sub {
        color: #bed0f3 !important;
        margin-bottom: 20px;
        line-height: 1.6;
    }

    .tiny-badge {
        display: inline-block;
        padding: 6px 11px;
        border-radius: 999px;
        font-size: 0.75rem;
        background: rgba(255,255,255,0.08);
        margin-right: 8px;
        color: #d8e6ff !important;
        border: 1px solid rgba(255,255,255,0.08);
    }

    .footer-note {
        color: #8ca2cf !important;
        font-size: 0.83rem;
        margin-top: 10px;
    }

    div[data-testid="stTabs"] button {
        border-radius: 999px !important;
        font-weight: 700 !important;
    }

    div[data-testid="stTabs"] {
        margin-top: 4px;
    }

    div[data-testid="stTextInput"] input,
    div[data-testid="stTextArea"] textarea,
    div[data-testid="stSelectbox"] div[data-baseweb="select"] > div,
    div[data-testid="stMultiSelect"] div[data-baseweb="select"] > div {
        background: rgba(255,255,255,0.03) !important;
        border-radius: 14px !important;
        border: 1px solid rgba(255,255,255,0.06) !important;
    }

    div.stButton > button {
        border-radius: 14px !important;
        font-weight: 700 !important;
        border: 1px solid rgba(255,255,255,0.10) !important;
        min-height: 42px;
    }

    div[data-testid="stDataFrame"] {
        border-radius: 18px;
        overflow: hidden;
        border: 1px solid rgba(255,255,255,0.08);
    }

    hr {
        border-color: rgba(255,255,255,0.08) !important;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="main-hero">
    <h1>🛡️ CyberShieldX Secure Platform</h1>
    <p>Enterprise-grade cyber protection dashboard for threat detection, victim reporting, OTP access, and Jordanian law mapping.</p>
    <div class="hero-badges">
        <div class="hero-badge">Admin Dashboard</div>
        <div class="hero-badge">Live Threat Monitoring</div>
        <div class="hero-badge">Jordanian Law Mapping</div>
        <div class="hero-badge">Victim Reporting</div>
        <div class="hero-badge">OTP Access Layer</div>
    </div>
</div>
""", unsafe_allow_html=True)

if st.session_state.authenticated and session_expired(
    st.session_state.login_time,
    timeout_seconds=SESSION_TIMEOUT_SECONDS
):
    st.session_state.authenticated = False
    st.warning("Session expired. Please login again.")

if not st.session_state.authenticated:
    st.markdown('<div class="login-box">', unsafe_allow_html=True)
    st.markdown('<div class="login-title">🔐 Secure OTP Login</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div class="login-sub">Multi-channel OTP access with expiry, cooldown, attempt limit, lockout, and audit logging. OTP validity: {OTP_VALIDITY_SECONDS} seconds.</div>',
        unsafe_allow_html=True
    )

    st.markdown("""
    <span class="tiny-badge">OTP Expiry</span>
    <span class="tiny-badge">Cooldown</span>
    <span class="tiny-badge">Attempt Limit</span>
    <span class="tiny-badge">Audit Log</span>
    """, unsafe_allow_html=True)

    channel = st.selectbox(
        "Verification Channel",
        ["email", "smart_auto", "sms"],
        index=0,
        key="login_channel_select"
    )
    phone = st.text_input("Phone Number", placeholder="+9627XXXXXXXX", key="login_phone")
    email = st.text_input("Email Address", placeholder="name@example.com", key="login_email")

    st.info("Recommended for demo: Email OTP. Smart Auto tries SMS first, then Email fallback.")

    if st.session_state.last_destination:
        masked = mask_destination(
            st.session_state.last_destination,
            st.session_state.last_channel or "email"
        )
        st.markdown(
            f'<div class="status-ok">Last OTP destination: <b>{masked}</b> via <b>{st.session_state.last_channel}</b></div>',
            unsafe_allow_html=True
        )

    if lockout_active(st.session_state.lockout_until):
        remaining_lock = lockout_remaining(st.session_state.lockout_until)
        st.markdown(
            f'<div class="status-alert">🔒 Too many failed attempts. Try again in <b>{remaining_lock}</b> seconds.</div>',
            unsafe_allow_html=True
        )

    if st.session_state.otp_created_at is not None and not otp_code_expired(st.session_state.otp_created_at):
        remaining = OTP_VALIDITY_SECONDS - int(time.time() - st.session_state.otp_created_at)
        st.markdown(
            f'<div class="status-ok">⏳ Current OTP expires in <b>{remaining}</b> seconds.</div>',
            unsafe_allow_html=True
        )
        st.progress(max(0.0, min(1.0, remaining / OTP_VALIDITY_SECONDS)))

    elif st.session_state.otp_created_at is not None and otp_code_expired(st.session_state.otp_created_at):
        st.markdown(
            '<div class="status-alert">⚠️ The previous OTP has expired. Please request a new code.</div>',
            unsafe_allow_html=True
        )

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Send OTP", use_container_width=True, key="send_otp_btn"):
            if lockout_active(st.session_state.lockout_until):
                remaining_lock = lockout_remaining(st.session_state.lockout_until)
                st.error(f"Account temporarily locked. Try again in {remaining_lock} seconds.")
            elif resend_cooldown_active(st.session_state.otp_last_sent_at):
                cd = cooldown_remaining(st.session_state.otp_last_sent_at)
                st.warning(f"Please wait {cd} seconds before requesting another OTP.")
            else:
                success = False
                delivery_channel = ""

                with st.spinner("Sending OTP..."):
                    if channel == "smart_auto":
                        success, delivery_channel = send_otp_with_fallback("sms", phone, email)
                    else:
                        success, delivery_channel = send_otp_with_fallback(channel, phone, email)

                if success:
                    st.session_state.otp_created_at = time.time()
                    st.session_state.otp_last_sent_at = time.time()
                    st.session_state.otp_attempts = 0
                    st.session_state.otp_delivery_channel = delivery_channel

    with col2:
        user_code = st.text_input("Enter OTP", type="password", key="verify_otp_input")

        if st.button("Verify OTP", use_container_width=True, key="verify_otp_btn"):
            current_channel = st.session_state.otp_delivery_channel
            current_destination = st.session_state.last_destination

            if lockout_active(st.session_state.lockout_until):
                remaining_lock = lockout_remaining(st.session_state.lockout_until)
                st.error(f"Account temporarily locked. Try again in {remaining_lock} seconds.")
            elif st.session_state.otp_attempts >= MAX_OTP_ATTEMPTS:
                st.session_state.lockout_until = time.time() + LOCKOUT_SECONDS
                st.error(f"Maximum attempts reached. Locked for {LOCKOUT_SECONDS} seconds.")
            elif st.session_state.otp_created_at is None:
                st.error("Please request an OTP first.")
            elif otp_code_expired(st.session_state.otp_created_at):
                write_otp_audit(
                    "verify_otp",
                    current_channel or "unknown",
                    current_destination or "",
                    "expired",
                    "otp_expired",
                )
                st.error("This OTP has expired. Please request a new one.")
            else:
                try:
                    if current_channel == "sms":
                        verified = check_sms_verification(current_destination, user_code)
                    else:
                        verified = user_code == st.session_state.otp_code

                    if verified:
                        write_otp_audit(
                            "verify_otp",
                            current_channel or "unknown",
                            current_destination or "",
                            "success",
                            "otp_verified",
                        )
                        st.session_state.authenticated = True
                        st.session_state.login_time = time.time()
                        st.success("Login successful.")
                        st.rerun()
                    else:
                        st.session_state.otp_attempts += 1
                        remaining_attempts = MAX_OTP_ATTEMPTS - st.session_state.otp_attempts
                        write_otp_audit(
                            "verify_otp",
                            current_channel or "unknown",
                            current_destination or "",
                            "failed",
                            f"remaining_attempts={remaining_attempts}",
                        )
                        if st.session_state.otp_attempts >= MAX_OTP_ATTEMPTS:
                            st.session_state.lockout_until = time.time() + LOCKOUT_SECONDS
                            st.error(f"Invalid OTP. Maximum attempts reached. Locked for {LOCKOUT_SECONDS} seconds.")
                        else:
                            st.error(f"Invalid OTP. Remaining attempts: {remaining_attempts}")
                except Exception as e:
                    write_otp_audit(
                        "verify_otp",
                        current_channel or "unknown",
                        current_destination or "",
                        "failed",
                        str(e),
                    )
                    st.error(f"Verification failed: {e}")

    st.markdown(
        '<div class="footer-note">Role-based secure access with Email/SMS OTP, expiry, cooldown, lockout, and audit logging.</div>',
        unsafe_allow_html=True
    )
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

st.sidebar.title("⚙️ Navigation")

if st.session_state.login_time:
    session_left = SESSION_TIMEOUT_SECONDS - int(time.time() - st.session_state.login_time)
    session_left = max(session_left, 0)
    st.sidebar.markdown(f"🔐 Session expires in: **{session_left}s**")

page = st.sidebar.radio(
    "Choose Interface",
    ["Admin", "User", "Victim Report"],
    key="main_interface_radio"
)

if st.sidebar.button("Logout", use_container_width=True, key="logout_btn"):
    for key, value in DEFAULTS.items():
        st.session_state[key] = value
    st.rerun()

if page == "Admin":
    render_admin_dashboard()

elif page == "User":
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">👤 User Threat Check</div>', unsafe_allow_html=True)

    user_text = st.text_area("Message to Analyze", height=220, key="user_text_analyze")

    if st.button("Analyze Message", use_container_width=True, key="analyze_message_btn"):
        if not user_text.strip():
            st.error("Please enter a message first.")
        else:
            try:
                with st.spinner("Analyzing message..."):
                    result = analyze_message_runtime(user_text.strip())
                st.success("Analysis completed.")

                risk_class = get_risk_pill_class(result.get("risk_level", "Low"))
                st.markdown(
                    f'<div class="risk-pill {risk_class}">{result.get("risk_level", "Low")}</div>',
                    unsafe_allow_html=True
                )

                st.write("**Predicted Label:**", result.get("predicted_label", ""))
                st.write("**Confidence Score:**", result.get("confidence_score", ""))

                st.markdown(f"""
                <div class="law-panel">
                    <div class="panel-key">⚖️ Jordanian Law Applied</div>
                    <div class="panel-value">{result.get("main_law", "")}</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="explain-panel">
                    <div class="panel-key">🧠 AI Legal Explanation</div>
                    <div class="panel-value">{result.get("case_explanation", "")}</div>
                </div>
                """, unsafe_allow_html=True)

            except Exception as e:
                st.error(f"Analysis failed: {e}")

    st.markdown("</div>", unsafe_allow_html=True)

elif page == "Victim Report":
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">🚨 Victim Reporting Interface</div>', unsafe_allow_html=True)
    st.write("Submit a cyber incident report for analysis, legal mapping, and review.")

    full_name = st.text_input("Full Name", key="victim_full_name")
    phone = st.text_input("Victim Phone Number", key="victim_phone")
    email = st.text_input("Victim Email Address", key="victim_email")
    case_type_selected = st.selectbox(
        "Type of Case",
        ["ابتزاز", "تحرش", "تشهير", "احتيال", "تهديد", "رابط مشبوه", "أخرى"],
        key="victim_case_type"
    )
    incident_text = st.text_area("Incident Text / Message", height=220, key="victim_incident_text")
    extra_notes = st.text_area("Additional Notes", height=120, key="victim_extra_notes")

    if st.button("Submit Report", use_container_width=True, key="submit_report_btn"):
        if not incident_text.strip():
            st.error("Please enter the incident text first.")
        else:
            try:
                with st.spinner("Submitting and analyzing report..."):
                    result = analyze_message_runtime(incident_text.strip())

                save_report_row([
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
                    result.get("alert_status", ""),
                ])

                st.success("Report submitted successfully.")

                risk_class = get_risk_pill_class(result.get("risk_level", "Low"))
                st.markdown(
                    f'<div class="risk-pill {risk_class}">{result.get("risk_level", "Low")}</div>',
                    unsafe_allow_html=True
                )

                st.write("**Predicted Label:**", result.get("predicted_label", ""))

                st.markdown(f"""
                <div class="law-panel">
                    <div class="panel-key">⚖️ Jordanian Law Applied</div>
                    <div class="panel-value">{result.get("main_law", "")}</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="explain-panel">
                    <div class="panel-key">🧠 AI Legal Explanation</div>
                    <div class="panel-value">{result.get("case_explanation", "")}</div>
                </div>
                """, unsafe_allow_html=True)

                st.write("**Alert Status:**", result.get("alert_status", ""))

            except Exception as e:
                st.error(f"Failed to submit report: {e}")

    st.markdown("</div>", unsafe_allow_html=True)
