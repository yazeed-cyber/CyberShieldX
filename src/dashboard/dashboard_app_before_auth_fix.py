from pathlib import Path
import hashlib
import re
import os
import time
import csv
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st
from src.red_team_simulator import run_all_simulations, run_random_simulation
from src.jordanian_law_engine import detect_law_case, format_law_summary

from src.dashboard.device_identity import get_device_uid, get_device_info

from src.doctor_rule_based import log_login_alert

from src.doctor_rule_based import (
    analyze_doctor_requirements,
    log_login_alert,
    LOGIN_ALERT_FILE,
)

from src.rule_engine import analyze_rule_based

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
TELEGRAM_LIVE_FILE = "outputs/telegram_live_dataset.csv"
ALERTS_FILE = "outputs/realtime_alerts.csv"
THREAT_INTEL_FILE = "outputs/threat_intel_results.csv"
USER_TRACKING_FILE = "outputs/real_user_tracking.csv"
INCIDENT_CENTER_FILE = "outputs/incident_center.csv"
REDTEAM_FILE = "outputs/red_team_simulation.csv"
SESSION_TIMEOUT_SECONDS = 300


AUTH_FILE = Path("outputs/auth_users.csv")

def is_valid_email(email):
    return re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email or "") is not None


def check_password_strength(password):
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

    weak_words = [
        "password", "admin", "qwerty", "123456", "123456789",
        "cybershieldx", "yazeed", "kali"
    ]

    for word in weak_words:
        if word.lower() in password.lower():
            errors.append(f"Password must not contain weak word: {word}")

    if errors:
        return False, errors

    return True, ["Strong password accepted."]


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def ensure_auth_file():
    AUTH_FILE.parent.mkdir(exist_ok=True)

    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("email,password_hash\n", encoding="utf-8")


def load_users():
    ensure_auth_file()
    users = {}

    lines = AUTH_FILE.read_text(encoding="utf-8").splitlines()[1:]

    for line in lines:
        if "," in line:
            email, password_hash = line.split(",", 1)
            users[email.strip().lower()] = password_hash.strip()

    return users


def create_user(email, password):
    email = (email or "").strip().lower()

    if not is_valid_email(email):
        return False, "Enter a valid email address."

    strong, messages = check_password_strength(password)

    if not strong:
        return False, "\n".join(messages)

    users = load_users()

    if email in users:
        return False, "This email is already registered. Use Login."

    with AUTH_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{email},{hash_password(password)}\n")

    return True, "Account created successfully with a strong password."


def login_user(email, password):
    email = (email or "").strip().lower()

    if not is_valid_email(email):
        return False, "Enter a valid email address."

    users = load_users()

    if email not in users:
        return False, "Email is not registered. Please Sign in first."

    if users[email] != hash_password(password):
        return False, "Invalid password."

    return True, "Login successful."

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
    "device_uid": get_device_uid(),
    "signin_completed": False,
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

    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📡 Live Incidents",
        "🗂️ Original Dataset",
        "📊 Analytics",
        "🔎 Detail View",
        "🧾 OTP Audit Logs",
        "🚨 Victim Reports",
        "🧠 Rule-Based Engine",
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

    with tab7:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🧠 Rule Based Center</div>', unsafe_allow_html=True)

        st.write("This section implements Rule-Based detection using automatic device UID, dataset rules, text matching, search/filter, port check, HTTPS check, Telegram indicators, phishing, and social engineering.")

        uid = st.session_state.get("device_uid", get_device_uid())
        st.markdown(f"""
        <div class="law-panel">
            <div class="panel-key">🆔 Automatic Device UID</div>
            <div class="panel-value">{uid}</div>
        </div>
        """, unsafe_allow_html=True)

        rule_text = st.text_area(
            "Message Text as Rule-Based Input",
            placeholder="Example: لا تخبر أحد، ابعتلي كود التحقق عبر تلجرام https://t.me/support_login",
            height=170,
            key="doctor_rule_text"
        )

        search_filter = st.text_input(
            "Search / Filter in Rule-Based Dataset",
            placeholder="blackmail / ابتزاز / telegram",
            key="doctor_search_filter"
        )

        port = ""
        url = ""

        st.info("Port and URL are extracted automatically from the message text by the Rule-Based engine.")

        c_login, c_signin = st.columns(2)

        with c_login:
            if st.button("🔐 Log Login Alert", use_container_width=True, key="doctor_login_alert_btn"):
                if not uid.strip():
                    st.error("UID is required before logging login alert.")
                else:
                    log_login_alert(uid, "login", "alert_logged", "Manual login alert from dashboard")
                    st.success("Login alert saved.")

        with c_signin:
            if st.button("📝 Log Sign-in Alert", use_container_width=True, key="doctor_signin_alert_btn"):
                if not uid.strip():
                    st.error("UID is required before logging sign-in alert.")
                else:
                    log_login_alert(uid, "sign_in", "alert_logged", "Manual sign-in alert from dashboard")
                    st.success("Sign-in alert saved.")

        if st.button("🚀 Run Doctor Required Rule-Based Check", use_container_width=True, key="doctor_run_rule_check"):
            result = analyze_doctor_requirements(uid, rule_text, port, url, search_filter)

            if not result["valid"]:
                st.error(result["error"])
            else:
                risk = result["risk"]
                risk_class = "risk-high" if risk == "High" else "risk-medium" if risk == "Medium" else "risk-low"

                st.markdown(
                    f'<div class="risk-pill {risk_class}">{risk}</div>',
                    unsafe_allow_html=True
                )

                if risk == "High":
                    st.error("🚨 ALERT: High-risk rule-based match detected.")
                elif risk == "Medium":
                    st.warning("⚠️ Suspicious rule-based activity detected.")
                else:
                    st.success("✅ No critical rule-based match detected.")

                k1, k2, k3, k4 = st.columns(4)

                with k1:
                    st.markdown(f"""
                    <div class="metric-box">
                        <div class="metric-label">UID</div>
                        <div class="metric-value">OK</div>
                        <div class="metric-sub">{result["uid"]}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with k2:
                    st.markdown(f"""
                    <div class="metric-box">
                        <div class="metric-label">Rule Score</div>
                        <div class="metric-value">{result["score"]}</div>
                        <div class="metric-sub">Text + Dataset + Port + HTTPS</div>
                    </div>
                    """, unsafe_allow_html=True)

                with k3:
                    st.markdown(f"""
                    <div class="metric-box">
                        <div class="metric-label">Alert Status</div>
                        <div class="metric-value">ON</div>
                        <div class="metric-sub">{result["alert"]}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with k4:
                    st.markdown(f"""
                    <div class="metric-box">
                        <div class="metric-label">Port</div>
                        <div class="metric-value">{result["port_check"]["port"]}</div>
                        <div class="metric-sub">{result["port_check"]["service"]}</div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="explain-panel">
                    <div class="panel-key">🎯 Rule-Based Match Summary</div>
                    <div class="panel-value">
                        Matched Rules: {result["matched_rules"]}<br>
                        Phishing: {result["phishing"] or "None"}<br>
                        Social Engineering: {result["social"] or "None"}<br>
                        Telegram: {result["telegram"] or "None"}<br>
                        Auto URLs: {", ".join(result.get("auto_detected_urls", [])) or "None"}<br>
                        Auto Ports: {", ".join(map(str, result.get("auto_detected_ports", []))) or "None"}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="law-panel">
                    <div class="panel-key">🌐 Automatic Port Rule-Based Check</div>
                    <div class="panel-value">
                        Port: {result["port_check"]["port"]}<br>
                        Service: {result["port_check"]["service"]}<br>
                        Recommendation: {result["port_check"]["recommendation"]}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.write("**Automatic HTTPS / URL Check:**")
                st.dataframe(pd.DataFrame(result["https_checks"]), use_container_width=True)

                if not result["dataset_matches"].empty:
                    st.write("**Dataset as Rule-Based Table Matches:**")
                    st.caption(f'Dataset text column: {result["dataset_text_col"]} | label column: {result["dataset_label_col"]}')
                    st.dataframe(result["dataset_matches"], use_container_width=True, height=360)
                else:
                    st.info("No dataset rule matched this text.")

        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🔐 Login / Sign-in Alert Log</div>', unsafe_allow_html=True)

        if LOGIN_ALERT_FILE.exists():
            login_alerts_df = pd.read_csv(LOGIN_ALERT_FILE, encoding="utf-8-sig")
            st.dataframe(login_alerts_df.tail(50), use_container_width=True, height=260)
        else:
            st.info("No login/sign-in alerts recorded yet.")

        st.markdown("</div>", unsafe_allow_html=True)

    with tab7:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🧠 Rule-Based Threat Detection Engine</div>', unsafe_allow_html=True)

        st.write("Hybrid detection layer for phishing, social engineering, Telegram indicators, suspicious links, and port/protocol checks.")

        rb_text = st.text_area(
            "Message / Telegram Post / Suspicious Text",
            placeholder="Example: اضغط على الرابط للتحقق من حسابك عبر تلجرام https://t.me/support_login",
            height=160,
            key="rule_based_text"
        )

        rb_port = st.text_input(
            "Optional Port Check",
            placeholder="Example: 443 / 80 / 3389 / 4444",
            key="rule_based_port"
        )

        rb_source = st.selectbox(
            "Source",
            ["manual", "telegram", "web", "network", "victim_report"],
            key="rule_based_source"
        )

        if st.button("Run Rule-Based Detection", use_container_width=True, key="run_rule_based_detection"):
            if not rb_text.strip() and not rb_port.strip():
                st.error("Please enter text or port to analyze.")
            else:
                rb_result = analyze_rule_based(
                    text=rb_text,
                    port=rb_port,
                    source=rb_source
                )

                risk_class = get_risk_pill_class(rb_result["rule_risk_level"])

                st.markdown(
                    f'<div class="risk-pill {risk_class}">{rb_result["rule_risk_level"]}</div>',
                    unsafe_allow_html=True
                )

                if rb_result["rule_risk_level"] == "High":
                    st.error("🚨 HIGH RISK RULE-BASED ALERT TRIGGERED")
                elif rb_result["rule_risk_level"] == "Medium":
                    st.warning("⚠️ Suspicious activity detected by rule-based engine")
                else:
                    st.success("✅ No critical rule-based threat detected")

                c1, c2, c3 = st.columns(3)

                with c1:
                    st.markdown(f"""
                    <div class="metric-box">
                        <div class="metric-label">Rule Score</div>
                        <div class="metric-value">{rb_result["rule_score"]}</div>
                        <div class="metric-sub">Calculated from matched rules</div>
                    </div>
                    """, unsafe_allow_html=True)

                with c2:
                    st.markdown(f"""
                    <div class="metric-box">
                        <div class="metric-label">Matched Rules</div>
                        <div class="metric-value">{len(rb_result["matched_rules"].split(","))}</div>
                        <div class="metric-sub">{rb_result["matched_rules"]}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with c3:
                    st.markdown(f"""
                    <div class="metric-box">
                        <div class="metric-label">Port / Protocol</div>
                        <div class="metric-value">{rb_result["port"]}</div>
                        <div class="metric-sub">{rb_result["port_service"]}</div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="explain-panel">
                    <div class="panel-key">🎣 Phishing Keywords</div>
                    <div class="panel-value">{rb_result["phishing_keywords"] or "No phishing keywords detected"}</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="explain-panel">
                    <div class="panel-key">👥 Social Engineering Indicators</div>
                    <div class="panel-value">{rb_result["social_engineering_hits"] or "No social engineering indicators detected"}</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="explain-panel">
                    <div class="panel-key">✈️ Telegram Indicators</div>
                    <div class="panel-value">{rb_result["telegram_indicators"] or "No Telegram indicators detected"}</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="law-panel">
                    <div class="panel-key">🌐 Port / HTTPS Check</div>
                    <div class="panel-value">
                        Port: {rb_result["port"]}<br>
                        Service: {rb_result["port_service"]}<br>
                        Recommendation: {rb_result["port_recommendation"]}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                if rb_result["phishing_urls"]:
                    st.write("**Suspicious URLs:**")
                    st.dataframe(pd.DataFrame(rb_result["phishing_urls"]), use_container_width=True)

        st.markdown("</div>", unsafe_allow_html=True)

    with st.expander('✈️ Telegram Live Feed', expanded=True):
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">✈️ Telegram Live Feed</div>', unsafe_allow_html=True)

        if st.button("🔄 Refresh Telegram Feed", use_container_width=True, key="refresh_telegram_live_feed"):
            refresh_data()
            st.rerun()

        telegram_df = load_csv(TELEGRAM_LIVE_FILE)

        if telegram_df.empty:
            st.info("No Telegram messages captured yet. Keep telegram_listener.py running and send a Telegram message.")
        else:
            st.markdown(f"""
            <div class="status-ok">
                Real Telegram messages captured: <b>{len(telegram_df)}</b>
            </div>
            """, unsafe_allow_html=True)

            preferred_cols = [
                "time",
                "uid",
                "telegram_sender_id",
                "telegram_chat_id",
                "telegram_message_id",
                "risk",
                "score",
                "alert",
                "matched_rules",
                "urls",
                "ports",
                "message_text",
                "url_analysis",
                "port_analysis",
            ]

            existing_cols = [c for c in preferred_cols if c in telegram_df.columns]
            st.dataframe(telegram_df[existing_cols].tail(100), use_container_width=True, height=520)

        st.markdown("</div>", unsafe_allow_html=True)

    with st.expander('🚨 Real-Time Alerts', expanded=False):
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🚨 Real-Time Alerts Center</div>', unsafe_allow_html=True)

        if st.button("🔄 Refresh Alerts", use_container_width=True, key="refresh_realtime_alerts"):
            refresh_data()
            st.rerun()

        alerts_df = load_csv(ALERTS_FILE)

        if alerts_df.empty:
            st.info("No real-time alerts yet.")
        else:
            high_count = len(alerts_df)

            st.markdown(f"""
            <div class="status-alert">
                🚨 Active Alert Log Detected: <b>{high_count}</b> alert records
            </div>
            """, unsafe_allow_html=True)

            st.components.v1.html("""
            <div style="padding:14px;border-radius:14px;background:#111827;color:white;border:1px solid #ef4444;">
                <b>🚨 High Risk Alert Sound</b><br><br>
                <button onclick="playAlarm()" style="
                    background:#ef4444;
                    color:white;
                    border:none;
                    padding:10px 18px;
                    border-radius:10px;
                    font-weight:bold;
                    cursor:pointer;
                ">
                    🔊 Enable / Play Alarm Sound
                </button>
            </div>

            <script>
            function playAlarm() {
                const audioCtx = new (window.AudioContext || window.webkitAudioContext)();

                function beep(start, freq, duration) {
                    const osc = audioCtx.createOscillator();
                    const gain = audioCtx.createGain();

                    osc.type = "square";
                    osc.frequency.value = freq;

                    gain.gain.setValueAtTime(0.25, audioCtx.currentTime + start);
                    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + start + duration);

                    osc.connect(gain);
                    gain.connect(audioCtx.destination);

                    osc.start(audioCtx.currentTime + start);
                    osc.stop(audioCtx.currentTime + start + duration);
                }

                beep(0.0, 880, 0.25);
                beep(0.35, 880, 0.25);
                beep(0.70, 1200, 0.35);
                beep(1.20, 880, 0.25);
                beep(1.55, 1200, 0.35);
            }
            </script>
            """, height=120)

            preferred_cols = [
                "time",
                "source",
                "uid",
                "risk",
                "score",
                "matched_rules",
                "urls",
                "ports",
                "chat_title",
                "sender_name",
                "email_status",
                "telegram_status",
                "message_text",
            ]

            existing_cols = [c for c in preferred_cols if c in alerts_df.columns]
            st.dataframe(alerts_df[existing_cols].tail(100), use_container_width=True, height=520)

            last_alert = alerts_df.tail(1).iloc[0]

            st.markdown(f"""
            <div class="law-panel">
                <div class="panel-key">Latest Alert Summary</div>
                <div class="panel-value">
                    UID: {last_alert.get("uid", "")}<br>
                    Risk: {last_alert.get("risk", "")}<br>
                    Rules: {last_alert.get("matched_rules", "")}<br>
                    URLs: {last_alert.get("urls", "")}<br>
                    Ports: {last_alert.get("ports", "")}
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

    with st.expander('🧬 Threat Intelligence', expanded=False):
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🧬 Threat Intelligence Center</div>', unsafe_allow_html=True)

        if st.button("🔄 Refresh Threat Intelligence", use_container_width=True, key="refresh_threat_intel"):
            refresh_data()
            st.rerun()

        ti_df = load_csv(THREAT_INTEL_FILE)

        if ti_df.empty:
            st.info("No Threat Intelligence results yet. Send a Telegram message with a URL.")
        else:
            high_ti = len(ti_df[ti_df["ti_risk"].astype(str) == "High"]) if "ti_risk" in ti_df.columns else 0
            medium_ti = len(ti_df[ti_df["ti_risk"].astype(str) == "Medium"]) if "ti_risk" in ti_df.columns else 0

            c1, c2, c3 = st.columns(3)

            with c1:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">TI Checks</div>
                    <div class="metric-value">{len(ti_df)}</div>
                    <div class="metric-sub">External reputation checks</div>
                </div>
                """, unsafe_allow_html=True)

            with c2:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">High TI Risk</div>
                    <div class="metric-value">{high_ti}</div>
                    <div class="metric-sub">Confirmed or strong external hits</div>
                </div>
                """, unsafe_allow_html=True)

            with c3:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Medium TI Risk</div>
                    <div class="metric-value">{medium_ti}</div>
                    <div class="metric-sub">Suspicious external intelligence</div>
                </div>
                """, unsafe_allow_html=True)

            preferred_cols = [
                "time",
                "uid",
                "url",
                "domain",
                "resolved_ip",
                "ti_risk",
                "ti_score",
                "ti_reasons",
                "virustotal_status",
                "virustotal_malicious",
                "virustotal_suspicious",
                "urlhaus_status",
                "urlhaus_malicious",
                "phishtank_status",
                "phishtank_malicious",
                "abuseipdb_status",
                "abuseipdb_score",
            ]

            existing_cols = [c for c in preferred_cols if c in ti_df.columns]
            st.dataframe(ti_df[existing_cols].tail(100), use_container_width=True, height=520)

        st.markdown("</div>", unsafe_allow_html=True)

    with st.expander('🤖 Hybrid AI Detection', expanded=False):
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🤖 Hybrid AI + Rule-Based Detection</div>', unsafe_allow_html=True)

        if st.button("🔄 Refresh Hybrid Results", use_container_width=True, key="refresh_hybrid_results"):
            refresh_data()
            st.rerun()

        hybrid_df = load_csv(TELEGRAM_LIVE_FILE)

        if hybrid_df.empty:
            st.info("No hybrid Telegram detections yet. Run telegram_listener.py and send a Telegram message.")
        else:
            high_count = len(hybrid_df[hybrid_df["hybrid_risk"].astype(str) == "High"]) if "hybrid_risk" in hybrid_df.columns else 0
            medium_count = len(hybrid_df[hybrid_df["hybrid_risk"].astype(str) == "Medium"]) if "hybrid_risk" in hybrid_df.columns else 0

            c1, c2, c3 = st.columns(3)

            with c1:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Hybrid Records</div>
                    <div class="metric-value">{len(hybrid_df)}</div>
                    <div class="metric-sub">Telegram + AI + Rule-Based</div>
                </div>
                """, unsafe_allow_html=True)

            with c2:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">High Hybrid Risk</div>
                    <div class="metric-value">{high_count}</div>
                    <div class="metric-sub">Strong combined detection</div>
                </div>
                """, unsafe_allow_html=True)

            with c3:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Medium Hybrid Risk</div>
                    <div class="metric-value">{medium_count}</div>
                    <div class="metric-sub">Suspicious combined evidence</div>
                </div>
                """, unsafe_allow_html=True)

            preferred_cols = [
                "time",
                "uid",
                "chat_type",
                "sender_name",
                "chat_title",
                "hybrid_risk",
                "hybrid_score",
                "hybrid_alert",
                "hybrid_reason",
                "rule_risk",
                "rule_score",
                "matched_rules",
                "ai_status",
                "ai_label",
                "ai_risk",
                "ai_confidence",
                "urls",
                "ports",
                "message_text",
            ]

            existing_cols = [c for c in preferred_cols if c in hybrid_df.columns]
            st.dataframe(hybrid_df[existing_cols].tail(100), use_container_width=True, height=540)

        st.markdown("</div>", unsafe_allow_html=True)

    with st.expander('👤 Real User Tracking', expanded=False):
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">👤 Real User Tracking Center</div>', unsafe_allow_html=True)

        if st.button("🔄 Refresh User Tracking", use_container_width=True, key="refresh_user_tracking"):
            refresh_data()
            st.rerun()

        tracking_df = load_csv(USER_TRACKING_FILE)

        if tracking_df.empty:
            st.info("No real user tracking records yet. Run telegram_listener.py and send a Telegram message.")
        else:
            unique_users = tracking_df["uid"].nunique() if "uid" in tracking_df.columns else 0
            unique_sessions = tracking_df["session_id"].nunique() if "session_id" in tracking_df.columns else 0
            high_risk = len(tracking_df[tracking_df["risk"].astype(str) == "High"]) if "risk" in tracking_df.columns else 0

            c1, c2, c3, c4 = st.columns(4)

            with c1:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Tracked Events</div>
                    <div class="metric-value">{len(tracking_df)}</div>
                    <div class="metric-sub">Telegram monitoring records</div>
                </div>
                """, unsafe_allow_html=True)

            with c2:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Unique UIDs</div>
                    <div class="metric-value">{unique_users}</div>
                    <div class="metric-sub">Telegram users tracked</div>
                </div>
                """, unsafe_allow_html=True)

            with c3:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Sessions</div>
                    <div class="metric-value">{unique_sessions}</div>
                    <div class="metric-sub">Device/session tracking</div>
                </div>
                """, unsafe_allow_html=True)

            with c4:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">High Risk</div>
                    <div class="metric-value">{high_risk}</div>
                    <div class="metric-sub">Critical user events</div>
                </div>
                """, unsafe_allow_html=True)

            preferred_cols = [
                "time",
                "platform",
                "session_id",
                "device_fingerprint",
                "local_ip",
                "uid",
                "telegram_sender_id",
                "sender_name",
                "telegram_chat_id",
                "chat_title",
                "chat_type",
                "message_id",
                "risk",
                "threat_type",
                "matched_rules",
                "urls",
                "ports",
                "alert",
                "message_text",
            ]

            existing_cols = [c for c in preferred_cols if c in tracking_df.columns]
            st.dataframe(tracking_df[existing_cols].tail(150), use_container_width=True, height=560)

            st.markdown('<div class="card-title">🔎 User Investigation Search</div>', unsafe_allow_html=True)

            search_uid = st.text_input("Search by UID / Sender / Chat / URL", key="tracking_search")

            if search_uid.strip():
                filtered = tracking_df[
                    tracking_df.astype(str).apply(
                        lambda row: row.str.contains(search_uid, case=False, na=False).any(),
                        axis=1
                    )
                ]

                st.dataframe(filtered[existing_cols].tail(100), use_container_width=True, height=350)

        st.markdown("</div>", unsafe_allow_html=True)

    with st.expander('🧾 Incident Center', expanded=False):
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🧾 Incident Center - SIEM Case Management</div>', unsafe_allow_html=True)

        if st.button("🔄 Refresh Incidents", use_container_width=True, key="refresh_incident_center"):
            refresh_data()
            st.rerun()

        incidents_df = load_csv(INCIDENT_CENTER_FILE)

        if incidents_df.empty:
            st.info("No incidents created yet. Send a high-risk Telegram message.")
        else:
            open_count = len(incidents_df[incidents_df["status"].astype(str) == "Open"]) if "status" in incidents_df.columns else 0
            high_count = len(incidents_df[incidents_df["risk_level"].astype(str) == "High"]) if "risk_level" in incidents_df.columns else 0
            unique_users = incidents_df["telegram_uid"].nunique() if "telegram_uid" in incidents_df.columns else 0
            law_count = incidents_df["law_category"].nunique() if "law_category" in incidents_df.columns else 0

            c1, c2, c3, c4 = st.columns(4)

            with c1:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Total Incidents</div>
                    <div class="metric-value">{len(incidents_df)}</div>
                    <div class="metric-sub">SIEM-style cases</div>
                </div>
                """, unsafe_allow_html=True)

            with c2:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Open Cases</div>
                    <div class="metric-value">{open_count}</div>
                    <div class="metric-sub">Require analyst review</div>
                </div>
                """, unsafe_allow_html=True)

            with c3:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">High Risk</div>
                    <div class="metric-value">{high_count}</div>
                    <div class="metric-sub">Critical incidents</div>
                </div>
                """, unsafe_allow_html=True)

            with c4:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Tracked UIDs</div>
                    <div class="metric-value">{unique_users}</div>
                    <div class="metric-sub">Telegram identities</div>
                </div>
                """, unsafe_allow_html=True)

            preferred_cols = [
                "incident_time",
                "incident_id",
                "status",
                "severity",
                "risk_level",
                "telegram_uid",
                "sender_name",
                "chat_title",
                "chat_type",
                "evidence_urls",
                "evidence_ports",
                "ai_classification",
                "hybrid_score",
                "law_category",
                "law_reference",
                "evidence_rules",
                "evidence_text",
            ]

            existing_cols = [c for c in preferred_cols if c in incidents_df.columns]
            st.dataframe(incidents_df[existing_cols].tail(150), use_container_width=True, height=560)

            st.markdown('<div class="card-title">🔎 Incident Investigation</div>', unsafe_allow_html=True)

            selected_incident = st.selectbox(
                "Select Incident ID",
                incidents_df["incident_id"].dropna().astype(str).tolist(),
                key="incident_selectbox"
            )

            selected = incidents_df[incidents_df["incident_id"].astype(str) == selected_incident]

            if not selected.empty:
                item = selected.iloc[0]

                st.markdown(f"""
                <div class="law-panel">
                    <div class="panel-key">Incident Summary</div>
                    <div class="panel-value">
                        Incident ID: {item.get("incident_id", "")}<br>
                        Status: {item.get("status", "")}<br>
                        Risk: {item.get("risk_level", "")}<br>
                        Telegram UID: {item.get("telegram_uid", "")}<br>
                        Sender: {item.get("sender_name", "")}<br>
                        Chat: {item.get("chat_title", "")}<br>
                        URL: {item.get("evidence_urls", "")}<br>
                        Port: {item.get("evidence_ports", "")}<br>
                        AI Classification: {item.get("ai_classification", "")}<br>
                        Law: {item.get("law_reference", "")}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="explain-panel">
                    <div class="panel-key">Evidence</div>
                    <div class="panel-value">
                        Rules: {item.get("evidence_rules", "")}<br><br>
                        Message: {item.get("evidence_text", "")}<br><br>
                        Legal Note: {item.get("legal_note", "")}<br><br>
                        Analyst Action: {item.get("analyst_action", "")}
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

    with st.expander('⚖️ Jordanian Law Engine', expanded=False):
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">⚖️ Jordanian Law Engine</div>', unsafe_allow_html=True)

        law_text = st.text_area(
            "Enter message/evidence for legal mapping",
            placeholder="مثال: إذا ما دفعت رح أنشر صورك على تلجرام",
            height=160,
            key="law_engine_text"
        )

        law_rules = st.text_input(
            "Matched Rules / AI Classification",
            placeholder="blackmail, harassment, defamation, phishing",
            key="law_engine_rules"
        )

        if st.button("⚖️ Run Jordanian Law Mapping", use_container_width=True, key="run_jordan_law_engine"):
            law_result = detect_law_case(
                text=law_text,
                matched_rules=law_rules,
                ai_label=law_rules
            )

            st.markdown(f"""
            <div class="law-panel">
                <div class="panel-key">Jordanian Cybercrime Law Mapping</div>
                <div class="panel-value">
                    Crime: {law_result.get("crime", "")}<br>
                    Article: {law_result.get("article", "")}<br>
                    Penalty: {law_result.get("penalty", "")}<br>
                    Severity: {law_result.get("severity", "")}<br>
                    Matched Keywords: {law_result.get("matched_keywords", "")}
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown(f"""
            <div class="explain-panel">
                <div class="panel-key">Legal Mapping Explanation</div>
                <div class="panel-value">{law_result.get("legal_mapping", "")}</div>
            </div>
            """, unsafe_allow_html=True)

            if "all_matches" in law_result:
                st.write("**All Legal Matches:**")
                st.dataframe(pd.DataFrame(law_result["all_matches"]), use_container_width=True)

        st.markdown('<div class="card-title">📚 Law Engine Reference Table</div>', unsafe_allow_html=True)

        reference_df = pd.DataFrame([
            {
                "Case": "Blackmail / ابتزاز",
                "Article": "Article 18",
                "Penalty": "Imprisonment not less than 1 year + fine, verify official Arabic text",
                "Severity": "High"
            },
            {
                "Case": "Harassment / إساءة / تهديد",
                "Article": "Article 15",
                "Penalty": "Imprisonment not less than 3 months or fine 5,000–20,000 JOD or both",
                "Severity": "Medium to High"
            },
            {
                "Case": "Defamation / تشهير / ذم / قدح",
                "Article": "Article 11",
                "Penalty": "Imprisonment not less than 3 months or fine 2,500–25,000 JOD or both",
                "Severity": "Medium"
            },
            {
                "Case": "Phishing / OTP theft",
                "Article": "Articles 3, 8, 9",
                "Penalty": "Depends on unauthorized access, fraud, or financial impact",
                "Severity": "High"
            },
        ])

        st.dataframe(reference_df, use_container_width=True)

        st.markdown("</div>", unsafe_allow_html=True)

    with st.expander('🎯 Red Team Simulation', expanded=False):
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🎯 Red Team Simulation Center</div>', unsafe_allow_html=True)

        st.write("Safe red-team simulation module for phishing, fake login, social engineering, suspicious Telegram campaigns, and blackmail detection. This does not collect credentials or attack real users.")

        c1, c2, c3 = st.columns(3)

        with c1:
            if st.button("🚀 Run Random Simulation", use_container_width=True, key="run_random_redteam"):
                result = run_random_simulation()
                st.success(f"Simulation completed: {result.get('scenario_name')} | Risk={result.get('risk')}")

        with c2:
            if st.button("🔥 Run Full Red Team Campaign", use_container_width=True, key="run_all_redteam"):
                results = run_all_simulations()
                st.success(f"Full campaign completed: {len(results)} simulations executed.")

        with c3:
            if st.button("🔄 Refresh Red Team Results", use_container_width=True, key="refresh_redteam_results"):
                refresh_data()
                st.rerun()

        red_df = load_csv(REDTEAM_FILE)

        if red_df.empty:
            st.info("No red team simulations yet.")
        else:
            high_count = len(red_df[red_df["risk"].astype(str) == "High"]) if "risk" in red_df.columns else 0
            incidents = len(red_df[red_df["incident_created"].astype(str) == "True"]) if "incident_created" in red_df.columns else 0
            unique_attacks = red_df["attack_type"].nunique() if "attack_type" in red_df.columns else 0

            k1, k2, k3, k4 = st.columns(4)

            with k1:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Simulations</div>
                    <div class="metric-value">{len(red_df)}</div>
                    <div class="metric-sub">Executed test attacks</div>
                </div>
                """, unsafe_allow_html=True)

            with k2:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">High Risk</div>
                    <div class="metric-value">{high_count}</div>
                    <div class="metric-sub">Detected as critical</div>
                </div>
                """, unsafe_allow_html=True)

            with k3:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Incidents</div>
                    <div class="metric-value">{incidents}</div>
                    <div class="metric-sub">Created in SIEM center</div>
                </div>
                """, unsafe_allow_html=True)

            with k4:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Attack Types</div>
                    <div class="metric-value">{unique_attacks}</div>
                    <div class="metric-sub">Covered scenarios</div>
                </div>
                """, unsafe_allow_html=True)

            preferred_cols = [
                "time",
                "simulation_id",
                "uid",
                "scenario_name",
                "attack_type",
                "source",
                "risk",
                "score",
                "alert",
                "matched_rules",
                "urls",
                "ports",
                "ai_label",
                "ai_risk",
                "incident_created",
                "incident_id",
                "message_text",
            ]

            existing_cols = [c for c in preferred_cols if c in red_df.columns]
            st.dataframe(red_df[existing_cols].tail(150), use_container_width=True, height=560)

            st.markdown('<div class="card-title">🧪 Manual Safe Simulation</div>', unsafe_allow_html=True)

            manual_text = st.text_area(
                "Enter a simulated attack message",
                placeholder="مثال: لا تخبر أحد، ابعتلي كود التحقق عبر http://fake-login.com:8080/verify tcp/4444",
                height=140,
                key="manual_redteam_text"
            )

            manual_type = st.selectbox(
                "Attack Type",
                ["phishing", "fake_login", "social_engineering", "blackmail", "telegram_campaign"],
                key="manual_redteam_type"
            )

            if st.button("Run Manual Safe Simulation", use_container_width=True, key="run_manual_safe_redteam"):
                from src.red_team_simulator import run_single_simulation

                scenario = {
                    "name": "Manual Safe Simulation",
                    "attack_type": manual_type,
                    "text": manual_text,
                    "source": "manual_red_team"
                }

                if not manual_text.strip():
                    st.error("Enter a simulated message first.")
                else:
                    result = run_single_simulation(scenario)
                    st.success(f"Manual simulation completed. Risk={result.get('risk')} Incident={result.get('incident_id')}")

        st.markdown("</div>", unsafe_allow_html=True)

    with st.expander('🛡️ SOC Dashboard', expanded=False):
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🛡️ Enterprise SOC Dashboard</div>', unsafe_allow_html=True)

        if st.button("🔄 Refresh SOC Dashboard", use_container_width=True, key="refresh_soc_dashboard"):
            refresh_data()
            st.rerun()

        soc_df = load_csv(TELEGRAM_LIVE_FILE)
        incident_df = load_csv(INCIDENT_CENTER_FILE)
        alerts_df = load_csv(ALERTS_FILE)

        if soc_df.empty:
            st.info("No SOC telemetry yet. Run telegram_listener.py and send Telegram messages.")
        else:
            total_events = len(soc_df)

            high_risk = len(
                soc_df[soc_df["risk"].astype(str).str.lower() == "high"]
            ) if "risk" in soc_df.columns else 0

            medium_risk = len(
                soc_df[soc_df["risk"].astype(str).str.lower() == "medium"]
            ) if "risk" in soc_df.columns else 0

            unique_users = soc_df["uid"].nunique() if "uid" in soc_df.columns else 0

            active_incidents = len(incident_df) if not incident_df.empty else 0
            active_alerts = len(alerts_df) if not alerts_df.empty else 0

            k1, k2, k3, k4, k5, k6 = st.columns(6)

            with k1:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Events</div>
                    <div class="metric-value">{total_events}</div>
                    <div class="metric-sub">Live telemetry</div>
                </div>
                """, unsafe_allow_html=True)

            with k2:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">High Risk</div>
                    <div class="metric-value">{high_risk}</div>
                    <div class="metric-sub">Critical threats</div>
                </div>
                """, unsafe_allow_html=True)

            with k3:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Medium Risk</div>
                    <div class="metric-value">{medium_risk}</div>
                    <div class="metric-sub">Suspicious events</div>
                </div>
                """, unsafe_allow_html=True)

            with k4:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Users</div>
                    <div class="metric-value">{unique_users}</div>
                    <div class="metric-sub">Tracked Telegram UIDs</div>
                </div>
                """, unsafe_allow_html=True)

            with k5:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Incidents</div>
                    <div class="metric-value">{active_incidents}</div>
                    <div class="metric-sub">SIEM cases</div>
                </div>
                """, unsafe_allow_html=True)

            with k6:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">Alerts</div>
                    <div class="metric-value">{active_alerts}</div>
                    <div class="metric-sub">Real-time alerts</div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown('<div class="card-title">📈 Threat Timeline</div>', unsafe_allow_html=True)

            if "time" in soc_df.columns and "risk" in soc_df.columns:
                timeline_df = soc_df.copy()

                timeline_df["time"] = pd.to_datetime(
                    timeline_df["time"],
                    errors="coerce"
                )

                timeline_group = (
                    timeline_df.groupby(
                        [timeline_df["time"].dt.strftime("%H:%M"), "risk"]
                    )
                    .size()
                    .reset_index(name="count")
                )

                fig_timeline = px.line(
                    timeline_group,
                    x="time",
                    y="count",
                    color="risk",
                    markers=True,
                    title="Threat Timeline"
                )

                st.plotly_chart(fig_timeline, use_container_width=True)

            c_left, c_right = st.columns(2)

            with c_left:
                st.markdown('<div class="card-title">🔥 Risk Heatmap</div>', unsafe_allow_html=True)

                if "chat_type" in soc_df.columns and "risk" in soc_df.columns:
                    heatmap_data = (
                        soc_df.groupby(["chat_type", "risk"])
                        .size()
                        .reset_index(name="count")
                    )

                    heatmap_pivot = heatmap_data.pivot(
                        index="chat_type",
                        columns="risk",
                        values="count"
                    ).fillna(0)

                    fig_heat = px.imshow(
                        heatmap_pivot,
                        text_auto=True,
                        aspect="auto",
                        title="Threat Heatmap"
                    )

                    st.plotly_chart(fig_heat, use_container_width=True)

            with c_right:
                st.markdown('<div class="card-title">🎯 Attack Types</div>', unsafe_allow_html=True)

                if "ai_label" in soc_df.columns:
                    attack_df = (
                        soc_df["ai_label"]
                        .astype(str)
                        .value_counts()
                        .reset_index()
                    )

                    attack_df.columns = ["attack_type", "count"]

                    fig_pie = px.pie(
                        attack_df,
                        names="attack_type",
                        values="count",
                        title="Attack Classification"
                    )

                    st.plotly_chart(fig_pie, use_container_width=True)

            st.markdown('<div class="card-title">🌐 Suspicious URLs</div>', unsafe_allow_html=True)

            if "urls" in soc_df.columns:
                urls_df = soc_df.copy()
                urls_df = urls_df[urls_df["urls"].astype(str).str.len() > 0]

                if not urls_df.empty:
                    top_urls = (
                        urls_df["urls"]
                        .astype(str)
                        .value_counts()
                        .reset_index()
                        .head(10)
                    )

                    top_urls.columns = ["url", "count"]

                    fig_urls = px.bar(
                        top_urls,
                        x="url",
                        y="count",
                        title="Most Detected URLs"
                    )

                    st.plotly_chart(fig_urls, use_container_width=True)

            st.markdown('<div class="card-title">🚪 Most Used Ports</div>', unsafe_allow_html=True)

            if "ports" in soc_df.columns:
                ports_df = soc_df.copy()
                ports_df = ports_df[ports_df["ports"].astype(str).str.len() > 0]

                if not ports_df.empty:
                    top_ports = (
                        ports_df["ports"]
                        .astype(str)
                        .value_counts()
                        .reset_index()
                        .head(10)
                    )

                    top_ports.columns = ["port", "count"]

                    fig_ports = px.bar(
                        top_ports,
                        x="port",
                        y="count",
                        title="Most Detected Ports"
                    )

                    st.plotly_chart(fig_ports, use_container_width=True)

            st.markdown('<div class="card-title">🚨 Active High-Risk Events</div>', unsafe_allow_html=True)

            high_df = soc_df[
                soc_df["risk"].astype(str).str.lower() == "high"
            ] if "risk" in soc_df.columns else pd.DataFrame()

            if high_df.empty:
                st.success("No active high-risk events currently.")
            else:
                preferred_cols = [
                    "time",
                    "uid",
                    "chat_type",
                    "sender_name",
                    "chat_title",
                    "risk",
                    "score",
                    "urls",
                    "ports",
                    "matched_rules",
                    "message_text",
                ]

                existing_cols = [c for c in preferred_cols if c in high_df.columns]

                st.dataframe(
                    high_df[existing_cols].tail(100),
                    use_container_width=True,
                    height=420
                )

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

    .auth-choice-card {
        background: linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.02));
        border: 1px solid rgba(255,255,255,0.09);
        border-radius: 24px;
        padding: 18px;
        margin-bottom: 14px;
        box-shadow: 0 14px 40px rgba(0,0,0,0.22);
    }

    .auth-mini-title {
        font-size: 0.92rem;
        color: #9fc9ff !important;
        font-weight: 700;
        margin-bottom: 6px;
    }

    .auth-mini-text {
        font-size: 0.85rem;
        color: #bed0f3 !important;
        line-height: 1.5;
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

if not st.session_state.authenticated and not st.session_state.signin_completed:
    device_info = get_device_info()

    st.markdown('<div class="login-box">', unsafe_allow_html=True)

    st.markdown("""
    <div class="main-hero">
        <h1>CyberShieldX Secure Access</h1>
        <p>Enterprise authentication portal for AI-powered cyber threat monitoring, OTP verification, Telegram threat analysis, and Jordanian law mapping.</p>
    </div>
    """, unsafe_allow_html=True)

    auth_mode = st.radio(
        "Authentication Mode",
        ["Login", "Sign in"],
        horizontal=True,
        key="auth_mode_selector"
    )

    auth_col1, auth_col2 = st.columns(2)

    with auth_col1:
        username = st.text_input(
            "Username / Email",
            placeholder="example@company.com",
            key="auth_username"
        )

    with auth_col2:
        password = st.text_input(
            "Password",
            type="password",
            placeholder="Enter password",
            key="auth_password"
        )

    st.markdown(f"""
    <div class="law-panel">
        <div class="panel-key">🆔 Secure Device UID</div>
        <div class="panel-value">{device_info["device_uid"]}</div>
    </div>
    """, unsafe_allow_html=True)

    st.caption(f"Hostname: {device_info['hostname']} | OS: {device_info['os']} | Machine: {device_info['machine']}")

    if auth_mode == "Sign in":

        st.markdown("""
        <div class="auth-choice-card">
            <div class="auth-mini-title">Create Secure Session</div>
            <div class="auth-mini-text">
            Register this device and continue to OTP verification.
            </div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Create Account / Sign in", use_container_width=True, key="device_signin_btn"):

            if not username.strip():
                st.error("Username or email is required.")
                st.stop()

            if not password.strip():
                st.error("Password is required.")
                st.stop()

            log_login_alert(
                device_info["device_uid"],
                "sign_in",
                "success",
                f"New sign-in session for {username}"
            )

            st.session_state.device_uid = device_info["device_uid"]
            st.session_state.signin_completed = True

            st.success("Sign in successful. Proceeding to OTP verification...")
            st.rerun()

    else:

        st.markdown("""
        <div class="auth-choice-card">
            <div class="auth-mini-title">Existing Dashboard Access</div>
            <div class="auth-mini-text">
            Continue securely using username/email and password before OTP verification.
            </div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Login to Dashboard", use_container_width=True, key="device_login_btn"):

            if not username.strip():
                st.error("Username or email is required.")
                st.stop()

            if not password.strip():
                st.error("Password is required.")
                st.stop()

            log_login_alert(
                device_info["device_uid"],
                "login",
                "success",
                f"Login session for {username}"
            )

            st.session_state.device_uid = device_info["device_uid"]
            st.session_state.signin_completed = True

            st.success("Login successful. Proceeding to OTP verification...")
            st.rerun()


    st.markdown(f"""
    <div class="law-panel">
        <div class="panel-key">🆔 Secure Device UID</div>
        <div class="panel-value">{device_info["device_uid"]}</div>
    </div>
    """, unsafe_allow_html=True)

    st.write("**Hostname:**", device_info["hostname"])
    st.write("**OS:**", device_info["os"])
    st.write("**Machine:**", device_info["machine"])

    col_signin, col_login = st.columns(2)

    with col_signin:
        st.markdown("""
        <div class="auth-choice-card">
            <div class="auth-mini-title">New secure session</div>
            <div class="auth-mini-text">Use this option to register this device session before OTP verification.</div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Create Session / Sign in", use_container_width=True, key="device_signin_btn"):
            log_login_alert(device_info["device_uid"], "sign_in", "success", "Device sign-in completed")
            st.session_state.device_uid = device_info["device_uid"]
            st.session_state.signin_completed = True
            st.success("Device sign-in completed.")
            st.rerun()

    with col_login:
        st.markdown("""
        <div class="auth-choice-card">
            <div class="auth-mini-title">Existing dashboard access</div>
            <div class="auth-mini-text">Continue to OTP login using the automatically detected device identity.</div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Login to Dashboard", use_container_width=True, key="device_login_btn"):
            log_login_alert(device_info["device_uid"], "login_opened", "success", "Login screen opened from device")
            st.session_state.device_uid = device_info["device_uid"]
            st.session_state.signin_completed = True
            st.success("Proceeding to OTP login.")
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

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

    login_uid = st.session_state.device_uid
    st.markdown(f"""
    <div class="law-panel">
        <div class="panel-key">🆔 Secure Device UID</div>
        <div class="panel-value">{login_uid}</div>
    </div>
    """, unsafe_allow_html=True)

    channel = st.selectbox(
        "Verification Channel",
        ["email", "smart_auto", "sms"],
        index=0,
        key="login_channel_select"
    )
    phone = st.text_input("Phone Number", placeholder="+9627XXXXXXXX", key="login_phone")
    email = st.text_input("Email Address", placeholder="name@example.com", key="login_email")

    alert_col1, alert_col2 = st.columns(2)

    with alert_col1:
        if st.button("🔐 Login Alert", use_container_width=True, key="main_login_alert_btn"):
            if not login_uid.strip():
                st.error("UID is required.")
            else:
                log_login_alert(login_uid, "login", "manual_alert", "Login alert from main OTP page")
                st.success("Login alert saved.")

    with alert_col2:
        if st.button("📝 Sign-in Alert", use_container_width=True, key="main_signin_alert_btn"):
            if not login_uid.strip():
                st.error("UID is required.")
            else:
                log_login_alert(login_uid, "sign_in", "manual_alert", "Sign-in alert from main OTP page")
                st.success("Sign-in alert saved.")

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
            if not login_uid.strip():
                st.error("UID is required before sending OTP.")
                st.stop()

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
                log_login_alert(login_uid, "login", "expired", "OTP expired before verification")
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
                        log_login_alert(login_uid, "login", "success", "OTP login successful")
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
                    rule_result = analyze_rule_based(user_text.strip(), source="user")
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
                    <div class="panel-key">🧠 Rule-Based Detection Result</div>
                    <div class="panel-value">
                        Rule Risk: {rule_result["rule_risk_level"]}<br>
                        Rule Score: {rule_result["rule_score"]}<br>
                        Matched Rules: {rule_result["matched_rules"]}<br>
                        Alert Status: {rule_result["alert_status"]}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                if rule_result["rule_risk_level"] == "High":
                    st.error("🚨 Rule-Based Engine triggered a high-risk alert.")
                elif rule_result["rule_risk_level"] == "Medium":
                    st.warning("⚠️ Rule-Based Engine detected suspicious indicators.")

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
                    rule_result = analyze_rule_based(incident_text.strip(), source="victim_report")

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
                    <div class="panel-key">🧠 Rule-Based Evidence</div>
                    <div class="panel-value">
                        Rule Risk: {rule_result["rule_risk_level"]}<br>
                        Rule Score: {rule_result["rule_score"]}<br>
                        Matched Rules: {rule_result["matched_rules"]}<br>
                        Telegram Indicators: {rule_result["telegram_indicators"] or "None"}<br>
                        Social Engineering: {rule_result["social_engineering_hits"] or "None"}
                    </div>
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
