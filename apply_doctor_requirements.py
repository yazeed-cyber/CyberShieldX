from pathlib import Path

p = Path("src/dashboard/dashboard_app.py")
text = p.read_text(encoding="utf-8")

if "from src.doctor_rule_based import" not in text:
    text = text.replace(
        "import streamlit as st\n",
        """import streamlit as st

from src.doctor_rule_based import (
    analyze_doctor_requirements,
    log_login_alert,
    LOGIN_ALERT_FILE,
)
""",
        1
    )

old_tabs = '''tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📡 Live Incidents",
        "🗂️ Original Dataset",
        "📊 Analytics",
        "🔎 Detail View",
        "🧾 OTP Audit Logs",
        "🚨 Victim Reports",
    ])'''

new_tabs = '''tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📡 Live Incidents",
        "🗂️ Original Dataset",
        "📊 Analytics",
        "🔎 Detail View",
        "🧾 OTP Audit Logs",
        "🚨 Victim Reports",
        "🧠 Doctor Required Rule-Based",
    ])'''

if old_tabs in text:
    text = text.replace(old_tabs, new_tabs, 1)

marker = '''    with tab6:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🚨 Victim Reports Control View</div>', unsafe_allow_html=True)

        if reports_df.empty:
            st.info("No victim reports found yet.")
        else:
            st.dataframe(reports_df, use_container_width=True, height=460)

        st.markdown("</div>", unsafe_allow_html=True)'''

replacement = '''    with tab6:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🚨 Victim Reports Control View</div>', unsafe_allow_html=True)

        if reports_df.empty:
            st.info("No victim reports found yet.")
        else:
            st.dataframe(reports_df, use_container_width=True, height=460)

        st.markdown("</div>", unsafe_allow_html=True)

    with tab7:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🧠 Doctor Required Rule-Based Center</div>', unsafe_allow_html=True)

        st.write("This section implements the doctor requirements: Login/Sign-in alerting, mandatory UID, rule-based filtering/search, text-to-rule matching, dataset rows as rules, port check, HTTPS check, Telegram, phishing, and social engineering.")

        uid = st.text_input(
            "UID / User ID - إجباري",
            placeholder="Example: user_202130045",
            key="doctor_uid"
        )

        rule_text = st.text_area(
            "Message Text as Rule-Based Input",
            placeholder="Example: لا تخبر أحد، ابعتلي كود التحقق عبر تلجرام https://t.me/support_login",
            height=170,
            key="doctor_rule_text"
        )

        col_a, col_b, col_c = st.columns(3)

        with col_a:
            port = st.text_input(
                "1) Port Check",
                placeholder="443 / 80 / 3389 / 4444",
                key="doctor_port"
            )

        with col_b:
            url = st.text_input(
                "2) HTTPS / URL Check",
                placeholder="https://example.com/login",
                key="doctor_url"
            )

        with col_c:
            search_filter = st.text_input(
                "Search / Filter in Rule-Based Dataset",
                placeholder="blackmail / ابتزاز / telegram",
                key="doctor_search_filter"
            )

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
                        Telegram: {result["telegram"] or "None"}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="law-panel">
                    <div class="panel-key">🌐 Port Rule-Based Check</div>
                    <div class="panel-value">
                        Port: {result["port_check"]["port"]}<br>
                        Service: {result["port_check"]["service"]}<br>
                        Recommendation: {result["port_check"]["recommendation"]}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.write("**HTTPS / URL Check:**")
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

        st.markdown("</div>", unsafe_allow_html=True)'''

if marker in text and "Doctor Required Rule-Based Center" not in text:
    text = text.replace(marker, replacement, 1)

p.write_text(text, encoding="utf-8")
print("✅ Doctor requirements added.")
