from pathlib import Path

path = Path("src/dashboard/dashboard_app.py")
text = path.read_text(encoding="utf-8")

# 1) import
if "from src.rule_engine import analyze_rule_based" not in text:
    text = text.replace(
        "import streamlit as st\n",
        "import streamlit as st\n\nfrom src.rule_engine import analyze_rule_based\n",
        1
    )

# 2) tabs
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
        "🧠 Rule-Based Engine",
    ])'''

if old_tabs in text:
    text = text.replace(old_tabs, new_tabs)

# 3) add tab7 before function ends, after tab6 block marker
marker = '''        st.markdown("</div>", unsafe_allow_html=True)


st.markdown("""
<style>'''

tab7_code = '''        st.markdown("</div>", unsafe_allow_html=True)

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


st.markdown("""
<style>'''

if 'key="rule_based_text"' not in text and marker in text:
    text = text.replace(marker, tab7_code, 1)

# 4) User hybrid
old_user = '''result = analyze_message_runtime(user_text.strip())
                st.success("Analysis completed.")'''

new_user = '''result = analyze_message_runtime(user_text.strip())
                    rule_result = analyze_rule_based(user_text.strip(), source="user")
                st.success("Analysis completed.")'''

if old_user in text and "rule_result = analyze_rule_based(user_text.strip(), source=\"user\")" not in text:
    text = text.replace(old_user, new_user, 1)

old_after_user = '''                st.markdown(f"""
                <div class="law-panel">
                    <div class="panel-key">⚖️ Jordanian Law Applied</div>
                    <div class="panel-value">{result.get("main_law", "")}</div>
                </div>
                """, unsafe_allow_html=True)'''

new_after_user = '''                st.markdown(f"""
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
                    st.warning("⚠️ Rule-Based Engine detected suspicious indicators.")'''

if old_after_user in text and "Rule-Based Detection Result" not in text:
    text = text.replace(old_after_user, new_after_user, 1)

# 5) Victim hybrid
old_victim = '''result = analyze_message_runtime(incident_text.strip())

                save_report_row(['''

new_victim = '''result = analyze_message_runtime(incident_text.strip())
                    rule_result = analyze_rule_based(incident_text.strip(), source="victim_report")

                save_report_row(['''

if old_victim in text and "rule_result = analyze_rule_based(incident_text.strip(), source=\"victim_report\")" not in text:
    text = text.replace(old_victim, new_victim, 1)

old_after_victim = '''                st.markdown(f"""
                <div class="law-panel">
                    <div class="panel-key">⚖️ Jordanian Law Applied</div>
                    <div class="panel-value">{result.get("main_law", "")}</div>
                </div>
                """, unsafe_allow_html=True)'''

new_after_victim = '''                st.markdown(f"""
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
                """, unsafe_allow_html=True)'''

# replace second occurrence for victim if possible
if text.count(old_after_victim) >= 2 and "Rule-Based Evidence" not in text:
    first = text.find(old_after_victim)
    second = text.find(old_after_victim, first + 1)
    text = text[:second] + new_after_victim + text[second + len(old_after_victim):]

path.write_text(text, encoding="utf-8")
print("✅ Rule-Based patch applied.")
