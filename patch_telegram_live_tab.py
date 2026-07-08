from pathlib import Path

p = Path("src/dashboard/dashboard_app.py")
text = p.read_text(encoding="utf-8")

if "TELEGRAM_LIVE_FILE" not in text:
    text = text.replace(
        'REPORTS_FILE = "outputs/reports_log.csv"',
        'REPORTS_FILE = "outputs/reports_log.csv"\nTELEGRAM_LIVE_FILE = "outputs/telegram_live_dataset.csv"',
        1
    )

old_tabs = '''tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📡 Live Incidents",
        "🗂️ Original Dataset",
        "📊 Analytics",
        "🔎 Detail View",
        "🧾 OTP Audit Logs",
        "🚨 Victim Reports",
        "🧠 Rule Based",
    ])'''

new_tabs = '''tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
        "📡 Live Incidents",
        "🗂️ Original Dataset",
        "📊 Analytics",
        "🔎 Detail View",
        "🧾 OTP Audit Logs",
        "🚨 Victim Reports",
        "🧠 Rule Based",
        "✈️ Telegram Live Feed",
    ])'''

if old_tabs in text:
    text = text.replace(old_tabs, new_tabs, 1)

old_tabs2 = '''tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📡 Live Incidents",
        "🗂️ Original Dataset",
        "📊 Analytics",
        "🔎 Detail View",
        "🧾 OTP Audit Logs",
        "🚨 Victim Reports",
        "🧠 Doctor Required Rule-Based",
    ])'''

new_tabs2 = '''tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
        "📡 Live Incidents",
        "🗂️ Original Dataset",
        "📊 Analytics",
        "🔎 Detail View",
        "🧾 OTP Audit Logs",
        "🚨 Victim Reports",
        "🧠 Rule Based",
        "✈️ Telegram Live Feed",
    ])'''

if old_tabs2 in text:
    text = text.replace(old_tabs2, new_tabs2, 1)

marker = '''        st.markdown("</div>", unsafe_allow_html=True)


st.markdown("""
<style>'''

telegram_tab = '''        st.markdown("</div>", unsafe_allow_html=True)

    with tab8:
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


st.markdown("""
<style>'''

if "Telegram Live Feed" not in text and marker in text:
    text = text.replace(marker, telegram_tab, 1)

p.write_text(text, encoding="utf-8")
print("✅ Telegram Live Feed tab added.")
