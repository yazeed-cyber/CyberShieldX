from pathlib import Path

p = Path("src/dashboard/dashboard_app.py")
text = p.read_text(encoding="utf-8")

old_block = '''        col_a, col_b, col_c = st.columns(3)

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
            )'''

new_block = '''        search_filter = st.text_input(
            "Search / Filter in Rule-Based Dataset",
            placeholder="blackmail / ابتزاز / telegram",
            key="doctor_search_filter"
        )

        port = ""
        url = ""

        st.info("Port and URL are extracted automatically from the message text by the Rule-Based engine.")'''

if old_block in text:
    text = text.replace(old_block, new_block, 1)

# غيّر العناوين حتى تبين أنها Auto
text = text.replace("1) Port Check", "Auto Port Check")
text = text.replace("2) HTTPS / URL Check", "Auto HTTPS / URL Check")
text = text.replace("🌐 Port Rule-Based Check", "🌐 Automatic Port Rule-Based Check")
text = text.replace("**HTTPS / URL Check:**", "**Automatic HTTPS / URL Check:**")

# أضف عرض واضح للـ auto detected ports/urls بعد metric cards
target = '''                st.markdown(f"""
                <div class="explain-panel">
                    <div class="panel-key">🎯 Rule-Based Match Summary</div>
                    <div class="panel-value">
                        Matched Rules: {result["matched_rules"]}<br>
                        Phishing: {result["phishing"] or "None"}<br>
                        Social Engineering: {result["social"] or "None"}<br>
                        Telegram: {result["telegram"] or "None"}
                    </div>
                </div>
                """, unsafe_allow_html=True)'''

replacement = '''                st.markdown(f"""
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
                """, unsafe_allow_html=True)'''

if target in text and "Auto URLs:" not in text:
    text = text.replace(target, replacement, 1)

p.write_text(text, encoding="utf-8")
print("✅ Manual Port/URL fields removed. Rule-Based now auto-detects checks from text.")
