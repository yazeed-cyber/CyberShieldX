from pathlib import Path

p = Path("src/dashboard/dashboard_app.py")
text = p.read_text(encoding="utf-8")

# 1) Rename tab title
text = text.replace("🧠 Doctor Required Rule-Based", "🧠 Rule Based")
text = text.replace("🧠 Doctor Required Rule-Based Center", "🧠 Rule Based")

# 2) Better Sign in/Login page title and description
text = text.replace(
    "🛡️ CyberShieldX Device Sign-in",
    "Welcome to CyberShieldX"
)

text = text.replace(
    "This screen records a real device UID before OTP login.",
    "Sign in securely to access the CyberShieldX enterprise dashboard."
)

# 3) Rename device UID label
text = text.replace("🆔 Auto Device UID", "🆔 Secure Device UID")
text = text.replace("🆔 Device UID", "🆔 Secure Device UID")

# 4) Make Sign in/Login buttons more realistic
text = text.replace(
    'if st.button("📝 Sign in", use_container_width=True, key="device_signin_btn"):',
    'if st.button("Create Session / Sign in", use_container_width=True, key="device_signin_btn"):'
)

text = text.replace(
    'if st.button("🔐 Login", use_container_width=True, key="device_login_btn"):',
    'if st.button("Login to Dashboard", use_container_width=True, key="device_login_btn"):'
)

# 5) Replace manual UID input inside Rule Based tab with automatic device UID
old_uid_block = '''        uid = st.text_input(
            "UID / User ID - إجباري",
            placeholder="Example: user_202130045",
            key="doctor_uid"
        )'''

new_uid_block = '''        uid = st.session_state.get("device_uid", get_device_uid())
        st.markdown(f"""
        <div class="law-panel">
            <div class="panel-key">🆔 Automatic Device UID</div>
            <div class="panel-value">{uid}</div>
        </div>
        """, unsafe_allow_html=True)'''

if old_uid_block in text:
    text = text.replace(old_uid_block, new_uid_block, 1)

# 6) Replace old required description
text = text.replace(
    "This section implements the doctor requirements: Login/Sign-in alerting, mandatory UID, rule-based filtering/search, text-to-rule matching, dataset rows as rules, port check, HTTPS check, Telegram, phishing, and social engineering.",
    "This section implements Rule-Based detection using automatic device UID, dataset rules, text matching, search/filter, port check, HTTPS check, Telegram indicators, phishing, and social engineering."
)

# 7) Add stronger CSS for realistic login if not exists
css_marker = "</style>"
extra_css = """
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
"""

if ".auth-choice-card" not in text and css_marker in text:
    text = text.replace(css_marker, extra_css + "\n</style>", 1)

# 8) Add info cards before buttons in device sign-in page
old_buttons = '''    col_signin, col_login = st.columns(2)

    with col_signin:
        if st.button("Create Session / Sign in", use_container_width=True, key="device_signin_btn"):'''

new_buttons = '''    col_signin, col_login = st.columns(2)

    with col_signin:
        st.markdown("""
        <div class="auth-choice-card">
            <div class="auth-mini-title">New secure session</div>
            <div class="auth-mini-text">Use this option to register this device session before OTP verification.</div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Create Session / Sign in", use_container_width=True, key="device_signin_btn"):'''

if old_buttons in text:
    text = text.replace(old_buttons, new_buttons, 1)

old_login_button = '''    with col_login:
        if st.button("Login to Dashboard", use_container_width=True, key="device_login_btn"):'''

new_login_button = '''    with col_login:
        st.markdown("""
        <div class="auth-choice-card">
            <div class="auth-mini-title">Existing dashboard access</div>
            <div class="auth-mini-text">Continue to OTP login using the automatically detected device identity.</div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Login to Dashboard", use_container_width=True, key="device_login_btn"):'''

if old_login_button in text:
    text = text.replace(old_login_button, new_login_button, 1)

p.write_text(text, encoding="utf-8")
print("✅ Login UI updated + Rule Based renamed + automatic UID enabled.")
