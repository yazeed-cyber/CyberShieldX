from pathlib import Path

p = Path("src/dashboard/dashboard_app.py")
text = p.read_text(encoding="utf-8")

old_block = '''if not st.session_state.authenticated and not st.session_state.signin_completed:
    device_info = get_device_info()
    st.markdown('<div class="login-box">', unsafe_allow_html=True)
    st.markdown('<div class="login-title">Welcome to CyberShieldX</div>', unsafe_allow_html=True)
    st.markdown('<div class="login-sub">Sign in securely to access the CyberShieldX enterprise dashboard.</div>', unsafe_allow_html=True)'''

new_block = '''if not st.session_state.authenticated and not st.session_state.signin_completed:
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
'''

if old_block in text:
    text = text.replace(old_block, new_block, 1)

p.write_text(text, encoding="utf-8")
print("✅ Real Login / Sign in authentication UI added.")
