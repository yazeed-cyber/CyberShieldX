from pathlib import Path

p = Path("src/dashboard/dashboard_app.py")
text = p.read_text(encoding="utf-8")

if "from src.dashboard.device_identity import get_device_uid, get_device_info" not in text:
    text = text.replace(
        "import streamlit as st\n",
        "import streamlit as st\n\nfrom src.dashboard.device_identity import get_device_uid, get_device_info\n",
        1
    )

# أضف device defaults
target_defaults = '''    "otp_delivery_channel": None,
}'''

replace_defaults = '''    "otp_delivery_channel": None,
    "device_uid": get_device_uid(),
    "signin_completed": False,
}'''

if target_defaults in text and '"signin_completed": False' not in text:
    text = text.replace(target_defaults, replace_defaults, 1)

# أضف شاشة sign in / login قبل OTP
marker = '''if not st.session_state.authenticated:
    st.markdown('<div class="login-box">', unsafe_allow_html=True)'''

signin_block = '''if not st.session_state.authenticated and not st.session_state.signin_completed:
    device_info = get_device_info()
    st.markdown('<div class="login-box">', unsafe_allow_html=True)
    st.markdown('<div class="login-title">🛡️ CyberShieldX Device Sign-in</div>', unsafe_allow_html=True)
    st.markdown('<div class="login-sub">This screen records a real device UID before OTP login.</div>', unsafe_allow_html=True)

    st.markdown(f"""
    <div class="law-panel">
        <div class="panel-key">🆔 Auto Device UID</div>
        <div class="panel-value">{device_info["device_uid"]}</div>
    </div>
    """, unsafe_allow_html=True)

    st.write("**Hostname:**", device_info["hostname"])
    st.write("**OS:**", device_info["os"])
    st.write("**Machine:**", device_info["machine"])

    col_signin, col_login = st.columns(2)

    with col_signin:
        if st.button("📝 Sign in", use_container_width=True, key="device_signin_btn"):
            log_login_alert(device_info["device_uid"], "sign_in", "success", "Device sign-in completed")
            st.session_state.device_uid = device_info["device_uid"]
            st.session_state.signin_completed = True
            st.success("Device sign-in completed.")
            st.rerun()

    with col_login:
        if st.button("🔐 Login", use_container_width=True, key="device_login_btn"):
            log_login_alert(device_info["device_uid"], "login_opened", "success", "Login screen opened from device")
            st.session_state.device_uid = device_info["device_uid"]
            st.session_state.signin_completed = True
            st.success("Proceeding to OTP login.")
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

if not st.session_state.authenticated:
    st.markdown('<div class="login-box">', unsafe_allow_html=True)'''

if marker in text and "CyberShieldX Device Sign-in" not in text:
    text = text.replace(marker, signin_block, 1)

# استبدل UID اليدوي بالتلقائي
old_uid = '''    login_uid = st.text_input(
        "UID / User ID - Required",
        placeholder="Example: user_202130045",
        key="main_login_uid"
    )'''

new_uid = '''    login_uid = st.session_state.device_uid
    st.markdown(f"""
    <div class="law-panel">
        <div class="panel-key">🆔 Device UID</div>
        <div class="panel-value">{login_uid}</div>
    </div>
    """, unsafe_allow_html=True)'''

if old_uid in text:
    text = text.replace(old_uid, new_uid, 1)

p.write_text(text, encoding="utf-8")
print("✅ Device UID Sign-in/Login screen added.")
