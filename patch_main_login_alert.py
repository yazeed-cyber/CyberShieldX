from pathlib import Path

p = Path("src/dashboard/dashboard_app.py")
text = p.read_text(encoding="utf-8")

# 1) Add import
if "from src.doctor_rule_based import log_login_alert" not in text:
    text = text.replace(
        "import streamlit as st\n",
        "import streamlit as st\n\nfrom src.doctor_rule_based import log_login_alert\n",
        1
    )

# 2) Add UID before channel select
target_channel = '''    channel = st.selectbox(
        "Verification Channel",
        ["email", "smart_auto", "sms"],
        index=0,
        key="login_channel_select"
    )'''

uid_block = '''    login_uid = st.text_input(
        "UID / User ID - Required",
        placeholder="Example: user_202130045",
        key="main_login_uid"
    )

    channel = st.selectbox(
        "Verification Channel",
        ["email", "smart_auto", "sms"],
        index=0,
        key="login_channel_select"
    )'''

if target_channel in text and "key=\"main_login_uid\"" not in text:
    text = text.replace(target_channel, uid_block, 1)

# 3) Add Login / Sign-in alert buttons after email input
target_email = '''    email = st.text_input("Email Address", placeholder="name@example.com", key="login_email")'''

alert_buttons = '''    email = st.text_input("Email Address", placeholder="name@example.com", key="login_email")

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
                st.success("Sign-in alert saved.")'''

if target_email in text and "key=\"main_login_alert_btn\"" not in text:
    text = text.replace(target_email, alert_buttons, 1)

# 4) Enforce UID before Send OTP
target_send = '''        if st.button("Send OTP", use_container_width=True, key="send_otp_btn"):
            if lockout_active(st.session_state.lockout_until):'''

new_send = '''        if st.button("Send OTP", use_container_width=True, key="send_otp_btn"):
            if not login_uid.strip():
                st.error("UID is required before sending OTP.")
                st.stop()

            if lockout_active(st.session_state.lockout_until):'''

if target_send in text and "UID is required before sending OTP." not in text:
    text = text.replace(target_send, new_send, 1)

# 5) Log failed OTP attempts if possible
target_failed = '''                        else:
                            st.session_state.otp_attempts += 1'''

new_failed = '''                        else:
                            log_login_alert(login_uid, "login", "failed", "Invalid OTP entered")
                            st.session_state.otp_attempts += 1'''

if target_failed in text and "Invalid OTP entered" not in text:
    text = text.replace(target_failed, new_failed, 1)

# 6) Log expired OTP
target_expired = '''                st.error("This OTP has expired. Please request a new one.")'''

new_expired = '''                log_login_alert(login_uid, "login", "expired", "OTP expired before verification")
                st.error("This OTP has expired. Please request a new one.")'''

if target_expired in text and "OTP expired before verification" not in text:
    text = text.replace(target_expired, new_expired, 1)

# 7) Log success
target_success = '''                        st.session_state.authenticated = True
                        st.session_state.login_time = time.time()
                        st.success("Login successful.")
                        st.rerun()'''

new_success = '''                        st.session_state.authenticated = True
                        st.session_state.login_time = time.time()
                        log_login_alert(login_uid, "login", "success", "OTP login successful")
                        st.success("Login successful.")
                        st.rerun()'''

if target_success in text and "OTP login successful" not in text:
    text = text.replace(target_success, new_success, 1)

p.write_text(text, encoding="utf-8")
print("✅ Main page UID + Login/Sign-in alerts added successfully.")
