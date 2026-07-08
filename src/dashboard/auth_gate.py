import time
import streamlit as st

from src.dashboard.auth_system import (
    create_user,
    validate_login,
    check_password_strength,
    generate_otp,
    send_email_otp,
)

OTP_EXPIRY_SECONDS = 300


def require_auth():
    if "auth" not in st.session_state:
        st.session_state.auth = False

    if "mfa_pending" not in st.session_state:
        st.session_state.mfa_pending = False

    if st.session_state.auth:
        st.session_state.authenticated = True
        st.session_state.signin_completed = True
        return

    st.markdown("""
    <div class="glass">
        <h1>🛡️ CyberShieldX Secure Access</h1>
        <p>Any valid email can register. Strong password + Email OTP MFA required.</p>
    </div>
    """, unsafe_allow_html=True)

    if not st.session_state.mfa_pending:
        mode = st.radio(
            "Mode",
            ["Login", "Sign in"],
            horizontal=True,
            key="mfa_auth_mode"
        )

        email = st.text_input(
            "Email Address",
            placeholder="anyone@example.com",
            key="mfa_auth_email"
        )

        password = st.text_input(
            "Password",
            type="password",
            placeholder="12+ chars, uppercase, lowercase, number, special character",
            key="mfa_auth_password"
        )

        if password:
            strong_ok, strong_msg = check_password_strength(password)

            if strong_ok:
                st.success("Strong password ✅")
            else:
                st.warning(strong_msg)

        st.caption("Password policy: 12+ chars, uppercase, lowercase, number, special character, and no weak words.")

        if st.button("Continue", use_container_width=True, key="mfa_continue_btn"):
            if not email or not password:
                st.error("Enter email and password.")
            else:
                if mode == "Sign in":
                    ok, msg = create_user(email, password)
                else:
                    ok, msg = validate_login(email, password)

                if not ok:
                    st.error(msg)
                else:
                    otp = generate_otp()
                    sent, send_msg = send_email_otp(email.strip().lower(), otp)

                    if not sent:
                        st.error(send_msg)
                    else:
                        st.session_state.mfa_pending = True
                        st.session_state.mfa_email = email.strip().lower()
                        st.session_state.mfa_otp = otp
                        st.session_state.mfa_expires = time.time() + OTP_EXPIRY_SECONDS
                        st.success("OTP sent. Check your email.")
                        st.rerun()

    else:
        st.info(f"OTP sent to: {st.session_state.mfa_email}")

        remaining = int(st.session_state.mfa_expires - time.time())

        if remaining <= 0:
            st.session_state.mfa_pending = False
            st.error("OTP expired. Please login again.")
            st.rerun()

        st.caption(f"OTP expires in {remaining} seconds.")

        entered_otp = st.text_input(
            "Enter OTP",
            placeholder="6-digit code",
            key="mfa_entered_otp"
        )

        col1, col2 = st.columns(2)

        with col1:
            if st.button("Verify OTP", use_container_width=True, key="mfa_verify_btn"):
                if entered_otp == st.session_state.mfa_otp:
                    st.session_state.auth = True
                    st.session_state.authenticated = True
                    st.session_state.signin_completed = True
                    st.session_state.logged_user = st.session_state.mfa_email
                    st.session_state.mfa_pending = False
                    st.success("MFA verified. Login successful.")
                    st.rerun()
                else:
                    st.error("Invalid OTP.")

        with col2:
            if st.button("Cancel", use_container_width=True, key="mfa_cancel_btn"):
                st.session_state.mfa_pending = False
                st.rerun()

    st.stop()
