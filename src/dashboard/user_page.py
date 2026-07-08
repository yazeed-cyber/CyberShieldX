import streamlit as st
from src.detection_engine import detect_threat


def render_user_page():
    st.markdown("## 👤 User Threat Check")
    st.write("Analyze a suspicious message and view its classification, risk level, Jordanian law, and explanation.")

    user_text = st.text_area("Message to Analyze", height=220)

    if st.button("Analyze Message", use_container_width=True):
        if not user_text.strip():
            st.error("Please enter a message first.")
            return

        try:
            result = detect_threat(user_text.strip())

            st.success("Analysis completed.")
            st.write("**Predicted Label:**", result.get("predicted_label", ""))
            st.write("**Confidence Score:**", result.get("confidence_score", ""))
            st.write("**Risk Level:**", result.get("risk_level", ""))
            st.write("**Jordanian Law Applied:**", result.get("main_law", ""))
            st.write("**Explanation:**", result.get("case_explanation", ""))

        except Exception as e:
            st.error(f"Analysis failed: {e}")
