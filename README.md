# CyberShieldX

AI-powered Arabic cyber threat detection platform.

## Features
- Arabic NLP threat detection
- Rule-Based detection
- Hybrid AI engine
- Telegram monitoring
- SOC dashboard
- OTP authentication
- PDF report generation

## Technologies
- Python
- Streamlit
- Telethon
- Pandas
- Plotly

## Run

```bash
cd CyberShieldX
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m streamlit run src/dashboard/dashboard_app.py
OR
python -m streamlit run src/dashboard/dashboard_app.py --server.port=8501
OR
python -m streamlit run src/dashboard/dashboard_app.py --server.port=8502
OR
PYTHONPATH=. streamlit run src/dashboard/dashboard_app.py

