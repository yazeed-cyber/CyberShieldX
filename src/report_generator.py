from pathlib import Path
from datetime import datetime
import pandas as pd
from src.risk_methodology import explain_risk_methodology

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = ROOT / "outputs"
REPORTS = ROOT / "reports"

TELEGRAM_FILE = OUTPUTS / "dashboard_live_clean.csv"
INCIDENT_FILE = OUTPUTS / "incident_center.csv"


def read_csv_safe(path):
    if not path.exists():
        return pd.DataFrame()

    return pd.read_csv(path, encoding="utf-8-sig", engine="python", on_bad_lines="skip").fillna("")


def generate_security_report():
    REPORTS.mkdir(exist_ok=True)

    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = REPORTS / f"CyberShieldX_Security_Report_{now}.pdf"

    telegram_df = read_csv_safe(TELEGRAM_FILE)
    incident_df = read_csv_safe(INCIDENT_FILE)

    doc = SimpleDocTemplate(str(report_path), pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("CyberShieldX Security Incident Report", styles["Title"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph(f"Generated automatically by CyberShieldX on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    story.append(Spacer(1, 12))

    total_events = len(telegram_df)
    total_incidents = len(incident_df)

    high_risk = 0
    if not telegram_df.empty and "risk" in telegram_df.columns:
        high_risk = len(telegram_df[telegram_df["risk"].astype(str).str.lower() == "high"])

    summary_data = [
        ["Metric", "Value"],
        ["Total Telegram Events", str(total_events)],
        ["Total Incidents", str(total_incidents)],
        ["High Risk Events", str(high_risk)],
        ["Report Type", "Automatically Generated"],
    ]

    summary_table = Table(summary_data, colWidths=[220, 220])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))

    story.append(Paragraph("1. Executive Summary", styles["Heading2"]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("2. Latest Telegram Threat Events", styles["Heading2"]))

    if telegram_df.empty:
        story.append(Paragraph("No Telegram events found.", styles["Normal"]))
    else:
        cols = ["time", "uid", "sender_name", "text", "risk", "score", "ai_label", "incident_id"]
        existing = [c for c in cols if c in telegram_df.columns]
        latest = telegram_df[existing].tail(10)

        table_data = [existing]
        for _, row in latest.iterrows():
            table_data.append([str(row.get(c, ""))[:80] for c in existing])

        t = Table(table_data, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkred),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)

    story.append(Spacer(1, 16))
    story.append(Paragraph("3. Risk Methodology", styles["Heading2"]))
    story.append(Paragraph("CyberShieldX calculates risk using hybrid detection: Rule-Based matching + NLP/AI classification + threat indicators such as URL, port, blackmail keywords, phishing patterns, and social engineering signals.", styles["Normal"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Risk Formula: Risk Score = Likelihood x Impact. The qualitative level is mapped into Low, Medium, High, or Critical based on the score.", styles["Normal"]))

    story.append(Spacer(1, 16))
    story.append(Paragraph("4. Recommendations", styles["Heading2"]))
    recommendations = [
        "Preserve Telegram message evidence and timestamps.",
        "Escalate High and Critical incidents for immediate review.",
        "Block suspicious URLs and investigate dangerous ports.",
        "Apply legal mapping for blackmail, harassment, defamation, and phishing cases.",
        "Review account security and enable MFA for sensitive access.",
    ]

    for r in recommendations:
        story.append(Paragraph(f"- {r}", styles["Normal"]))


    story.append(Spacer(1, 16))
    story.append(Paragraph("5. Risk Management Methodology and References", styles["Heading2"]))

    methodology = explain_risk_methodology()

    story.append(Paragraph(f"Method: {methodology['method']}", styles["Normal"]))
    story.append(Paragraph(f"Formula: {methodology['formula']}", styles["Normal"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Risk Classification:", styles["Heading3"]))
    risk_table = [["Score Range", "Level", "Meaning"]]
    for item in methodology["classification"]:
        risk_table.append([item["score_range"], item["level"], item["meaning"]])

    rt = Table(risk_table, colWidths=[100, 100, 260])
    rt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkgreen),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(rt)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Risk Calculation Rules:", styles["Heading3"]))
    rules_table = [["Threat", "Likelihood", "Impact", "Score", "Level"]]
    for rule in methodology["rules"]:
        rules_table.append([
            rule["threat"],
            str(rule["likelihood"]),
            str(rule["impact"]),
            str(rule["score"]),
            rule["level"]
        ])

    rlt = Table(rules_table, colWidths=[180, 70, 70, 60, 80])
    rlt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkred),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(rlt)
    story.append(Spacer(1, 12))

    story.append(Paragraph("References:", styles["Heading3"]))
    for ref in methodology["references"]:
        story.append(Paragraph(f"- {ref['id']}: {ref['title']} — {ref['use']}", styles["Normal"]))


    doc.build(story)

    return str(report_path)


if __name__ == "__main__":
    print(generate_security_report())
