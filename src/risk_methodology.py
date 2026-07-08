RISK_REFERENCES = [
    {
        "id": "ISO 31000:2018",
        "title": "Risk Management – Guidelines",
        "use": "General risk management process: identify, analyze, evaluate, treat, monitor, and report risk."
    },
    {
        "id": "NIST SP 800-30 Rev.1",
        "title": "Guide for Conducting Risk Assessments",
        "use": "Cybersecurity risk assessment methodology for threat, likelihood, impact, and risk determination."
    },
    {
        "id": "NIST CSF 2.0",
        "title": "Cybersecurity Framework 2.0",
        "use": "Cybersecurity governance, identification, protection, detection, response, and recovery."
    },
    {
        "id": "NIST SP 800-39",
        "title": "Managing Information Security Risk",
        "use": "Organization-wide information security risk management."
    }
]


RISK_LEVEL_TABLE = [
    {"score_range": "1-5", "level": "Low", "meaning": "Limited impact and low likelihood."},
    {"score_range": "6-10", "level": "Medium", "meaning": "Moderate likelihood or moderate impact."},
    {"score_range": "11-15", "level": "High", "meaning": "High likelihood or high impact requiring response."},
    {"score_range": "16-25", "level": "Critical", "meaning": "Severe impact and high likelihood requiring immediate escalation."},
]


RISK_RULES = [
    {
        "threat": "Blackmail / Extortion",
        "keywords": ["ابتزاز", "ادفع", "تدفع", "سأقوم بنشر", "سأنشر", "صورك الخاصة", "فضيحة", "تهديد"],
        "likelihood": 5,
        "impact": 5,
        "score": 25,
        "level": "Critical",
        "reason": "Direct threat against the victim, privacy exposure, and legal harm."
    },
    {
        "threat": "Phishing",
        "keywords": ["تحقق", "اضغط", "login", "verify", "fake-login", "رابط"],
        "likelihood": 4,
        "impact": 5,
        "score": 20,
        "level": "Critical",
        "reason": "Can lead to credential theft, account takeover, and financial fraud."
    },
    {
        "threat": "Credential / OTP Theft",
        "keywords": ["كود التحقق", "otp", "password", "رمز التحقق", "كلمة المرور"],
        "likelihood": 4,
        "impact": 5,
        "score": 20,
        "level": "Critical",
        "reason": "OTP or password theft can give direct unauthorized access."
    },
    {
        "threat": "Fraud / Scam",
        "keywords": ["اربح", "جائزة", "استثمار", "تحويل", "مبلغ"],
        "likelihood": 4,
        "impact": 4,
        "score": 16,
        "level": "Critical",
        "reason": "Potential financial loss or deception."
    },
    {
        "threat": "Defamation",
        "keywords": ["تشهير", "نشر معلومات", "سمعة"],
        "likelihood": 3,
        "impact": 4,
        "score": 12,
        "level": "High",
        "reason": "Reputation damage and legal consequences."
    },
    {
        "threat": "Harassment",
        "keywords": ["سب", "شتم", "مضايقة", "إهانة"],
        "likelihood": 3,
        "impact": 3,
        "score": 9,
        "level": "Medium",
        "reason": "Psychological and social impact but usually lower than extortion."
    },
    {
        "threat": "Safe / Normal Message",
        "keywords": [],
        "likelihood": 1,
        "impact": 2,
        "score": 2,
        "level": "Low",
        "reason": "No malicious indicators detected."
    },
]


def calculate_risk(likelihood, impact):
    score = int(likelihood) * int(impact)

    if score <= 5:
        level = "Low"
    elif score <= 10:
        level = "Medium"
    elif score <= 15:
        level = "High"
    else:
        level = "Critical"

    return {
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": score,
        "risk_level": level,
        "formula": "Risk Score = Likelihood × Impact"
    }


def explain_risk_methodology():
    return {
        "method": "5x5 Risk Matrix",
        "formula": "Risk Score = Likelihood × Impact",
        "likelihood_scale": {
            1: "Rare",
            2: "Unlikely",
            3: "Possible",
            4: "Likely",
            5: "Almost Certain"
        },
        "impact_scale": {
            1: "Negligible",
            2: "Minor",
            3: "Moderate",
            4: "Major",
            5: "Severe"
        },
        "classification": RISK_LEVEL_TABLE,
        "rules": RISK_RULES,
        "references": RISK_REFERENCES
    }
