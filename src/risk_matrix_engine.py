def calculate_5x5_risk(text="", ai_label="", rule_risk="Low", ai_risk="Low"):
    text = str(text or "").lower()
    ai_label = str(ai_label or "").lower()
    rule_risk = str(rule_risk or "Low")
    ai_risk = str(ai_risk or "Low")

    high_keywords = [
        "ابتزاز", "ادفع", "تدفع", "سأقوم بنشر", "سأنشر",
        "بنشر صورك", "نشرت صورك", "صورك الخاصة",
        "فضيحة", "تهديد", "500 دينار", "لا تخبر أحد",
        "كود التحقق", "otp", "password", "fake-login",
        "phishing", "blackmail", "extortion"
    ]

    medium_keywords = [
        "رابط", "اضغط", "تحقق", "حسابك", "جائزة",
        "اربح", "تسجيل دخول", "login", "verify"
    ]

    if any(w in text for w in high_keywords) or any(w in ai_label for w in ["ابتزاز", "phishing", "blackmail"]):
        likelihood = 5
        impact = 5
    elif rule_risk == "High" or ai_risk == "High":
        likelihood = 5
        impact = 4
    elif any(w in text for w in medium_keywords) or rule_risk == "Medium" or ai_risk == "Medium":
        likelihood = 3
        impact = 3
    else:
        likelihood = 1
        impact = 2

    score = likelihood * impact

    if score <= 5:
        qualitative = "Low"
    elif score <= 10:
        qualitative = "Medium"
    elif score <= 15:
        qualitative = "High"
    else:
        qualitative = "Critical"

    return {
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": score,
        "risk_level": qualitative,
        "formula": "Risk = Likelihood × Impact",
        "matrix": "5x5 Risk Matrix",
        "quantitative": score,
        "qualitative": qualitative
    }
