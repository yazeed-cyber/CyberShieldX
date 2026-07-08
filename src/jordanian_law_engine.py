import re


LAW_RULES = {
    "blackmail": {
        "keywords": [
            "blackmail", "extortion", "threaten", "threat", "expose",
            "ابتزاز", "ببتزك", "افضحك", "فضيحة", "انشر صورك", "صورك",
            "بنشر", "راح انشر", "ادفع", "حول", "فلوس", "دينار"
        ],
        "article": "Article 18 - Jordan Cybercrime Law No. 17 of 2023",
        "crime": "Electronic Blackmail / Cyber Extortion",
        "penalty": "Imprisonment for not less than 1 year and a fine. Fine value should be verified from the official Arabic legal text.",
        "severity": "High",
        "legal_mapping": "Using electronic means to threaten, pressure, or extort a victim by publishing private content or demanding money/service."
    },

    "harassment": {
        "keywords": [
            "harassment", "abuse", "insult", "threatening", "stalking",
            "تحرش", "إزعاج", "ازعاج", "إساءة", "اساءة", "سب", "شتم",
            "تهديد", "بهددك", "ملاحقة", "تخويف"
        ],
        "article": "Article 15 - Jordan Cybercrime Law No. 17 of 2023",
        "crime": "Online Harassment / Abuse / Threatening Content",
        "penalty": "Imprisonment for not less than 3 months or a fine between 5,000 and 20,000 JOD, or both.",
        "severity": "Medium to High",
        "legal_mapping": "Using an information network or platform to insult, abuse, threaten, or target another person digitally."
    },

    "defamation": {
        "keywords": [
            "defamation", "slander", "rumor", "fake news", "reputation",
            "تشهير", "ذم", "قدح", "تحقير", "إشاعة", "اشاعة", "سمعة",
            "فضح", "كذب", "نشر كلام", "نشر عنك"
        ],
        "article": "Article 11 - Jordan Cybercrime Law No. 17 of 2023",
        "crime": "Defamation / Slander / Character Harm Online",
        "penalty": "Imprisonment for not less than 3 months or a fine between 2,500 and 25,000 JOD, or both.",
        "severity": "Medium",
        "legal_mapping": "Publishing or spreading digital content that harms a person’s reputation, dignity, or social standing."
    },

    "phishing": {
        "keywords": [
            "phishing", "otp", "password", "login", "verify", "account",
            "كود", "رمز", "تحقق", "حسابك", "تسجيل الدخول", "كلمة السر"
        ],
        "article": "Articles 3, 8, 9 - Jordan Cybercrime Law No. 17 of 2023",
        "crime": "Phishing / Unauthorized Access / Electronic Fraud",
        "penalty": "Penalties vary based on result: unauthorized access, fraud, or financial gain may lead to imprisonment and fines.",
        "severity": "High",
        "legal_mapping": "Attempting to obtain credentials, OTP codes, or access to accounts through deception."
    }
}


def normalize_text(text):
    return str(text or "").lower()


def detect_law_case(text, matched_rules="", ai_label=""):
    combined = normalize_text(f"{text} {matched_rules} {ai_label}")

    matched_cases = []

    for case_type, rule in LAW_RULES.items():
        hits = []

        for keyword in rule["keywords"]:
            if keyword.lower() in combined:
                hits.append(keyword)

        if hits:
            matched_cases.append({
                "case_type": case_type,
                "crime": rule["crime"],
                "article": rule["article"],
                "penalty": rule["penalty"],
                "severity": rule["severity"],
                "legal_mapping": rule["legal_mapping"],
                "matched_keywords": ", ".join(hits[:10])
            })

    if not matched_cases:
        return {
            "case_type": "general_cyber_incident",
            "crime": "General Cyber Incident",
            "article": "General review under Jordan Cybercrime Law No. 17 of 2023",
            "penalty": "Requires legal review based on the exact facts.",
            "severity": "Low",
            "legal_mapping": "No direct legal rule matched. Analyst review is required.",
            "matched_keywords": "None"
        }

    severity_rank = {
        "High": 3,
        "Medium to High": 2,
        "Medium": 1,
        "Low": 0
    }

    matched_cases = sorted(
        matched_cases,
        key=lambda x: severity_rank.get(x["severity"], 0),
        reverse=True
    )

    primary = matched_cases[0]
    primary["all_matches"] = matched_cases

    return primary


def format_law_summary(law_result):
    return (
        f'Crime: {law_result.get("crime", "")}\\n'
        f'Article: {law_result.get("article", "")}\\n'
        f'Penalty: {law_result.get("penalty", "")}\\n'
        f'Severity: {law_result.get("severity", "")}\\n'
        f'Mapping: {law_result.get("legal_mapping", "")}\\n'
        f'Matched Keywords: {law_result.get("matched_keywords", "")}'
    )
