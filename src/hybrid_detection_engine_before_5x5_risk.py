from src.doctor_rule_based import analyze_doctor_requirements


def safe_get(data, key, default=""):
    if isinstance(data, dict):
        return data.get(key, default)
    return default


def normalize_risk(value):
    value = str(value or "").strip().lower()

    if value in ["critical", "high", "danger", "dangerous"]:
        return "High"

    if value in ["medium", "moderate", "suspicious"]:
        return "Medium"

    return "Low"


def risk_to_score(risk):
    risk = normalize_risk(risk)
    if risk == "High":
        return 3
    if risk == "Medium":
        return 2
    return 1


def run_ai_detection(text):
    """
    Uses your existing BERT/NLP detection engine if available.
    If it fails, the system continues with Rule-Based only.
    """
    try:
        from src.detection_engine import detect_threat

        result = detect_threat(text)

        ai_label = (
            safe_get(result, "predicted_label")
            or safe_get(result, "label")
            or safe_get(result, "type")
            or safe_get(result, "classification")
            or "Unknown"
        )

        ai_risk = (
            safe_get(result, "risk_level")
            or safe_get(result, "risk")
            or "Low"
        )

        ai_confidence = (
            safe_get(result, "confidence_score")
            or safe_get(result, "confidence")
            or safe_get(result, "score")
            or ""
        )

        ai_law = (
            safe_get(result, "main_law")
            or safe_get(result, "law_reference")
            or ""
        )

        ai_explanation = (
            safe_get(result, "case_explanation")
            or safe_get(result, "explanation")
            or ""
        )

        return {
            "ai_status": "ok",
            "ai_label": ai_label,
            "ai_risk": normalize_risk(ai_risk),
            "ai_confidence": ai_confidence,
            "ai_law": ai_law,
            "ai_explanation": ai_explanation,
            "raw_ai": result,
        }

    except Exception as e:
        return {
            "ai_status": "error",
            "ai_label": "NLP unavailable",
            "ai_risk": "Low",
            "ai_confidence": "",
            "ai_law": "",
            "ai_explanation": str(e),
            "raw_ai": {},
        }


def calculate_hybrid_decision(rule_result, ai_result):
    rule_risk = normalize_risk(rule_result.get("risk", "Low"))
    ai_risk = normalize_risk(ai_result.get("ai_risk", "Low"))

    rule_score = int(rule_result.get("score", 0) or 0)
    ai_score = risk_to_score(ai_risk)

    hybrid_numeric = rule_score + (ai_score * 3)

    reasons = []

    if rule_risk == "High":
        reasons.append("Rule-Based engine detected high-risk indicators")

    if ai_risk == "High":
        reasons.append("AI/BERT model classified the message as high risk")

    if rule_result.get("matched_rules"):
        reasons.append(f'Rule matches: {rule_result.get("matched_rules")}')

    if ai_result.get("ai_label"):
        reasons.append(f'AI label: {ai_result.get("ai_label")}')

    if rule_risk == "High" or ai_risk == "High" or hybrid_numeric >= 12:
        final_risk = "High"
        final_alert = "HYBRID_ALERT_TRIGGERED"
    elif rule_risk == "Medium" or ai_risk == "Medium" or hybrid_numeric >= 6:
        final_risk = "Medium"
        final_alert = "HYBRID_SUSPICIOUS_ACTIVITY"
    else:
        final_risk = "Low"
        final_alert = "HYBRID_NO_CRITICAL_MATCH"

    if not reasons:
        reasons.append("No strong AI or rule-based evidence detected")

    return {
        "hybrid_risk": final_risk,
        "hybrid_score": hybrid_numeric,
        "hybrid_alert": final_alert,
        "hybrid_reason": " | ".join(reasons),
        "rule_risk": rule_risk,
        "ai_risk": ai_risk,
    }


def _analyze_hybrid_base(uid, text, port="", url="", search_filter=""):
    rule_result = analyze_doctor_requirements(
        uid=uid,
        text=text,
        port=port,
        url=url,
        search_filter=search_filter,
    )

    if not rule_result.get("valid", False):
        return {
            "valid": False,
            "error": rule_result.get("error", "Rule-Based validation failed"),
            "rule_result": rule_result,
            "ai_result": {},
        }

    ai_result = run_ai_detection(text)
    hybrid = calculate_hybrid_decision(rule_result, ai_result)

    return {
        "valid": True,
        "uid": uid,
        "text": text,

        "hybrid_risk": hybrid["hybrid_risk"],
        "hybrid_score": hybrid["hybrid_score"],
        "hybrid_alert": hybrid["hybrid_alert"],
        "hybrid_reason": hybrid["hybrid_reason"],

        "rule_risk": hybrid["rule_risk"],
        "rule_score": rule_result.get("score", 0),
        "rule_alert": rule_result.get("alert", ""),
        "matched_rules": rule_result.get("matched_rules", ""),

        "ai_status": ai_result.get("ai_status", ""),
        "ai_label": ai_result.get("ai_label", ""),
        "ai_risk": ai_result.get("ai_risk", ""),
        "ai_confidence": ai_result.get("ai_confidence", ""),
        "ai_law": ai_result.get("ai_law", ""),
        "ai_explanation": ai_result.get("ai_explanation", ""),

        "auto_detected_urls": rule_result.get("auto_detected_urls", []),
        "auto_detected_ports": rule_result.get("auto_detected_ports", []),
        "https_checks": rule_result.get("https_checks", []),
        "port_checks": rule_result.get("port_checks", []),

        "phishing": rule_result.get("phishing", ""),
        "social": rule_result.get("social", ""),
        "telegram": rule_result.get("telegram", ""),

        "dataset_matches": rule_result.get("dataset_matches"),
        "rule_result": rule_result,
        "ai_result": ai_result,
    }


def _critical_override(text, ai_label=""):
    text = str(text or "").lower()
    ai_label = str(ai_label or "").lower()

    high_words = [
        "ابتزاز", "سأقوم بنشر", "سأنشر", "بنشر صورك", "نشرت صورك",
        "صورك الخاصة", "ادفع", "تدفع", "500 دينار", "فضيحة",
        "تهديد", "لا تخبر أحد", "كود التحقق", "fake-login", "otp"
    ]

    if "ابتزاز" in ai_label or any(w in text for w in high_words):
        return True

    return False


def analyze_hybrid(*args, **kwargs):
    result = _analyze_hybrid_base(*args, **kwargs)

    text = ""
    if args:
        text = args[0]
    text = kwargs.get("text", text)

    ai_label = ""
    if isinstance(result, dict):
        ai_label = result.get("ai_label", "")

    if isinstance(result, dict) and _critical_override(text, ai_label):
        result["risk"] = "High"
        result["final_risk"] = "High"
        result["hybrid_risk"] = "High"
        result["risk_level"] = "High"
        result["score"] = max(int(result.get("score", 0) or 0), 15)
        result["hybrid_score"] = max(int(result.get("hybrid_score", 0) or 0), 15)
        result["alert"] = "CRITICAL_RISK_OVERRIDE"

        if not result.get("ai_label"):
            result["ai_label"] = "ابتزاز"

    return result
