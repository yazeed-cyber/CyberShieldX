import os
import json
import re
from difflib import SequenceMatcher

import pandas as pd

from src.arabic_cleaning import clean_text
from src.alert_module import should_alert, send_alert
from src.incident_logger import save_incident

DATASET_PATH = "data/cybershieldx_20k_full_arabic_UTF8.csv"
MODEL_PATH = "outputs/saved_model"
LABEL_MAP_PATH = "outputs/label_mapping.json"

_tokenizer = None
_model = None
_label_map = None
_model_load_attempted = False


def load_dataset():
    try:
        return pd.read_csv(DATASET_PATH, encoding="utf-8")
    except Exception:
        return pd.DataFrame()


def safe_str(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def load_model_if_possible():
    global _tokenizer, _model, _label_map, _model_load_attempted

    if _model_load_attempted:
        return _tokenizer, _model, _label_map

    _model_load_attempted = True

    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        _tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        _model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

        with open(LABEL_MAP_PATH, "r", encoding="utf-8") as f:
            _label_map = json.load(f)

    except Exception:
        _tokenizer = None
        _model = None
        _label_map = None

    return _tokenizer, _model, _label_map


def get_risk_level(predicted_label, confidence_score):
    label = safe_str(predicted_label)

    if label == "آمن":
        return "No Risk"

    if confidence_score >= 0.85:
        return "High"
    if confidence_score >= 0.60:
        return "Medium"
    return "Low"


def extract_keywords(text):
    text = safe_str(text)
    text = re.sub(r"[^\w\s\u0600-\u06FF]", " ", text)
    words = [w for w in text.split() if len(w) >= 3]
    return list(dict.fromkeys(words))


def similarity(a, b):
    return SequenceMatcher(None, safe_str(a), safe_str(b)).ratio()


def get_best_dataset_match(message, dataset_df):
    if dataset_df.empty:
        return None

    text_col = "نص_الرسالة" if "نص_الرسالة" in dataset_df.columns else None
    label_col = "نوع_الحالة" if "نوع_الحالة" in dataset_df.columns else None
    law_col = "القانون_الاردني_المطبق" if "القانون_الاردني_المطبق" in dataset_df.columns else None

    if not text_col or not label_col or not law_col:
        return None

    msg_clean = clean_text(message)
    msg_keywords = extract_keywords(msg_clean)

    best_row = None
    best_score = -1.0

    for _, row in dataset_df.iterrows():
        row_text = clean_text(safe_str(row[text_col]))
        row_keywords = extract_keywords(row_text)

        overlap = len(set(msg_keywords) & set(row_keywords))
        sim = similarity(msg_clean, row_text)

        score = (overlap * 0.7) + (sim * 3.0)

        if score > best_score:
            best_score = score
            best_row = row

    return best_row


def get_law_from_label(predicted_label, dataset_df):
    if dataset_df.empty:
        return "لا يوجد قانون مطابق"

    if "نوع_الحالة" not in dataset_df.columns or "القانون_الاردني_المطبق" not in dataset_df.columns:
        return "لا يوجد قانون مطابق"

    matches = dataset_df[
        dataset_df["نوع_الحالة"].astype(str).str.strip() == safe_str(predicted_label)
    ]

    if not matches.empty:
        return safe_str(matches.iloc[0]["القانون_الاردني_المطبق"])

    return "لا يوجد قانون مطابق"


def build_case_explanation(predicted_label, risk_level, law_text):
    return (
        f"تم تصنيف الرسالة على أنها '{safe_str(predicted_label)}' "
        f"ومستوى الخطورة '{safe_str(risk_level)}'. "
        f"القانون الأردني المعروض تم استخراجه مباشرة من الـdataset "
        f"من الحقل 'القانون_الاردني_المطبق'. "
        f"النص القانوني المرتبط: {safe_str(law_text)}"
    )


def detect_with_model(message):
    tokenizer, model, label_map = load_model_if_possible()
    if not tokenizer or not model or not label_map:
        return None

    import torch

    cleaned_message = clean_text(message)

    inputs = tokenizer(
        cleaned_message,
        return_tensors="pt",
        truncation=True,
        padding="max_length",
        max_length=128
    )

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=1)
        confidence, predicted_class = torch.max(probs, dim=1)

    predicted_id = int(predicted_class.item())
    confidence_score = float(confidence.item())
    predicted_label = label_map.get(str(predicted_id), "غير معروف")

    return predicted_label, confidence_score


def detect_with_dataset_fallback(message, dataset_df):
    best_row = get_best_dataset_match(message, dataset_df)

    if best_row is None:
        return "آمن", 0.50, "لا يوجد قانون مطابق"

    predicted_label = safe_str(best_row.get("نوع_الحالة", "غير معروف"))
    law_text = safe_str(best_row.get("القانون_الاردني_المطبق", "لا يوجد قانون مطابق"))

    matched_text = safe_str(best_row.get("نص_الرسالة", ""))
    confidence_score = max(0.55, min(0.95, similarity(clean_text(message), clean_text(matched_text))))

    return predicted_label, confidence_score, law_text


def detect_threat(message):
    dataset_df = load_dataset()
    cleaned_message = clean_text(message)

    model_result = detect_with_model(message)

    if model_result is not None:
        predicted_label, confidence_score = model_result
        law_text = get_law_from_label(predicted_label, dataset_df)
    else:
        predicted_label, confidence_score, law_text = detect_with_dataset_fallback(message, dataset_df)

    risk_level = get_risk_level(predicted_label, confidence_score)
    case_explanation = build_case_explanation(predicted_label, risk_level, law_text)

    alert_needed = should_alert(predicted_label, risk_level)

    incident = {
        "original_text": message,
        "cleaned_text": cleaned_message,
        "predicted_label": predicted_label,
        "confidence_score": round(float(confidence_score), 4),
        "risk_level": risk_level,
        "main_law": law_text,
        "all_laws": law_text,
        "law_count": 1,
        "alert_status": "Yes" if alert_needed else "No",
        "case_explanation": case_explanation,
    }

    if alert_needed:
        try:
            send_alert(incident)
        except Exception:
            pass

    save_incident(incident)
    return incident


if __name__ == "__main__":
    tests = [
        "اذا ما دفعت رح انشر صورك",
        "ادخل هذا الرابط لتحصل على الجائزة",
        "مرحبا كيفك اليوم",
    ]

    for msg in tests:
        result = detect_threat(msg)
        print("=" * 50)
        for k, v in result.items():
            print(f"{k}: {v}")
