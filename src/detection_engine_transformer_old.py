import json
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from src.arabic_cleaning import clean_text
from src.law_lookup import get_law_info
from src.alert_module import should_alert, send_alert
from src.incident_logger import save_incident

MODEL_PATH = "outputs/saved_model"

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

with open("outputs/label_mapping.json", "r", encoding="utf-8") as f:
    label_map = json.load(f)

def get_risk_level(confidence):
    if confidence >= 0.85:
        return "High"
    elif confidence >= 0.60:
        return "Medium"
    return "Low"

def detect_threat(message):
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
    predicted_label = label_map[str(predicted_id)]
    risk_level = get_risk_level(confidence_score)

    law_info = get_law_info(predicted_label)
    top_law = law_info["top_law"]
    all_possible_laws = law_info["all_possible_laws"]

    incident = {
        "original_text": message,
        "cleaned_text": cleaned_message,
        "predicted_label": predicted_label,
        "confidence_score": round(confidence_score, 4),
        "risk_level": risk_level,
        "law": top_law,
        "all_possible_laws": " | ".join(all_possible_laws)
    }

    if should_alert(predicted_label, risk_level):
        send_alert(incident)

    save_incident(incident)
    return incident

if __name__ == "__main__":
    sample_messages = [
        "اذا ما دفعت رح انشر صورك",
        "هذا الشخص نصاب وراح يوقعك",
        "مرحبا كيفك اليوم",
        "ادخل هذا الرابط لتحصل على جائزة"
    ]

    for msg in sample_messages:
        result = detect_threat(msg)
        print("=== Detection Result ===")
        for key, value in result.items():
            print(f"{key}: {value}")
        print("-" * 50)
