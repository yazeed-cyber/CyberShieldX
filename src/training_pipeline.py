import os
import json
import pandas as pd
import torch

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer

from src.arabic_cleaning import clean_text

FILE_PATH = "data/cybershieldx_20k_full_arabic_UTF8.csv"
MODEL_NAME = "aubmindlab/bert-base-arabertv02"

os.makedirs("outputs", exist_ok=True)
os.makedirs("outputs/saved_model", exist_ok=True)

# -----------------------------
# Helper: detect law column name automatically
# -----------------------------
def detect_law_column(columns):
    possible_names = [
        "القانون",
        "القانون الاردني المطبق",
        "القانون الأردني المطبق",
        "المادة القانونية",
        "القانون المطبق",
        "المادة",
        "law",
        "applied_law"
    ]
    normalized_map = {str(c).strip(): c for c in columns}

    for name in possible_names:
        if name in normalized_map:
            return normalized_map[name]

    for c in columns:
        c_str = str(c).strip()
        if "قانون" in c_str or "القانون" in c_str or "مادة" in c_str:
            return c

    raise ValueError(
        f"لم أجد عمود القانون داخل الداتا. الأعمدة الموجودة هي:\n{list(columns)}"
    )

# -----------------------------
# Load data
# -----------------------------
df = pd.read_csv(FILE_PATH)

text_col = "نص_الرسالة"
label_col = "نوع_الحالة"
law_col = detect_law_column(df.columns)

print(f"Detected law column: {law_col}")

df = df[[text_col, label_col, law_col]].copy()
df.dropna(subset=[text_col, label_col], inplace=True)

df["text"] = df[text_col].apply(clean_text)
df["label_text"] = df[label_col]
df["law_text"] = df[law_col].astype(str)

# -----------------------------
# Encode labels
# -----------------------------
label_encoder = LabelEncoder()
df["label"] = label_encoder.fit_transform(df["label_text"])

label_map = {int(i): label for i, label in enumerate(label_encoder.classes_)}
with open("outputs/label_mapping.json", "w", encoding="utf-8") as f:
    json.dump(label_map, f, ensure_ascii=False, indent=2)

# -----------------------------
# Split data
# -----------------------------
train_df, test_df = train_test_split(
    df[["text", "label", "label_text", "law_text"]],
    test_size=0.2,
    random_state=42,
    stratify=df["label"]
)

# -----------------------------
# Tokenizer
# -----------------------------
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def tokenize(batch):
    return tokenizer(
        batch["text"],
        padding="max_length",
        truncation=True,
        max_length=128
    )

train_dataset = Dataset.from_pandas(train_df[["text", "label"]])
test_dataset = Dataset.from_pandas(test_df[["text", "label"]])

train_dataset = train_dataset.map(tokenize, batched=True)
test_dataset = test_dataset.map(tokenize, batched=True)

train_dataset.set_format(type="torch", columns=["input_ids", "attention_mask", "label"])
test_dataset.set_format(type="torch", columns=["input_ids", "attention_mask", "label"])

# -----------------------------
# Model
# -----------------------------
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=len(label_encoder.classes_)
)

training_args = TrainingArguments(
    output_dir="outputs/checkpoints",
    eval_strategy="epoch",
    learning_rate=2e-5,
    per_device_train_batch_size=4,
    per_device_eval_batch_size=4,
    num_train_epochs=1,
    logging_dir="outputs/logs",
    report_to="none"
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset
)

trainer.train()

# -----------------------------
# Predictions
# -----------------------------
pred_output = trainer.predict(test_dataset)
logits = pred_output.predictions
preds = logits.argmax(axis=1)

probs = torch.nn.functional.softmax(torch.tensor(logits), dim=1).numpy()
confidences = probs.max(axis=1)

def risk_level(c):
    if c >= 0.85:
        return "High"
    elif c >= 0.60:
        return "Medium"
    return "Low"

results_df = test_df.copy().reset_index(drop=True)
results_df["predicted_label_id"] = preds
results_df["predicted_label"] = [label_map[int(i)] for i in preds]
results_df["confidence_score"] = confidences
results_df["risk_level"] = results_df["confidence_score"].apply(risk_level)

# القانون الحقيقي من نفس الداتا
results_df["law"] = test_df["law_text"].values

results_df.to_csv("outputs/advanced_predictions.csv", index=False, encoding="utf-8-sig")

report = classification_report(
    test_df["label"],
    preds,
    target_names=label_encoder.classes_,
    zero_division=0
)
acc = accuracy_score(test_df["label"], preds)

with open("outputs/classification_report.txt", "w", encoding="utf-8") as f:
    f.write(f"Accuracy: {acc:.4f}\n\n")
    f.write(report)

model.save_pretrained("outputs/saved_model")
tokenizer.save_pretrained("outputs/saved_model")

print("DONE ✅")
print(f"Accuracy: {acc:.4f}")
print(f"Law column used: {law_col}")
