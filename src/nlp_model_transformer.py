import pandas as pd
import json
import torch
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer

from Arabic_Cleaning import clean_text

FILE_PATH = "data/cybershieldx_20k_full_arabic_UTF8.csv"
MODEL_NAME = "aubmindlab/bert-base-arabertv02"

df = pd.read_csv(FILE_PATH)

# نأخذ الأعمدة المهمة فقط
df = df[["نص_الرسالة", "نوع_الحالة"]].copy()
df.dropna(inplace=True)

# تنظيف النص
df["text"] = df["نص_الرسالة"].apply(clean_text)
df["label_text"] = df["نوع_الحالة"]

# تحويل اللابلز لأرقام
label_encoder = LabelEncoder()
df["label"] = label_encoder.fit_transform(df["label_text"])

label_map = {int(i): label for i, label in enumerate(label_encoder.classes_)}
with open("outputs/label_mapping.json", "w", encoding="utf-8") as f:
    json.dump(label_map, f, ensure_ascii=False, indent=2)

# تقسيم البيانات
train_df, test_df = train_test_split(
    df[["text", "label", "label_text"]],
    test_size=0.2,
    random_state=42,
    stratify=df["label"]
)

# تحميل tokenizer
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def tokenize_function(batch):
    return tokenizer(batch["text"], padding="max_length", truncation=True, max_length=128)

# تحويل إلى HuggingFace Dataset
train_dataset = Dataset.from_pandas(train_df[["text", "label"]])
test_dataset = Dataset.from_pandas(test_df[["text", "label"]])

train_dataset = train_dataset.map(tokenize_function, batched=True)
test_dataset = test_dataset.map(tokenize_function, batched=True)

train_dataset.set_format(type="torch", columns=["input_ids", "attention_mask", "label"])
test_dataset.set_format(type="torch", columns=["input_ids", "attention_mask", "label"])

# تحميل المودل
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=len(label_encoder.classes_)
)

training_args = TrainingArguments(
    output_dir="outputs/transformer_checkpoints",
    eval_strategy="epoch",
    save_strategy="no",
    learning_rate=2e-5,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    num_train_epochs=2,
    weight_decay=0.01,
    logging_dir="outputs/logs",
    logging_steps=50
)

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = logits.argmax(axis=1)
    return {"accuracy": accuracy_score(labels, preds)}

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
    compute_metrics=compute_metrics
)

# تدريب
trainer.train()

# توقع
pred_output = trainer.predict(test_dataset)
logits = pred_output.predictions
preds = logits.argmax(axis=1)

# confidence
probs = torch.nn.functional.softmax(torch.tensor(logits), dim=1).numpy()
confidences = probs.max(axis=1)

def risk_level(conf):
    if conf >= 0.85:
        return "High"
    elif conf >= 0.60:
        return "Medium"
    return "Low"

report = classification_report(test_df["label"], preds, target_names=label_encoder.classes_)
acc = accuracy_score(test_df["label"], preds)

with open("outputs/classification_report.txt", "w", encoding="utf-8") as f:
    f.write(f"Accuracy: {acc}\n\n")
    f.write(report)

results_df = test_df.copy().reset_index(drop=True)
results_df["predicted_label_id"] = preds
results_df["predicted_label"] = [label_map[int(i)] for i in preds]
results_df["confidence_score"] = confidences
results_df["risk_level"] = results_df["confidence_score"].apply(risk_level)

results_df.to_csv("outputs/advanced_predictions.csv", index=False, encoding="utf-8-sig")

print("Training complete.")
print(f"Accuracy: {acc}")
print("Saved files:")
print("- outputs/classification_report.txt")
print("- outputs/advanced_predictions.csv")
print("- outputs/label_mapping.json")
