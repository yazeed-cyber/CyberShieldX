import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

from arabic_cleaning import clean_text

file_path = "data/cybershieldx_20k_full_arabic_UTF8.csv"

df = pd.read_csv(file_path)

# اختيار الأعمدة المهمة فقط
df = df[["نص_الرسالة", "نوع_الحالة"]].copy()

# حذف القيم الفارغة
df.dropna(subset=["نص_الرسالة", "نوع_الحالة"], inplace=True)

# تنظيف النص
df["نص_منظف"] = df["نص_الرسالة"].apply(clean_text)

# تقسيم البيانات
X = df["نص_منظف"]
y = df["نوع_الحالة"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# TF-IDF
vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=10000)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# تدريب النموذج
model = LogisticRegression(max_iter=1000)
model.fit(X_train_vec, y_train)

# التوقع
y_pred = model.predict(X_test_vec)

print("=== Accuracy ===")
print(accuracy_score(y_test, y_pred))

print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred))

with open("outputs/model_results.txt", "w", encoding="utf-8") as f:
    f.write("Accuracy:\n")
    f.write(str(accuracy_score(y_test, y_pred)) + "\n\n")
    f.write("Classification Report:\n")
    f.write(classification_report(y_test, y_pred))
