import pandas as pd

file_path = "data/cybershieldx_20k_full_arabic_UTF8.csv"
df = pd.read_csv(file_path)

print("=== Shape ===")
print(df.shape)

print("\n=== Columns ===")
print(df.columns.tolist())

print("\n=== First 5 Rows ===")
print(df.head())

print("\n=== Missing Values ===")
print(df.isnull().sum())

print("\n=== Duplicate Rows ===")
print(df.duplicated().sum())

print("\n=== Label Distribution ===")
print(df["نوع_الحالة"].value_counts())

print("\n=== Sample Messages ===")
print(df["نص_الرسالة"].head(10))

with open("outputs/dataset_summary.txt", "w", encoding="utf-8") as f:
    f.write("Shape:\n")
    f.write(str(df.shape) + "\n\n")

    f.write("Columns:\n")
    f.write(str(df.columns.tolist()) + "\n\n")

    f.write("Missing Values:\n")
    f.write(str(df.isnull().sum()) + "\n\n")

    f.write("Duplicate Rows:\n")
    f.write(str(df.duplicated().sum()) + "\n\n")

    f.write("Label Distribution:\n")
    f.write(str(df["نوع_الحالة"].value_counts()) + "\n")
