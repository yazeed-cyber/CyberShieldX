import re

def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+", " ", text)
    text = re.sub(r"[^\u0600-\u06FF\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text
