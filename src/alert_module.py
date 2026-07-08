def should_alert(label, risk):
    if str(label).strip() == "آمن":
        return False
    return risk in ["High", "Medium"]

def send_alert(incident):
    print("\n===== ALERT =====")
    print(f"Message: {incident['original_text']}")
    print(f"Label: {incident['predicted_label']}")
    print(f"Risk: {incident['risk_level']}")
    print(f"Law: {incident['main_law']}")
    print("=================\n")
