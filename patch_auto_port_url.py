from pathlib import Path

p = Path("src/doctor_rule_based.py")
text = p.read_text(encoding="utf-8")

# Add auto port extractor after extract_urls
old = '''def extract_urls(text):
    return re.findall(r"(https?://[^\\s]+|www\\.[^\\s]+|t\\.me/[^\\s]+)", str(text), re.IGNORECASE)
'''

new = '''def extract_urls(text):
    return re.findall(r"(https?://[^\\s]+|www\\.[^\\s]+|t\\.me/[^\\s]+)", str(text), re.IGNORECASE)


def extract_ports(text):
    """
    Auto-detect ports from message text.
    Examples:
    - port 4444
    - Port: 3389
    - :443
    - tcp/80
    - https port 443
    """
    text = str(text or "").lower()
    ports = set()

    patterns = [
        r"port\\s*[:=]?\\s*(\\d{1,5})",
        r"tcp\\s*/\\s*(\\d{1,5})",
        r"udp\\s*/\\s*(\\d{1,5})",
        r":(\\d{2,5})\\b",
        r"\\b(21|22|23|25|80|443|445|3389|4444|8080)\\b",
    ]

    for pattern in patterns:
        for match in re.findall(pattern, text):
            try:
                port = int(match)
                if 1 <= port <= 65535:
                    ports.add(port)
            except Exception:
                pass

    return sorted(list(ports))
'''

if old in text:
    text = text.replace(old, new, 1)

# Replace analyze function port/url behavior
old2 = '''def analyze_doctor_requirements(uid, text, port="", url="", search_filter=""):
    uid = str(uid or "").strip()
    text = str(text or "").strip()

    if not uid:
        return {"valid": False, "error": "UID is mandatory / UID إجباري."}

    phishing = contains_rules(text, PHISHING_RULES)
    social = contains_rules(text, SOCIAL_ENGINEERING_RULES)
    telegram = contains_rules(text, TELEGRAM_RULES)

    urls = extract_urls(text)
    if url:
        urls.append(url)

    https_checks = [check_https(u) for u in urls] if urls else [check_https(url)]
    port_check = check_port(port)
    dataset_matches, dataset_status, text_col, label_col = dataset_as_rules_match(text, search_filter)
'''

new2 = '''def analyze_doctor_requirements(uid, text, port="", url="", search_filter=""):
    uid = str(uid or "").strip()
    text = str(text or "").strip()

    if not uid:
        return {"valid": False, "error": "UID is mandatory / UID إجباري."}

    phishing = contains_rules(text, PHISHING_RULES)
    social = contains_rules(text, SOCIAL_ENGINEERING_RULES)
    telegram = contains_rules(text, TELEGRAM_RULES)

    # Auto URL detection from message text
    urls = extract_urls(text)
    if url:
        urls.append(url)

    # Auto Port detection from message text
    auto_ports = extract_ports(text)
    if port:
        try:
            manual_port = int(str(port).strip())
            if manual_port not in auto_ports:
                auto_ports.append(manual_port)
        except Exception:
            pass

    https_checks = [check_https(u) for u in urls] if urls else [check_https(url)]

    # Check all detected ports, not just one
    port_checks = [check_port(p) for p in auto_ports] if auto_ports else [check_port(port)]
    port_check = max(port_checks, key=lambda x: 1 if x.get("is_risky") else 0)

    dataset_matches, dataset_status, text_col, label_col = dataset_as_rules_match(text, search_filter)
'''

if old2 in text:
    text = text.replace(old2, new2, 1)

# Update score to consider all port checks
text = text.replace(
    '''    score += 4 if port_check["is_risky"] else 0
    score += 3 if any(x["is_risky"] for x in https_checks) else 0''',
    '''    score += 4 if any(x["is_risky"] for x in port_checks) else 0
    score += 3 if any(x["is_risky"] for x in https_checks) else 0'''
)

text = text.replace(
    '''    if port_check["is_risky"]:
        matched.append("Port Rule")''',
    '''    if any(x["is_risky"] for x in port_checks):
        matched.append("Port Rule")'''
)

# Add outputs
text = text.replace(
    '''        "https_checks": https_checks,
        "port_check": port_check,''',
    '''        "https_checks": https_checks,
        "auto_detected_urls": urls,
        "auto_detected_ports": auto_ports,
        "port_checks": port_checks,
        "port_check": port_check,'''
)

p.write_text(text, encoding="utf-8")
print("✅ Auto URL + Auto Port extraction added to Rule-Based engine.")
