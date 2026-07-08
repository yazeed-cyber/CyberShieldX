from pathlib import Path

p = Path("src/doctor_rule_based.py")
text = p.read_text(encoding="utf-8")

# Replace extract_urls/check_https/check_port area with stronger real URL/port parsing
start = text.find("def extract_urls(text):")
end = text.find("def dataset_as_rules_match", start)

new_block = r'''
def extract_urls(text):
    """
    Extract real URLs from Telegram/message text.
    Supports:
    - https://domain.com/path
    - http://domain.com:8080/path
    - www.domain.com/path
    - t.me/channel
    """
    return re.findall(
        r"(https?://[^\s]+|www\.[^\s]+|t\.me/[^\s]+|telegram\.me/[^\s]+)",
        str(text),
        re.IGNORECASE
    )


def normalize_url(url):
    url = str(url or "").strip().rstrip(".,،؛;)")
    if not url:
        return ""

    if url.startswith("www."):
        return "https://" + url

    if url.startswith("t.me/") or url.startswith("telegram.me/"):
        return "https://" + url

    return url


def parse_real_url(url):
    """
    Parse actual URL data:
    - scheme
    - domain
    - path
    - explicit port if exists
    - default port by scheme
    """
    clean_url = normalize_url(url)

    if not clean_url:
        return {
            "url": "N/A",
            "scheme": "N/A",
            "domain": "N/A",
            "path": "",
            "port": "N/A",
            "is_https": False,
            "is_http": False,
            "note": "No URL provided."
        }

    parsed = urlparse(clean_url)
    scheme = parsed.scheme.lower()
    domain = parsed.hostname or parsed.netloc or "N/A"
    path = parsed.path or ""

    explicit_port = parsed.port

    if explicit_port:
        port = explicit_port
    elif scheme == "https":
        port = 443
    elif scheme == "http":
        port = 80
    else:
        port = "N/A"

    return {
        "url": clean_url,
        "scheme": scheme or "unknown",
        "domain": domain,
        "path": path,
        "port": port,
        "is_https": scheme == "https",
        "is_http": scheme == "http",
        "note": "Parsed from real URL."
    }


def extract_ports_from_text(text):
    """
    Extract explicit ports from normal text.
    Examples:
    - port 4444
    - tcp/3389
    - udp/53
    - :8080 inside URL or text
    """
    text = str(text or "").lower()
    ports = set()

    patterns = [
        r"\bport\s*[:=]?\s*(\d{1,5})\b",
        r"\btcp\s*/\s*(\d{1,5})\b",
        r"\budp\s*/\s*(\d{1,5})\b",
        r":(\d{2,5})\b",
        r"\b(21|22|23|25|53|80|443|445|3389|4444|8080|8443)\b",
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


def check_https(url):
    parsed = parse_real_url(url)

    if parsed["url"] == "N/A":
        return {
            "url": "N/A",
            "scheme": "N/A",
            "domain": "N/A",
            "port": "N/A",
            "https_status": "No URL",
            "is_risky": False,
            "note": "No URL was provided."
        }

    if parsed["is_https"]:
        return {
            "url": parsed["url"],
            "scheme": parsed["scheme"],
            "domain": parsed["domain"],
            "port": parsed["port"],
            "https_status": "HTTPS",
            "is_risky": False,
            "note": "HTTPS detected. Still inspect domain, Telegram source, and phishing context."
        }

    if parsed["is_http"]:
        return {
            "url": parsed["url"],
            "scheme": parsed["scheme"],
            "domain": parsed["domain"],
            "port": parsed["port"],
            "https_status": "HTTP",
            "is_risky": True,
            "note": "HTTP detected. Traffic is not encrypted; high phishing risk."
        }

    return {
        "url": parsed["url"],
        "scheme": parsed["scheme"],
        "domain": parsed["domain"],
        "port": parsed["port"],
        "https_status": "Unknown Protocol",
        "is_risky": True,
        "note": "Unknown or missing protocol."
    }


def check_port(port):
    if port is None or str(port).strip() == "" or str(port) == "N/A":
        return {
            "port": "N/A",
            "is_risky": False,
            "service": "No port",
            "recommendation": "No port was detected."
        }

    try:
        p = int(str(port).strip())
    except ValueError:
        return {
            "port": str(port),
            "is_risky": False,
            "service": "Invalid input",
            "recommendation": "Enter numeric port only."
        }

    if p in RISKY_PORTS:
        return {
            "port": p,
            "is_risky": True,
            "service": RISKY_PORTS[p],
            "recommendation": "Investigate and restrict this port if not required."
        }

    if p in NORMAL_PORTS:
        return {
            "port": p,
            "is_risky": False,
            "service": NORMAL_PORTS[p],
            "recommendation": "Known port. Continue inspection based on URL, Telegram source, and message context."
        }

    return {
        "port": p,
        "is_risky": False,
        "service": "Unknown/normal service",
        "recommendation": "No risky port rule matched."
    }


'''

if start != -1 and end != -1:
    text = text[:start] + new_block + text[end:]

# Patch analyze function URL/port part
old = '''    urls = extract_urls(text)
    if url:
        urls.append(url)

    https_checks = [check_https(u) for u in urls] if urls else [check_https(url)]
    port_check = check_port(port)
    dataset_matches, dataset_status, text_col, label_col = dataset_as_rules_match(text, search_filter)
'''

new = '''    # Real URL extraction from Telegram/message text
    urls = extract_urls(text)
    if url:
        urls.append(url)

    https_checks = [check_https(u) for u in urls] if urls else [check_https(url)]

    # Real port extraction:
    # 1) explicit ports in text like tcp/4444 or port 3389
    # 2) actual URL ports like http://site.com:8080
    # 3) default URL ports: https=443, http=80
    text_ports = extract_ports_from_text(text)

    url_ports = []
    for u in urls:
        parsed = parse_real_url(u)
        if parsed.get("port") != "N/A":
            url_ports.append(parsed.get("port"))

    all_ports = []
    for item in text_ports + url_ports:
        try:
            item = int(item)
            if item not in all_ports:
                all_ports.append(item)
        except Exception:
            pass

    if port:
        try:
            manual_port = int(str(port).strip())
            if manual_port not in all_ports:
                all_ports.append(manual_port)
        except Exception:
            pass

    port_checks = [check_port(p) for p in all_ports] if all_ports else [check_port("")]
    port_check = max(port_checks, key=lambda x: 1 if x.get("is_risky") else 0)

    dataset_matches, dataset_status, text_col, label_col = dataset_as_rules_match(text, search_filter)
'''

if old in text:
    text = text.replace(old, new, 1)

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

text = text.replace(
    '''        "https_checks": https_checks,
        "port_check": port_check,''',
    '''        "https_checks": https_checks,
        "auto_detected_urls": urls,
        "auto_detected_ports": all_ports,
        "port_checks": port_checks,
        "port_check": port_check,'''
)

p.write_text(text, encoding="utf-8")
print("✅ Real URL and real port extraction enabled for Telegram-ready Rule Based.")
