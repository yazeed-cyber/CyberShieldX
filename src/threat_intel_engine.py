import os
import csv
import time
import socket
import base64
import requests
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
THREAT_INTEL_FILE = PROJECT_ROOT / "outputs" / "threat_intel_results.csv"


def ensure_outputs():
    (PROJECT_ROOT / "outputs").mkdir(exist_ok=True)


def save_threat_intel(row):
    ensure_outputs()
    exists = THREAT_INTEL_FILE.exists()

    with open(THREAT_INTEL_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def normalize_url(url):
    url = str(url or "").strip().rstrip(".,،؛;)")
    if not url:
        return ""

    if url.startswith("www."):
        return "https://" + url

    if url.startswith("t.me/") or url.startswith("telegram.me/"):
        return "https://" + url

    return url


def get_domain(url):
    try:
        parsed = urlparse(normalize_url(url))
        return parsed.hostname or ""
    except Exception:
        return ""


def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""


def vt_url_id(url):
    normalized = normalize_url(url)
    encoded = base64.urlsafe_b64encode(normalized.encode()).decode().strip("=")
    return encoded


def check_virustotal_url(url):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "source": "VirusTotal",
            "status": "not_configured",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "details": "VT_API_KEY is not configured"
        }

    url = normalize_url(url)

    try:
        headers = {"x-apikey": api_key}

        scan_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=20
        )

        time.sleep(2)

        report_response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{vt_url_id(url)}",
            headers=headers,
            timeout=20
        )

        if report_response.status_code >= 300:
            return {
                "source": "VirusTotal",
                "status": "error",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "details": report_response.text[:300]
            }

        data = report_response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        return {
            "source": "VirusTotal",
            "status": "ok",
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "details": str(stats)
        }

    except Exception as e:
        return {
            "source": "VirusTotal",
            "status": "error",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "details": str(e)
        }


def check_urlhaus(url):
    url = normalize_url(url)

    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=20
        )

        if response.status_code >= 300:
            return {
                "source": "URLHaus",
                "status": "error",
                "malicious": 0,
                "suspicious": 0,
                "details": response.text[:300]
            }

        data = response.json()
        query_status = data.get("query_status", "")

        if query_status == "ok":
            threat = data.get("threat", "")
            url_status = data.get("url_status", "")
            return {
                "source": "URLHaus",
                "status": "ok",
                "malicious": 1,
                "suspicious": 0,
                "details": f"threat={threat}; url_status={url_status}"
            }

        return {
            "source": "URLHaus",
            "status": query_status or "not_found",
            "malicious": 0,
            "suspicious": 0,
            "details": "URL not found in URLHaus"
        }

    except Exception as e:
        return {
            "source": "URLHaus",
            "status": "error",
            "malicious": 0,
            "suspicious": 0,
            "details": str(e)
        }


def check_phishtank(url):
    url = normalize_url(url)

    try:
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url": url,
                "format": "json",
            },
            headers={
                "User-Agent": "CyberShieldX"
            },
            timeout=20
        )

        if response.status_code >= 300:
            return {
                "source": "PhishTank",
                "status": "error",
                "malicious": 0,
                "suspicious": 0,
                "details": response.text[:300]
            }

        data = response.json()
        results = data.get("results", {})

        in_database = bool(results.get("in_database", False))
        valid = bool(results.get("valid", False))

        if in_database and valid:
            return {
                "source": "PhishTank",
                "status": "ok",
                "malicious": 1,
                "suspicious": 0,
                "details": "URL is verified phishing in PhishTank"
            }

        if in_database:
            return {
                "source": "PhishTank",
                "status": "in_database_not_verified",
                "malicious": 0,
                "suspicious": 1,
                "details": "URL exists in PhishTank but not verified"
            }

        return {
            "source": "PhishTank",
            "status": "not_found",
            "malicious": 0,
            "suspicious": 0,
            "details": "URL not found in PhishTank"
        }

    except Exception as e:
        return {
            "source": "PhishTank",
            "status": "error",
            "malicious": 0,
            "suspicious": 0,
            "details": str(e)
        }


def check_abuseipdb_ip(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "source": "AbuseIPDB",
            "status": "not_configured",
            "ip": ip,
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "details": "ABUSEIPDB_API_KEY is not configured"
        }

    if not ip:
        return {
            "source": "AbuseIPDB",
            "status": "no_ip",
            "ip": "",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "details": "No IP resolved"
        }

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": api_key,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=20
        )

        if response.status_code >= 300:
            return {
                "source": "AbuseIPDB",
                "status": "error",
                "ip": ip,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "details": response.text[:300]
            }

        data = response.json().get("data", {})

        return {
            "source": "AbuseIPDB",
            "status": "ok",
            "ip": ip,
            "abuse_confidence_score": int(data.get("abuseConfidenceScore", 0)),
            "total_reports": int(data.get("totalReports", 0)),
            "details": f"country={data.get('countryCode', '')}; isp={data.get('isp', '')}"
        }

    except Exception as e:
        return {
            "source": "AbuseIPDB",
            "status": "error",
            "ip": ip,
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "details": str(e)
        }


def calculate_ti_risk(vt, urlhaus, phishtank, abuseipdb):
    score = 0
    reasons = []

    vt_bad = int(vt.get("malicious", 0)) + int(vt.get("suspicious", 0))
    if vt_bad > 0:
        score += min(10, vt_bad * 3)
        reasons.append(f"VirusTotal detections={vt_bad}")

    if int(urlhaus.get("malicious", 0)) > 0:
        score += 8
        reasons.append("URLHaus listed malware URL")

    if int(phishtank.get("malicious", 0)) > 0:
        score += 8
        reasons.append("PhishTank verified phishing")

    if int(phishtank.get("suspicious", 0)) > 0:
        score += 4
        reasons.append("PhishTank suspicious entry")

    abuse_score = int(abuseipdb.get("abuse_confidence_score", 0))
    if abuse_score >= 75:
        score += 8
        reasons.append(f"AbuseIPDB high score={abuse_score}")
    elif abuse_score >= 25:
        score += 4
        reasons.append(f"AbuseIPDB medium score={abuse_score}")

    if score >= 12:
        risk = "High"
    elif score >= 5:
        risk = "Medium"
    else:
        risk = "Low"

    return risk, score, "; ".join(reasons) if reasons else "No external TI hit"


def check_url_threat_intel(url, uid="", message_text=""):
    normalized_url = normalize_url(url)
    domain = get_domain(normalized_url)
    ip = resolve_domain_to_ip(domain)

    vt = check_virustotal_url(normalized_url)
    urlhaus = check_urlhaus(normalized_url)
    phishtank = check_phishtank(normalized_url)
    abuseipdb = check_abuseipdb_ip(ip)

    ti_risk, ti_score, reasons = calculate_ti_risk(vt, urlhaus, phishtank, abuseipdb)

    row = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uid": uid,
        "url": normalized_url,
        "domain": domain,
        "resolved_ip": ip,
        "ti_risk": ti_risk,
        "ti_score": ti_score,
        "ti_reasons": reasons,
        "virustotal_status": vt.get("status", ""),
        "virustotal_malicious": vt.get("malicious", 0),
        "virustotal_suspicious": vt.get("suspicious", 0),
        "urlhaus_status": urlhaus.get("status", ""),
        "urlhaus_malicious": urlhaus.get("malicious", 0),
        "phishtank_status": phishtank.get("status", ""),
        "phishtank_malicious": phishtank.get("malicious", 0),
        "abuseipdb_status": abuseipdb.get("status", ""),
        "abuseipdb_score": abuseipdb.get("abuse_confidence_score", 0),
        "message_text": message_text,
    }

    save_threat_intel(row)

    return row


def check_urls_threat_intel(urls, uid="", message_text=""):
    results = []

    for url in urls:
        if str(url).strip():
            results.append(check_url_threat_intel(url, uid=uid, message_text=message_text))

    return results
