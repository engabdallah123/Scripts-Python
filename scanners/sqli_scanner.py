import requests
from datetime import datetime

def scan_sqli(url: str):
    payloads = ["' OR '1'='1", "'--", "' OR 1=1 --"]
    results = []

    for payload in payloads:
        test_url = f"{url}?id={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            if "sql" in r.text.lower() or "syntax" in r.text.lower():
                results.append({
                    "type": "SQL Injection",
                    "severity": 2,
                    "target": test_url,
                    "payload": payload,
                    "description": "SQL Injection vulnerability detected.",
                    "recommendation": "Use parameterized queries.",
                    "isConfirmed": True,
                    "detectedAt": datetime.utcnow().isoformat(),
                    "scannerName": "SQLiScanner"
                })
        except:
            continue

    return results
